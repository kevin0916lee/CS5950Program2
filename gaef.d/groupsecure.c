/*--------------------------------------------------------
1. Jialiang Chang / Dec 03, 2015:

2. Version log :1.written by Dec 03,2015

3. Precise examples / instructions to run this program:
> (in working gaef.d folder path)$ make
> $ ./groupsecure file

4. Aim: initialize and apply the group security scheme to file

5. Notes:
  a.This is for Fall 2015 CS 5950 program2, taught by Professor Steve Carr, Western Michigan University.
  b.BLOWFISH reference: https://en.wikipedia.org/wiki/Blowfish_(cipher)

6. TODO:
  a.should check pubring.gpg exists
  b.indicate which key is used to encrypt the file
  c.let owner of the file decide whether to delete the file or not
  EX1.add comments
  EX2.clean up the code
----------------------------------------------------------*/
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "cryptlib.h"

#define  SYMMETRIC_ALG   CRYPT_ALGO_BLOWFISH
#define  KEYSIZE         56
#define  BUFSIZE 		 4096
uid_t uid;


void checkCryptNormal(int returnCode, char *routineName, int line){
  if (cryptStatusError(returnCode)){
    printf("Error in %s at line %d, return value %d\n",
	   routineName, line, returnCode);
    exit(returnCode);
  }
}


//File owner and states checker
void fileChecker(char *file){
	
	uid_t ownerID;
    int f = -1;
    struct stat fs;

  	//Check file owner
    f = open(file, O_RDONLY);

    if (f < 0){
        printf("slient exit\n");
        exit (1);
    }

    if (fstat(f, &fs)<0)
    {
        printf("slient exit\n");
        exit (1);
    }

    ownerID = fs.st_uid;

	uid = getuid();

	if (ownerID != uid) {
		printf("slient exit\n");
        exit (1);
	}

	//Check if the file is a regular file
	if ( (fs.st_mode & S_IFMT) != S_IFREG ) {
		printf("slient exit\n");
        exit (1);
	}

	if(close(f) < 0){
        printf("slient exit\n");
        exit (1);
    }

}


//Key generator
void genKey(char * keyPtr, int keySize){
  int  ret;  
  int  total;
  int  urandFd;

  urandFd=open("/dev/urandom",O_RDONLY);
  total=0;
  while (total<keySize) {
    ret=read(urandFd,&keyPtr[total],keySize-total);total+=ret;
  }
  printf("Successful generation of key with size <%d>\n",total);
  close(urandFd);


}


//Get public key name
void getPublicKeyName(char *keyFile, int id) {
	struct passwd *userInfo;      
	userInfo = getpwuid(id);
	if (userInfo == NULL) { perror("getpwuid"); exit(__LINE__); }

	if (keyFile == NULL) { perror("malloc"); exit(__LINE__); }
	strcpy(keyFile, userInfo->pw_dir);
	strcat(keyFile, "/.gnupg/pubring.gpg");

	//TODO should check pubring.gpg exists.

	printf("Getting key from <%s>\n", keyFile);
}


//Get the encrypted key encrypted by GPG public key
void encData(char *keyFile, char *encKey, char *encDataPtr, int encDataSize, int id){
	int  ret;                          /* Return value */
	int bytesCopied;
  	CRYPT_ENVELOPE dataEnv;    /* Envelope for enc */
	CRYPT_KEYSET   keyset;     /* GPG keyset */


	cryptInit();
	struct passwd *userInfo;     
	char *userInfoName;
  	userInfo = getpwuid(id);
	userInfoName = userInfo->pw_name;
	ret=cryptAddRandom( NULL , CRYPT_RANDOM_SLOWPOLL);
  	checkCryptNormal(ret,"cryptAddRandom",__LINE__);

  	/*====================================================
    Encrypt key with GPG public key
    Email address is for recipient
    ===================================================
  	*/

  
	ret=cryptKeysetOpen(&keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, keyFile, CRYPT_KEYOPT_READONLY);
	free(keyFile);
	checkCryptNormal(ret,"cryptKeysetOpen",__LINE__);
	ret=cryptCreateEnvelope(&dataEnv, CRYPT_UNUSED, CRYPT_FORMAT_PGP);
	checkCryptNormal(ret,"cryptCreateEnvelope",__LINE__);
	ret=cryptSetAttribute(dataEnv, CRYPT_ENVINFO_KEYSET_ENCRYPT, keyset);
	checkCryptNormal(ret,"cryptSetAttribute",__LINE__);
	// printf(dataEnv);
	userInfoName = "Jialiang Chang";
	// printf("%s\n",userInfoName );
	ret=cryptSetAttributeString(dataEnv, CRYPT_ENVINFO_RECIPIENT, userInfoName,strlen(userInfoName));
	// printf(dataEnv);
	checkCryptNormal(ret,"cryptSetAttributeString",__LINE__);
	//QQQ
	ret=cryptSetAttribute(dataEnv, CRYPT_ENVINFO_DATASIZE, KEYSIZE+1);

	ret=cryptPushData(dataEnv,encKey,KEYSIZE+1,&bytesCopied);
	checkCryptNormal(ret,"cryptPushData",__LINE__);
	ret=cryptFlushData(dataEnv);
	checkCryptNormal(ret,"cryptFlushData",__LINE__);

	// encDataSize=strlen(argv[2])+1+1028;
	// encDataPtr=malloc(encDataSize);

	if (encDataPtr==NULL){perror("malloc");exit(__LINE__);}
	ret=cryptPopData(dataEnv,encDataPtr,encDataSize,&bytesCopied);
	printf("cryptPopData returned <%d> bytes of encrypted data\n",bytesCopied);
	encDataSize=bytesCopied;

	ret=cryptDestroyEnvelope(dataEnv);  
	checkCryptNormal(ret,"cryptDestroyEnvelope",__LINE__);
	cryptKeysetClose(keyset);
	checkCryptNormal(ret,"cryptKeysetClose",__LINE__);
}



int main(int argc, char const *argv[])
{	
	int  i;                            /* Loop iterator */
	int  ret;                          /* Return value */
	int  total;                        /* Total key bytes */
	int  bytesCopied;                  /* Bytes output by cryptlib enc/dec ops */
	int  urandFd;                      /* Pointer to /dev/urandom */
	char            *keyPtr;           /* Pointer to key */
	CRYPT_ENVELOPE  dataEnv;           /* Envelope for encrypt/decrypt */
	CRYPT_CONTEXT   symContext;        /* Key context */
	char        *clrDataPtr;           /* Pointer to clear text */
	int         clrDataSize;           /* Bytes of clear text */
	int         clrDataFd;             /* Pointer to clear text file */
	struct stat clrDataFileInfo;       /* fstat return for clear text file */
	int         encDataFd;             /* Pointer to encrypted text file */
	char        *encDataPtr;           /* Pointer to encrypted data */
	int         encDataSize;           /* Buffer bytes availble for decrypt */
	struct stat encDataFileInfo;       /* fstat return for encrypted data file */
  	char          *keyFile;        /* GPG key ring file name */
	struct passwd *userInfo;       /* Password info for input user */
	char encFile[BUFSIZE+4];	/* Name to use for Encrypted file */
	char gpgKeyFile[BUFSIZE+7];	/* Name to use for Encrypted file */


	//Check arguments number 
	if (argc!=2) {
        printf("slient exit\n");
        exit (1);
	}

	uid = getuid();
	//Check if the owner of the file and if the file is not an ordinary file.
	fileChecker((char *)argv[1]);

	//Generate key using /dev/urandom;
	keyPtr=malloc(KEYSIZE);
	genKey(keyPtr, KEYSIZE);


	//Cryptlib initialization
	cryptInit();
	ret=cryptAddRandom( NULL , CRYPT_RANDOM_SLOWPOLL);
	checkCryptNormal(ret,"cryptAddRandom",__LINE__);

    //Open DATAFILE and get data
	clrDataFd=open(argv[1],O_RDONLY);
	if (clrDataFd<=0){perror("open clrData");exit(clrDataFd);}
	ret=fstat(clrDataFd,&clrDataFileInfo);
	if (ret!=0){perror("fstat clrDataFd");exit(ret);}
	clrDataSize=clrDataFileInfo.st_size;
	clrDataPtr=malloc(clrDataFileInfo.st_size);
	if (clrDataPtr==NULL){perror("malloc clrData");exit(__LINE__);}
	ret=read(clrDataFd,clrDataPtr,clrDataSize);
	if (ret!=clrDataSize){perror("read clrData");exit(ret);}
	close(clrDataFd);

 	//Encrypt data from file with the key and write it to output file.

	ret=cryptCreateEnvelope(&dataEnv, CRYPT_UNUSED, CRYPT_FORMAT_CRYPTLIB);
	checkCryptNormal(ret,"cryptCreateEnvelope",__LINE__);

	ret=cryptCreateContext(&symContext, CRYPT_UNUSED, SYMMETRIC_ALG);
	checkCryptNormal(ret,"cryptCreateContext",__LINE__);

	ret=cryptSetAttributeString(symContext, CRYPT_CTXINFO_KEY,keyPtr,KEYSIZE);
	checkCryptNormal(ret,"cryptSetAttributeString",__LINE__);

	ret=cryptSetAttribute(dataEnv, CRYPT_ENVINFO_SESSIONKEY, symContext);
	checkCryptNormal(ret,"cryptSetAttribute",__LINE__);

	ret=cryptDestroyContext(symContext);
	checkCryptNormal(ret,"cryptDestroyContext",__LINE__);

	ret=cryptSetAttribute(dataEnv, CRYPT_ENVINFO_DATASIZE, 
	                    clrDataSize);
	checkCryptNormal(ret,"cryptSetAttribute",__LINE__);

	ret=cryptPushData(dataEnv,clrDataPtr,clrDataSize,&bytesCopied);
	checkCryptNormal(ret,"cryptAddRandom",__LINE__);

	cryptFlushData(dataEnv);


	encDataSize=clrDataFileInfo.st_size+2048;
	encDataPtr=malloc(encDataSize);
	if (encDataPtr==NULL){perror("malloc encData");exit(__LINE__);}

	ret=cryptPopData(dataEnv,encDataPtr,encDataSize,&bytesCopied);
	checkCryptNormal(ret,"cryptPopData",__LINE__);
	printf("<%d> bytes of encrypted data\n",bytesCopied); 

	ret=cryptDestroyEnvelope(dataEnv);
	checkCryptNormal(ret,"cryptDestroyEnvelope",__LINE__);

	//Get enc file
	strcpy(encFile, argv[1]);
	//TODO indicate which key is used to encrypt the file
	strcat(encFile, ".enc");


	encDataFd=open(encFile,O_RDWR|O_CREAT|O_TRUNC,S_IRUSR|S_IWUSR);
	if (encDataFd<=0){perror("open encDataFd");exit(encDataFd);}


	ret=write(encDataFd,encDataPtr,bytesCopied);
	if (ret!=bytesCopied){perror("write encData");exit(ret);}

	close(encDataFd);
	free(encDataPtr);

	//TODO let owner of the file decide whether to delete the file or not.

	//Get enc key
	keyFile = malloc(1024);
	getPublicKeyName(keyFile, uid);


	// gpgEncFile = malloc(sizeof(encFile)+3);
	memcpy(gpgKeyFile, encFile, sizeof(encFile));
	strcat(gpgKeyFile, "GPGKey");


	encDataSize= KEYSIZE + 1 + 1028;//Accoring to the algorithm of the gpg key
	encDataPtr=malloc(encDataSize);
	if (encDataPtr==NULL){perror("malloc encData");exit(__LINE__);}

	encDataFd = open(gpgKeyFile, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	if (encDataFd<=0){perror("open encDataFd");exit(encDataFd);}

	encData(keyFile, keyPtr, encDataPtr, encDataSize, uid);
	ret=write(encDataFd,encDataPtr,bytesCopied);
	if (ret!=bytesCopied){perror("write encData");exit(ret);}
	close(encDataFd);
	free(encDataPtr);

	return 0;
}






















