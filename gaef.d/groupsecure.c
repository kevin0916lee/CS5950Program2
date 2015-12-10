/*--------------------------------------------------------
1. Jialiang Chang / Dec 03, 2015:

2. Version log :1.written by Dec 03,2015
				2.v0.9 by Dec 09,2015

3. Precise examples / instructions to run this program:
> (in working gaef.d folder path)$ make
> $ ./groupsecure file

4. Aim: initialize and apply the group security scheme to file

5. Notes:
  a.This is for Fall 2015 CS 5950 program2, taught by Professor Steve Carr, Western Michigan University.
  b.BLOWFISH reference: https://en.wikipedia.org/wiki/Blowfish_(cipher)
  c.Fixed the output of enc and enckey files.

6. TODO:
  a.should check pubring.gpg exists//DONE
  b.indicate which key is used to encrypt the file//DONE
  c.let owner of the file decide whether to delete the file or not//DONE
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
	char label[100];           /* Public key label */
    int  labelLength;          /* Length of label */
	struct passwd *userInfo;      
	userInfo = getpwuid(id);
	if (userInfo == NULL) { perror("getpwuid"); exit(__LINE__); }
	if (keyFile == NULL) { perror("malloc"); exit(__LINE__); }
	strcpy(keyFile, userInfo->pw_dir);
	strcat(keyFile, "/.gnupg/pubring.gpg");

	//TODO should check pubring.gpg exists.//DONE
	if ( open(keyFile,O_RDONLY) == -1 ) {
		printf("Failed to open or find: %s", keyFile);
		exit(1);
	}

	printf("Getting key from <%s>\n", keyFile);
}



void encKey(char *gpgPublicKeyPtr, char *keyPtr, char *encKeyPtr,char *user ) {

  int  ret;            /* Return code */
  int  i;              /* Loop iterator */
  int  bytesCopied;    /* Bytes output by cryptlib enc/dec ops */
  int  reqAttrib;      /* Crypt required attributed */

  CRYPT_ENVELOPE dataEnv;    /* Envelope for enc/dec */
  CRYPT_KEYSET   keyset;     /* GPG keyset */
  char label[100];           /* Private key label */
  int  labelLength;          /* Length of label */
  char passbuf[1024];        /* Buffer for GPG key passphrase */
  struct termios ts, ots;    /* Strutures for saving/modifying term attribs */

  char        *clrDataPtr;       /* Pointer to clear text */
  int         clrDataSize;       /* Size of clear text */
  char        *encDataPtr;       /* Pointer to encrypted data */
  int         encDataSize;       /* Size of encrypted data */
  struct passwd *userInfo;       /* Password info for input user */
  char          *keyFile;        /* GPG key ring file name */
  int          encDataFd;


  /*==============================================
     Cryptlib initialization
    ==============================================
  */
  cryptInit();
  ret=cryptAddRandom( NULL , CRYPT_RANDOM_SLOWPOLL);
  checkCryptNormal(ret,"cryptAddRandom",__LINE__);

  /*====================================================
    Encrypt key with GPG public key
    Email address is for recipient
    ===================================================
  */

  ret=cryptKeysetOpen(&keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, gpgPublicKeyPtr, CRYPT_KEYOPT_READONLY);
  free(gpgPublicKeyPtr);
  checkCryptNormal(ret,"cryptKeysetOpen",__LINE__);
  ret=cryptCreateEnvelope(&dataEnv, CRYPT_UNUSED, CRYPT_FORMAT_PGP);
  checkCryptNormal(ret,"cryptCreateEnvelope",__LINE__);
  ret=cryptSetAttribute(dataEnv, CRYPT_ENVINFO_KEYSET_ENCRYPT, keyset);
  checkCryptNormal(ret,"cryptSetAttribute",__LINE__);
  ret=cryptSetAttributeString(dataEnv, CRYPT_ENVINFO_RECIPIENT,
                              user,strlen(user));
  //Output message that indicate which key was used to encrypt the file key
  printf("The gpg public key owned by <%s> was used to encrypt the file key",user);

  checkCryptNormal(ret,"cryptSetAttributeString",__LINE__);
  ret=cryptSetAttribute(dataEnv, CRYPT_ENVINFO_DATASIZE, KEYSIZE);
  ret=cryptPushData(dataEnv,keyPtr,KEYSIZE,&bytesCopied);
  checkCryptNormal(ret,"cryptPushData",__LINE__);
  ret=cryptFlushData(dataEnv);
  checkCryptNormal(ret,"cryptFlushData",__LINE__);

  encDataSize=KEYSIZE+1028;
  encDataPtr=malloc(encDataSize);
  if (encDataPtr==NULL){perror("malloc");exit(__LINE__);}
  ret=cryptPopData(dataEnv,encDataPtr,encDataSize,&bytesCopied);
  printf("cryptPopData returned <%d> bytes of encrypted data\n",bytesCopied);
  encDataSize=bytesCopied;

  ret=cryptDestroyEnvelope(dataEnv);
  checkCryptNormal(ret,"cryptDestroyEnvelope",__LINE__);
  cryptKeysetClose(keyset);
  checkCryptNormal(ret,"cryptKeysetClose",__LINE__);

  encDataFd=open(encKeyPtr, O_RDWR|O_CREAT|O_TRUNC,S_IRUSR|S_IWUSR);
  if (encDataFd<=0){perror("open encDataFd1");exit(encDataFd);}
  ret=write(encDataFd,encDataPtr,bytesCopied);
  if (ret!=bytesCopied){perror("write encData");exit(ret);}
  close(encDataFd);

  int chmodStat = chmod (encKeyPtr, S_IWRITE| S_IREAD| S_IRGRP | S_IWGRP);
  if(chmodStat<0){
	  perror("failed to chmod");
	  exit(-1);
  }

  ret=cryptEnd();
  checkCryptNormal(ret,"cryptEnd",__LINE__);
}


int main(int argc, char const *argv[])
{	 
	int  i;                            /* Loop iterator */
	int  ret;                          /* Return value */
	int  total;                        /* Total key bytes */
	int  bytesCopied;                  /* Bytes output by cryptlib enc/dec ops */
	int  urandFd;                      /* Pointer to /dev/urandom */
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
	char *file;
	char encFile[BUFSIZE+4];
	char *encKeyPtr;
	char *key ;
	char *keyPtr;
	struct passwd *pws;       			/* info for input user */
	char   *pwname;       				/* username */
	char   *pwdir;        				/* home directory */
	char *gpgPublicKeyPtr;


	//Check arguments number 
	if (argc!=2) {
        printf("slient exit\n");
        exit (1);
	}
	uid = getuid();
	pws = getpwuid(uid);
	pwname = pws->pw_name;//get the user login name;
	pwdir = pws->pw_dir;
	//Check if the owner of the file and if the file is not an ordinary file.
	fileChecker((char *)argv[1]);
	//Generate key using /dev/urandom;
	keyPtr=malloc(KEYSIZE);
	genKey(keyPtr, KEYSIZE);

	//Get encfile name
	strcpy(encFile, argv[1]);
	strcat(encFile, ".enc");

	//Get enckey name
	encKeyPtr = malloc(strlen(encFile)+strlen(pwname) + 4);
	strcpy(encKeyPtr,encFile);
	strcat(encKeyPtr, ".");
	strcat(encKeyPtr, pwname);
	strcat(encKeyPtr, ".key");




	//Encrypt the file and get the pointer of key
	/*==============================================
	 Cryptlib initialization
	==============================================
	*/
	cryptInit();
	ret=cryptAddRandom( NULL , CRYPT_RANDOM_SLOWPOLL);
	checkCryptNormal(ret,"cryptAddRandom",__LINE__);

	/*=============================================
	Open DATAFILE and get data
	=============================================
	*/
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

	/*==============================================
	(1) Generate the key
	==============================================
	*/

	keyPtr=malloc(KEYSIZE);
	if (keyPtr==NULL){perror("malloc keyPtr");exit(__LINE__);}
	urandFd=open("/dev/urandom",O_RDONLY);
	if (urandFd<=0){perror("open urandFd");exit(urandFd);}
	total=0;ret=0;
	while (total<KEYSIZE){
	ret=read(urandFd,&keyPtr[total],KEYSIZE-total);total+=ret;
	if (ret < 0){perror("read urand");exit(ret);}
	}
	close(urandFd);





	/*==============================================
	(2) Encrypt data from file with the key and
	    write it to output file.
	==============================================
	*/

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

	encDataFd=open(encFile,O_RDWR|O_CREAT|O_TRUNC,S_IRUSR|S_IWUSR);
	if (encDataFd<=0){perror("open encDataFd");exit(encDataFd);}
	ret=write(encDataFd,encDataPtr,bytesCopied);
	if (ret!=bytesCopied){perror("write encData");exit(ret);}
	close(encDataFd);
	free(encDataPtr);
	ret=cryptEnd();
	checkCryptNormal(ret,"cryptEnd",__LINE__);


	//Get the pointer of the gpg public key
	gpgPublicKeyPtr = malloc(1024);
	getPublicKeyName(gpgPublicKeyPtr,uid);

	//Get the encrypted key
	encKey(gpgPublicKeyPtr, keyPtr, encKeyPtr, pwname);


	//Check if user want to delete the clear file or not
	clrDataFd=open(argv[1], O_RDONLY);
    if(clrDataFd < 0){
        printf("slient exit\n");
        exit(1);
    }else{
        printf("Do you want to delete the clear file<%s>? [y/n]\n", argv[1]);
        char option;
        int status;  
        status = -1;
        while (option = getchar()) {
			if (option == 'y')
				status = remove(argv[1]);
				if( status == 0 ){
					printf("%s file deleted successfully.\n",argv[1]);
					return 0;
				}
			if (option == 'n')
				return 0;
			printf("Please input 'y' or 'n'\n");
        }
    }
	return 0;
}






















