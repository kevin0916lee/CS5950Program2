/*--------------------------------------------------------
1. Jialiang Chang / Dec 09, 2015:

2. Version log :1.written by Dec 09,2015


3. Precise examples / instructions to run this program:
> (in working gaef.d folder path)$ make
> $ ./getsecure file

4. Aim: access to the contents of file by the user executing the command

5. Notes:
  a.This is for Fall 2015 CS 5950 program2, taught by Professor Steve Carr, Western Michigan University.
  b.BLOWFISH reference: https://en.wikipedia.org/wiki/Blowfish_(cipher)

6. TODO:
  1.if the user does not have a key in the key file
  EX1.add comments
  EX2.clean up the code
----------------------------------------------------------*/
#include "cryptlib.h"
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <pwd.h>


#define  SYMMETRIC_ALG   CRYPT_ALGO_BLOWFISH
#define  KEYSIZE         56
#define  BUFSIZE     4096
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


//Get public key name
void getPrivateKeyName(char *keyFile, int id) {
  struct passwd *userInfo;      
  userInfo = getpwuid(id);
  if (userInfo == NULL) { perror("getpwuid"); exit(__LINE__); }
  if (keyFile==NULL){perror("malloc");exit(__LINE__);}
  strcpy(keyFile,userInfo->pw_dir);
  strcat(keyFile,"/.gnupg/secring.gpg");
  printf("Getting secret key from <%s>\n",keyFile);

}



int main(int argc, char const *argv[])
{ 
  
  struct passwd *pws;       /* info for input user */
  char   *pwname;       /* username */
  char   *pwdir;        /* home directory */

  char *encFile;
  char *encKey;
  int encKeyFd;    //file state
  char *encKeyPtr;           /* Pointer to encrypted data */
  int encKeySize;           /* Buffer bytes availble for decrypt */

  struct stat fileStat;     /* Struce for checking file attributes */

  char          *keyFile;        /* GPG key ring file name */
  char *gpgPrivateKeyPtr;

  int  ret;            /* Return code */
  int  i;              /* Loop iterator */
  int  bytesCopied;    /* Bytes output by cryptlib enc/dec ops */
  int  reqAttrib;      /* Crypt required attributed */

  CRYPT_ENVELOPE dataEnv;    /* Envelope for enc/dec */
  CRYPT_KEYSET   keyset;     /* GPG keyset */
  CRYPT_CONTEXT   symContext; /* Key context */
  char label[100];           /* Private key label */
  int  labelLength;          /* Length of label */
  char passbuf[1024];        /* Buffer for GPG key passphrase */
  struct termios ts, ots;    /* Strutures for saving/modifying term attribs */

  char        *encDataPtr;       /* Pointer to encrypted data */
  int         encDataSize;       /* Size of encrypted data */
  struct passwd *userInfo;       /* Password info for input user */


  int encFileFd;          /* Destination (Encrypted) File Descriptor */
  int encFileSize;        /* Bytes of encrypted data */ 
  char * encFilePtr;      /* Pointer to enc text */
  char *clrFilePtr;     /* Pointer to clear text */
  int clrFileSize;        /* Bytes of clear text */
  char *clrKeyPtr;
  int clrKeySize;


  struct stat encFileInfo;

  uid = getuid();
  pws = getpwuid(uid);
  pwname = pws->pw_name;//get the user login name;
  pwdir = pws->pw_dir;

  //Check arguments number 
  if (argc!=2) {
        printf("slient exit\n");
        exit (1);
  }


  //Get encrepted file
  encFile = malloc(strlen(argv[1]) + 4);
  strcpy(encFile, argv[1]);
  //TODO indicate which key is used to encrypt the file
  strcat(encFile, ".enc");
 

  //Get gpg encrepted key name
  encKey = malloc(strlen(encFile) + strlen(pwname) +5 );
  strcpy(encKey,encFile);
  strcat(encKey, ".");
  strcat(encKey, pwname);
  strcat(encKey, ".key");

  //TODO check if user is permitted.

  //Open gpg encrepted key
  encKeyFd=open(encKey, O_RDONLY);
  if (encKeyFd<=0){perror("(2) open encKeyFd");exit(encKeyFd);}
  ret=fstat(encKeyFd,&fileStat);
  if (ret!=0){perror("fstat encKeyFd");exit(ret);}
  encKeySize=fileStat.st_size;
  encKeyPtr=malloc(encKeySize);
  if (encKeyPtr==NULL){perror("malloc encData");exit(__LINE__);}
  ret=read(encKeyFd,encKeyPtr,encKeySize);
  if (ret!=encKeySize){perror("read encData");exit(ret);}
  close(encKeyFd);
 
   

  //Get the private key name
  gpgPrivateKeyPtr=malloc(strlen(pwdir)
               + strlen("/.gnupg/secring.gpg") + 1);
  getPrivateKeyName(gpgPrivateKeyPtr,uid);


  //Decrypt key
  cryptInit();
  ret=cryptAddRandom( NULL , CRYPT_RANDOM_SLOWPOLL);
  checkCryptNormal(ret,"cryptAddRandom",__LINE__);
  ret=cryptKeysetOpen(&keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, gpgPrivateKeyPtr, CRYPT_KEYOPT_READONLY);
  free(gpgPrivateKeyPtr);
  checkCryptNormal(ret,"cryptKeysetOpen",__LINE__);
  ret=cryptCreateEnvelope(&dataEnv, CRYPT_UNUSED, CRYPT_FORMAT_AUTO);
  checkCryptNormal(ret,"cryptCreateEnvelope",__LINE__);
  ret=cryptSetAttribute(dataEnv, CRYPT_ENVINFO_KEYSET_DECRYPT, keyset);
  checkCryptNormal(ret,"cryptSetAttribute",__LINE__);
  ret=cryptPushData(dataEnv,encKeyPtr,encKeySize,&bytesCopied);
  /*  Expect non-zero return -- indicates need private key */
  ret=cryptGetAttribute(dataEnv, CRYPT_ATTRIBUTE_CURRENT, &reqAttrib); 
  if (reqAttrib != CRYPT_ENVINFO_PRIVATEKEY) 
     {printf("Decrypt error\n");exit(ret);}
  ret=cryptGetAttributeString(dataEnv, CRYPT_ENVINFO_PRIVATEKEY_LABEL, label, &labelLength);
  label[labelLength]='\0';
  checkCryptNormal(ret,"cryptGetAttributeString",__LINE__); 

  
  /*===============================================
    Get the passphrase
    ===============================================
  */

  tcgetattr(STDIN_FILENO, &ts);
  ots = ts;


  ts.c_lflag &= ~ECHO;
  ts.c_lflag |= ECHONL;
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &ts);


  tcgetattr(STDIN_FILENO, &ts);
  if (ts.c_lflag & ECHO) {
    fprintf(stderr, "Failed to turn off echo\n");
    tcsetattr(STDIN_FILENO, TCSANOW, &ots);
    exit(1);
  }

  printf("Enter password for <%s>: ",label);
  fflush(stdout);
  fgets(passbuf, 1024, stdin);

  tcsetattr(STDIN_FILENO, TCSANOW, &ots);   

  ret=cryptSetAttributeString(dataEnv, CRYPT_ENVINFO_PASSWORD,
                             passbuf, strlen(passbuf)-1);
  if (ret != CRYPT_OK) {
    if (ret=CRYPT_ERROR_WRONGKEY) {
      printf("Wrong Key\n");
      exit(ret);
    }else{ 
      printf("cryptSetAttributeString line %d returned <%d>\n",__LINE__,ret);
      exit(ret);
    }
  }



  ret=cryptFlushData(dataEnv);
  checkCryptNormal(ret,"cryptFlushData",__LINE__);

  clrKeySize=KEYSIZE;
  clrKeyPtr=malloc(clrKeySize);
  if (clrKeyPtr==NULL){perror("malloc");exit(__LINE__);}
  bzero(clrKeyPtr,clrKeySize);

  ret=cryptPopData(dataEnv,clrKeyPtr,clrKeySize,&bytesCopied);
  checkCryptNormal(ret,"cryptPopData",__LINE__);

  ret=cryptDestroyEnvelope(dataEnv);  
  checkCryptNormal(ret,"cryptDestroyEnvelope",__LINE__);
  cryptKeysetClose(keyset);
  checkCryptNormal(ret,"cryptKeysetClose",__LINE__);

  printf("Bytes decrypted <%d>\n",bytesCopied);
  // for (i=0;i<bytesCopied;i++){printf("%c",clrKeyPtr[i]);}
  ret=cryptEnd();
  checkCryptNormal(ret,"cryptEnd",__LINE__);
 


  //read enc file
  encFileFd=open(encFile, O_RDONLY);
  if (encFileFd<=0){perror("(2) open encFileFd");exit(encFileFd);}
  ret=fstat(encFileFd,&encFileInfo);
  if (ret!=0){perror("fstat encFileFd");exit(ret);}
  encFileSize=encFileInfo.st_size;
  encFilePtr=malloc(encFileSize);
  if (encFilePtr==NULL){perror("malloc encData");exit(__LINE__);}
  ret=read(encFileFd,encFilePtr,encFileSize);
  if (ret!=encFileSize){perror("read encData");exit(ret);}
  close(encFileFd);


  //Decrypt and get the content of decrepted file
  cryptInit();
  ret=cryptAddRandom( NULL , CRYPT_RANDOM_SLOWPOLL);
  checkCryptNormal(ret,"cryptAddRandom",__LINE__);

  cryptCreateEnvelope(&dataEnv, CRYPT_UNUSED, CRYPT_FORMAT_AUTO);
  checkCryptNormal(ret,"cryptCreateEnvelope",__LINE__);
  cryptPushData(dataEnv,encFilePtr,encFileSize,&bytesCopied);
 
  checkCryptNormal(ret,"cryptPushData",__LINE__);
  cryptCreateContext(&symContext,CRYPT_UNUSED,SYMMETRIC_ALG);
  checkCryptNormal(ret,"cryptCreateContext",__LINE__);
 
  cryptSetAttributeString(symContext, CRYPT_CTXINFO_KEY,clrKeyPtr,clrKeySize);
  checkCryptNormal(ret,"cryptSetAttributeString",__LINE__);
  cryptSetAttribute(dataEnv,CRYPT_ENVINFO_SESSIONKEY,symContext);
  checkCryptNormal(ret,"cryptSetAttribute",__LINE__);

  ret=cryptDestroyContext(symContext);
  checkCryptNormal(ret,"cryptDestroyContext",__LINE__);

  cryptFlushData(dataEnv);

  clrFileSize=KEYSIZE+1028;
  clrFilePtr=malloc(encDataSize);
  ret=cryptPopData(dataEnv,clrFilePtr,clrFileSize,&bytesCopied);
  checkCryptNormal(ret,"cryptPopData",__LINE__);

  ret=cryptDestroyEnvelope(dataEnv);
  checkCryptNormal(ret,"cryptDestroyEnvelope",__LINE__);

  printf("<%d> bytes of decrypted data\n",bytesCopied);
  for (i=0;i<bytesCopied;i++){printf("%c",clrFilePtr[i]);}
  printf("\n");
  fflush(stdout);
  
  ret=cryptEnd();
  checkCryptNormal(ret,"cryptEnd",__LINE__);


  return 0;
}





















