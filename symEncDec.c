/*=====================================================================
 
  (1) Generates a random number to be used as a key KEY
  (2) Encrypts named file DATAFILE with KEY and writes it
      to ENCDATAFILE.
  (3) Decrypts ENCDATAFILE with KEY and writes it to
      stdout.


Arguments:     argv[1]=DATAFILE
               argv[2]=ENCDATAFILE

----------------------------------------------------------------------
Compilation: gcc -o symEncDec symEncDec.c -lcl -ldl -lresolv -lpthread
======================================================================
*/

#include "cryptlib.h"
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

#define  SYMMETRIC_ALG   CRYPT_ALGO_BLOWFISH
#define  KEYSIZE         56

void checkCryptNormal(int returnCode, char *routineName, int line){

  if (cryptStatusError(returnCode)){
    printf("Error in %s at line %d, return value %d\n",
	   routineName,line,returnCode);
    exit(returnCode);
  }
}

main(int argc, char **argv){


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


  if (argc!=3) {printf("Wrong number of arguments\n");exit(__LINE__);}


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

  encDataFd=open(argv[2],O_RDWR|O_CREAT|O_TRUNC,S_IRUSR|S_IWUSR);
  if (encDataFd<=0){perror("open encDataFd");exit(encDataFd);}
  ret=write(encDataFd,encDataPtr,bytesCopied);
  if (ret!=bytesCopied){perror("write encData");exit(ret);}
  close(encDataFd);
  free(encDataPtr);

  /*======================================================
    Get decrypted data from file and write to stdout
    ======================================================
  */
  encDataFd=open(argv[2],O_RDONLY);
  if (encDataFd<=0){perror("(2) open encDataFd");exit(encDataFd);}
  ret=fstat(encDataFd,&encDataFileInfo);
  if (ret!=0){perror("fstat encDataFd");exit(ret);}
  encDataSize=encDataFileInfo.st_size;
  encDataPtr=malloc(encDataSize);
  if (encDataPtr==NULL){perror("malloc encData");exit(__LINE__);}

  ret=read(encDataFd,encDataPtr,encDataSize);
  if (ret!=encDataSize){perror("read encData");exit(ret);}
  close(encDataFd);
  
  cryptCreateEnvelope(&dataEnv, CRYPT_UNUSED, CRYPT_FORMAT_AUTO);
  checkCryptNormal(ret,"cryptCreateEnvelope",__LINE__);
  cryptPushData(dataEnv,encDataPtr,encDataSize,&bytesCopied);
  checkCryptNormal(ret,"cryptPushData",__LINE__);
  cryptCreateContext(&symContext,CRYPT_UNUSED,SYMMETRIC_ALG);
  checkCryptNormal(ret,"cryptCreateContext",__LINE__);
  cryptSetAttributeString(symContext, CRYPT_CTXINFO_KEY,keyPtr,KEYSIZE);
  checkCryptNormal(ret,"cryptSetAttributeString",__LINE__);
  cryptSetAttribute(dataEnv,CRYPT_ENVINFO_SESSIONKEY,symContext);
  checkCryptNormal(ret,"cryptSetAttribute",__LINE__);

  ret=cryptDestroyContext(symContext);
  checkCryptNormal(ret,"cryptDestroyContext",__LINE__);

  cryptFlushData(dataEnv);
  ret=cryptPopData(dataEnv,clrDataPtr,clrDataSize,&bytesCopied);
  checkCryptNormal(ret,"cryptPopData",__LINE__);

  ret=cryptDestroyEnvelope(dataEnv);
  checkCryptNormal(ret,"cryptDestroyEnvelope",__LINE__);

  printf("<%d> bytes of decrypted data\n",bytesCopied);
  for (i=0;i<bytesCopied;i++){printf("%c",clrDataPtr[i]);}
  printf("\n");
  fflush(stdout);
  
  ret=cryptEnd();
  checkCryptNormal(ret,"cryptEnd",__LINE__);
  }


