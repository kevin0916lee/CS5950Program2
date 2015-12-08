/*===========================================================
 
  (1) Encrypts STRING with the public key of the input user 
      USERID
  (2) Gets the private key for USERID
  (3) Decrypts encrypted string and writes it to stdout


Arguments:     argv[1]=USERID
               argv[2]=STRING
    

Compilation: gcc -o skelSoln -lcl -ldl -lresolv -lpthread

===========================================================
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
#include <pwd.h>
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

void checkCryptNormal(int returnCode, char *routineName, int line){
  if (cryptStatusError(returnCode)){
    printf("Error in %s at line %d, return value %d\n",
	   routineName, line, returnCode);
    exit(returnCode);
  }
}
main(int argc, char **argv){

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
  
  uid_t ownerID = getuid();
  struct passwd *owner_pws = getpwuid(ownerID);
  char* owner_pwname = owner_pws->pw_name;//get the user login name;
  char* owner_pwdir = owner_pws->pw_dir;
  char          *fileKeyName = malloc(owner_pwname)+strlen(argv[2]+10);
  fileKeyName = strcat(argv[2]+".enc.");
  fileKeyName = strcat(fileKeyName,owner_pwname);
  fileKeyName = strcat(fileKeyName,".key");
  uid_t userID = getuid();
  struct passwd *user_pws = getpwuid(userID);
  char* user_pwname = user_pws->pw_name;//get the user login name;
  char* user_pwdir = user_pws->pw_dir;
  char          *outputFileKeyName = malloc(user_pwname)+strlen(argv[2]+10);
  outputFileKeyName = strcat(argv[2]+".enc.");
  outputFileKeyName = strcat(outputFileKeyName,user_pwname);
  outputFileKeyName = strcat(outputFileKeyName,".key");
  
 /*==============================================
     Check Check Check Check Check Check
    ==============================================
   */
  if (argc!=3) {printf("Wrong number of arguments\n");exit(1);}
  fileChecker(argv[2]);
  
   /*==============================================
     Cryptlib initialization
    ==============================================
   */
  cryptInit();
  ret=cryptAddRandom( NULL , CRYPT_RANDOM_SLOWPOLL);
  checkCryptNormal(ret,"cryptAddRandom",__LINE__);
  
  
  
   /*======================================================
    Get decrypted data from file and write to stdout
    ======================================================
   */
  encDataFd=open(fileKeyName,O_RDONLY);
  if (encDataFd<=0){perror("(2) open encDataFd");exit(encDataFd);}
  ret=fstat(encDataFd,&encDataFileInfo);
  if (ret!=0){perror("fstat encDataFd");exit(ret);}
  encDataSize=encDataFileInfo.st_size;
  encDataPtr=malloc(encDataSize);
  if (encDataPtr==NULL){perror("malloc encData");exit(__LINE__);}

  ret=read(encDataFd,encDataPtr,encDataSize);
  if (ret!=encDataSize){perror("read encData");exit(ret);}
  close(encDataFd);
  
  
   /*=================================================
    Decrypt the key
    =================================================
  */

  keyFile=malloc(  strlen(owner_pw_dir )
                 + strlen("/.gnupg/secring.gpg") + 1);
  if (keyFile==NULL){perror("malloc");exit(__LINE__);}
  strcpy(keyFile,owner_pw_dir);
  strcat(keyFile,"/.gnupg/secring.gpg");
  printf("Getting secret key from <%s>\n",keyFile);

  ret=cryptKeysetOpen(&keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, keyFile, CRYPT_KEYOPT_READONLY);
  free(keyFile);
  checkCryptNormal(ret,"cryptKeysetOpen",__LINE__);
  ret=cryptCreateEnvelope(&dataEnv, CRYPT_UNUSED, CRYPT_FORMAT_AUTO);
  checkCryptNormal(ret,"cryptCreateEnvelope",__LINE__);
  ret=cryptSetAttribute(dataEnv, CRYPT_ENVINFO_KEYSET_DECRYPT, keyset);
  checkCryptNormal(ret,"cryptSetAttribute",__LINE__);

  ret=cryptPushData(dataEnv,encDataPtr,encDataSize,&bytesCopied);
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

  clrDataSize=strlen(argv[2])+1;
  clrDataPtr=malloc(clrDataSize);
  if (clrDataPtr==NULL){perror("malloc");exit(__LINE__);}
  bzero(clrDataPtr,clrDataSize);

  ret=cryptPopData(dataEnv,clrDataPtr,clrDataSize,&bytesCopied);
  checkCryptNormal(ret,"cryptPopData",__LINE__);

  ret=cryptDestroyEnvelope(dataEnv);  
  checkCryptNormal(ret,"cryptDestroyEnvelope",__LINE__);
  cryptKeysetClose(keyset);
  checkCryptNormal(ret,"cryptKeysetClose",__LINE__);

  printf("Bytes decrypted <%d>\n",bytesCopied);
  for (i=0;i<bytesCopied;i++){printf("%c",clrDataPtr[i]);}

  ret=cryptEnd();
  checkCryptNormal(ret,"cryptEnd",__LINE__);
  
  /*===============================================
    Encrypt Symmetric Key to a key file
    ===============================================
  */
   /*====================================================
    Get key file name 
    ====================================================
  */
  userInfo=getpwnam(argv[1]);
  if (userInfo==NULL){perror("getpwnam");exit(__LINE__);};
  keyFile=malloc(  strlen(userInfo->pw_dir )
                 + strlen("/.gnupg/pubring.gpg") + 1);
  if (keyFile==NULL){perror("malloc");exit(__LINE__);}
  strcpy(keyFile,userInfo->pw_dir);
  strcat(keyFile,"/.gnupg/pubring.gpg");
  printf("Getting key from <%s>\n",keyFile);

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
  ret=cryptSetAttributeString(dataEnv, CRYPT_ENVINFO_RECIPIENT, 
                              "pwcorbet",strlen(argv[1]));
  checkCryptNormal(ret,"cryptSetAttributeString",__LINE__);
  ret=cryptSetAttribute(dataEnv, CRYPT_ENVINFO_DATASIZE, strlen(argv[2])+1);

  ret=cryptPushData(dataEnv,argv[2],strlen(argv[2])+1,&bytesCopied);
  checkCryptNormal(ret,"cryptPushData",__LINE__);
  ret=cryptFlushData(dataEnv);
  checkCryptNormal(ret,"cryptFlushData",__LINE__);

  encDataSize=strlen(clrDataPtr)+1+1028;
  encDataPtr=malloc(encDataSize);
  if (encDataPtr==NULL){perror("malloc");exit(__LINE__);}
  ret=cryptPopData(dataEnv,encDataPtr,encDataSize,&bytesCopied);
  printf("cryptPopData returned <%d> bytes of encrypted data\n",bytesCopied);
  encDataSize=bytesCopied;

  ret=cryptDestroyEnvelope(dataEnv);  
  checkCryptNormal(ret,"cryptDestroyEnvelope",__LINE__);
  cryptKeysetClose(keyset);
  checkCryptNormal(ret,"cryptKeysetClose",__LINE__);
  /*==============================================
     
        write it to output file.
    ==============================================
  */

  

  encDataFd=open(outputFileKeyName,O_RDWR|O_CREAT|O_TRUNC,S_IRUSR|S_IWUSR);
  if (encDataFd<=0){perror("open encDataFd");exit(encDataFd);}
  ret=write(encDataFd,encDataPtr,bytesCopied);
  if (ret!=bytesCopied){perror("write encData");exit(ret);}
  close(encDataFd);
  free(encDataPtr);

  
  
  
  
  }
