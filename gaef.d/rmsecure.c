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
//File owner and states checker
void fileChecker(char *file){
	uid_t ownerID;
    int f = -1;
    struct stat fs;
  	//Check file owner
    f = open(file, O_RDONLY);

    if (f < 0){
        printf("slient exit1\n");
        exit (1);
    }
    if (fstat(f, &fs)<0)
    {
        printf("slient exit2\n");
        exit (1);
    }
    ownerID = fs.st_uid;
	uid_t uid = getuid();
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
main(int argc, char **argv){

  uid_t ownerID = getuid();
  struct passwd *owner_pws = getpwuid(ownerID);
  char* owner_pwname = owner_pws->pw_name;//get the user login name;
  char* owner_pwdir = owner_pws->pw_dir;
  char          *fileKeyName = malloc(strlen(owner_pwname)+strlen(argv[2]+20));

  memcpy(fileKeyName,argv[2],strlen(argv[2])+1);
  strcat(fileKeyName,".");
  strcat(fileKeyName,owner_pwname);
  
  strcat(fileKeyName,".key");
  printf("%s\n",fileKeyName);
  
  
  char          *outputFileKeyName = malloc(strlen(argv[1])+strlen(argv[2])+20);
  
  memcpy(outputFileKeyName,argv[2],strlen(argv[2])+1);
  strcat(outputFileKeyName,".");
  strcat(outputFileKeyName,argv[1]);
  strcat(outputFileKeyName,".key");
  printf("%s\n",outputFileKeyName);
  
 /*==============================================
     Check Check Check Check Check Check
    ==============================================
   */
  if (argc!=3) {printf("Wrong number of arguments\n");exit(1);}
  char *fileName = malloc(strlen(argv[2])+5);
  strcpy(fileName,argv[2]);
  strcat(fileName,".enc");
  
  fileChecker(fileName);
  /*==============================================
     Remove the file 
    ==============================================
   */
   int status = remove(argv[1]);
   if( status == 0 ){
	   printf("%s file deleted successfully.\n",argv[1]);
	   return 0;
	}
}
