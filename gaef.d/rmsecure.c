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
  fileChecker(argv[2]);
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
