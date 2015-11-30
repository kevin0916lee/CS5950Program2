/*===========================================================
 
  (1) Generates a cryptographic random number 
 
  NOTES: No error handling or key protection.
-------------------------------------------------------------
  Invocation:  genRand  keySize
-------------------------------------------------------------
  Compilation: gcc -o genRand genRand.c
=============================================================
*/

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>


main(int argc, char **argv){

  int  ret;  
  int  total;
  char *keyPtr;
  int  urandFd;
  int  keySize;
  
  keySize=atoi(argv[1]);
  keyPtr=malloc(keySize);
  urandFd=open("/dev/urandom",O_RDONLY);
  total=0;
  while (total<keySize) {
    ret=read(urandFd,&keyPtr[total],keySize-total);total+=ret;
  }
  printf("Successful generation of key with size <%d>\n",total);
  close(urandFd);

}


