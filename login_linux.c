/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -Wall -g -o mylogin login.linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include "pwent.h" 

#define TRUE 1
#define FALSE 0
#define LENGTH 16
#define AGELIMIT 60     
#define ATTEMPTS 10


void sighandler() {
    signal(SIGINT,SIG_IGN);    /*ctrl-c*/
    signal(SIGTSTP,SIG_IGN);   /*ctrl-z*/
    signal(SIGQUIT,SIG_IGN);   /*ctrl-\*/
    }

int main(int argc, char *argv[]) {

    mypwent *passwddata;
    char important[LENGTH] = "***IMPORTANT***";
    char user[LENGTH];
    char prompt[] = "password: ";
    char *user_pass;
    char *hash;
    char * const argv1[] = {"/bin/ls", NULL};
    char * const envp[] = {NULL};

    sighandler();
   
    while (TRUE) {
       /* check what important variable contains - do not remove, part of buffer overflow test */
       printf("Value of variable 'important' before input of login name: %s\n",
          important);

       printf("login: ");
       fflush(NULL); /* Flush all  output buffers */
       __fpurge(stdin); /* Purge any data in stdin buffer */

       if (fgets(user, LENGTH, stdin ) == NULL) /* gets() is vulnerable to buffer */
           exit(-1); /*  overflow attacks.  */
       user[strlen(user)-1] = '\0';

       /* check to see if important variable is intact after input of login name - do not remove */
       printf("Value of variable 'important' after input of login name: %*.*s\n",
              LENGTH - 1, LENGTH - 1, important);

       user_pass = getpass(prompt);
       if((passwddata = mygetpwnam(user))==NULL)
             printf("User does not exist\n");                 

       if (passwddata != NULL) {			

          if(passwddata->pwfailed >= ATTEMPTS){
             printf("%d incorrect password attempts\n", ATTEMPTS);
                           
             if(!mysetpwent(passwddata->pwname, passwddata))
                printf("Data not updated\n");

             sleep(10);  
          }

       /* password encryption using the salt */
       if((hash = crypt(user_pass, passwddata->passwd_salt))==NULL)			
          printf(" crypt program failed \n");

       if (!strncmp(hash, passwddata->passwd, strlen(passwddata->passwd)) ){
          printf(" You're in !\n");

          if(passwddata->pwfailed){
             printf(" Number of failed attempts: %d \n", passwddata->pwfailed);
             passwddata->pwfailed = 0;				
          }

          passwddata->pwage = passwddata->pwage +1;

          if(!mysetpwent(passwddata->pwname, passwddata))				
             printf("Password data not updated\n");

          if(passwddata->pwage>= AGELIMIT){
             printf("Your password has expired and must be changed!!\n");
          }

          /*  check UID, see setuid(2) */
          /*  starting a shell */
          if((setuid(passwddata->uid))==-1)
             printf("Setuid program failed  \n");

          if((execve ("/bin/ls", argv1, envp))==-1);
             printf("execve program failed \n");
       }
       else {
          sleep(5);    //sleep for 5 seconds for a wrong login in attempt
          passwddata->pwfailed = passwddata->pwfailed +1;
          if(!mysetpwent(passwddata->pwname, passwddata))
             printf("Password data not updated\n");

       }			
       }
    printf("Login Incorrect \n");		
    } //end while loop
    return 0;
}

