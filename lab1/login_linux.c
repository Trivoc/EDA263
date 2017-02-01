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
/* Uncomment next line in step 2 */
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void noop(int sign) {}

void intercept_signal(int sign, void(*function) (int)) {
    signal(sign, function);
}

void sighandler() {
   intercept_signal(SIGINT, &sighandler);
   intercept_signal(SIGTSTP, &sighandler);
   intercept_signal(SIGQUIT, &sighandler);
}

int main(int argc, char *argv[]) {

	mypwent *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important[LENGTH] = "***IMPORTANT***";

	char user[LENGTH];
	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important' before input of login name: %s\n",
				important);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user, LENGTH, stdin) == NULL) /* gets() is vulnerable to buffer */
			exit(0); /*  overflow attacks.  */

		char *newlinepos = strchr(user, '\n');
		if (newlinepos != NULL) {
			*newlinepos = '\0';
		}

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);

		if (passwddata != NULL) {

			/* Locks login attempts indefinitely after 5 failed attempts.
			Also, you have to encrypt user_pass for this to work.
			Don't forget to include the salt */
			if(passwddata->pwfailed > 5){
				printf("More than 5 unsuccessful logins: account locked.");
			} else if (!strcmp(crypt(user_pass, passwddata->passwd_salt), passwddata->passwd)) {
				if (passwddata->pwfailed > 0) {
					printf("Number of unsuccessful login attempts: %d\n", passwddata->pwfailed);
				}
				passwddata->pwfailed = 0;
				passwddata->pwage++;

				printf(" You're in !\n");
				if (setuid(passwddata->uid) == -1) {
					perror("setuid error");
				} else {
					mysetpwent(user, passwddata);
					char *args[] = { "/bin/sh", NULL };
					if (execve(args[0], args, NULL) == -1) {
						perror("execve error");
					}
				}
			} else {
				passwddata->pwfailed++;
			}

			mysetpwent(user, passwddata);
		}
		printf("Login Incorrect \n");
	}
	return 0;
}



