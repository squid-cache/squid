/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
/* Find passwords ... */
/* We do it in a brute force way ... Cycle through all the possible passwords
   sending a logon to see if all it works ... We have to wait for any timeout
   the the server implements before we try the next one. We could open lots
   of connections to the server and then send the logon request and not wait
   for the reply. This would allow us to have lots of outstanding attempts at
   a time. */

#include <sys/types.h>
#include <unistd.h>
#if HAVE_STRING_H
#include <string.h>
#endif

#include "smblib/smblib.h"

int verbose = FALSE;
int lotc = FALSE;

char *SMB_Prots[] = {"PC NETWORK PROGRAM 1.0",
                     "MICROSOFT NETWORKS 1.03",
                     "MICROSOFT NETWORKS 3.0",
                     "LANMAN1.0",
                     "LM1.2X002",
                     "LANMAN2.1",
                     "NT LM 0.12",
                     "NT LANMAN 1.0",
                     NULL
                    };

void usage()

{
    fprintf(stderr,"Usage: find_password -u <user> -l <pwd-len-max> server\n");
}

/* figure out next password */

static int pwinit = FALSE, pwpos = 0;

int next_password(char *pw, int pwlen)

{
    int i, carry = FALSE;

    if (pwinit == FALSE) {

        pwinit = TRUE;
        memset(pw, 0, pwlen + 1);
        pwpos = 0;

    }

    i = pwpos;

    while (TRUE) {

        pw[i] = pw[i] + 1;

        /* If it has wrapped around, then inc to 1 and carry up the chain */

        if (pw[i] == 0) {

            pw[i] = 1;
            i = i - 1;

            if (i < 0) {  /* If we went off the end, increment pwpos */

                pwpos = pwpos + 1;
                if (pwpos >= pwlen) return(FALSE); /* No more passwords */

                pw[pwpos] = 1;
                return(TRUE);

            }

        } else
            return(TRUE);

        return(FALSE);
    }
}

static char pwd_str[1024];  /* Where we put passwords as we convert them */

char *print_password(char * password)

{
    int i,j;
    char temp[4];

    j = 0;

    for (i = 0; i < strlen(password); i++) {

        if (((unsigned)password[i] <= ' ') || ((unsigned)password[i] > 127)) {

            pwd_str[j] = '\\';
            snprintf(temp, sizeof(temp)-1, "%03i", (int)password[i]);
            strcpy(&pwd_str[j + 1], temp);
            j = j + 3;                       /* Space for \ accounted for below */

        } else
            pwd_str[j] = password[i];

        j = j + 1;

    }

    pwd_str[j] = 0;  /* Put a null on the end ... */

    return(pwd_str);

}

main(int argc, char *argv[])

{
    void *con, *tree;
    extern char *optarg;
    extern int optind;
    int opt, error, SMB_Error, err_class, err_code, pwlen, tries = 0;
    char server[80], service[80], service_name[160], password[80], username[80];
    char old_password[80], err_string[1024];

    server[0] = 0;
    strncpy(service, "IPC$", sizeof(service) - 1);
    service_name[0] = 0;
    username[0] = 0;
    password[0] = 0;
    old_password[0] = 0;

    while ((opt = getopt(argc, argv, "s:u:l:v")) != EOF) {

        switch (opt) {
        case 's':

            strcpy(service, optarg);
            break;

        case 'u':     /* Pick up the user name */

            strncpy(username, optarg, sizeof(username) - 1);
            break;

        case 'l':     /* pick up password len */

            pwlen = atoi(optarg);
            break;

        case 'v':     /* Verbose? */
            verbose = TRUE;
            break;

        default:

            usage();
            exit(1);
            break;
        }

    }

    if (optind < argc) { /* Some more parameters, assume is the server */
        strncpy(server, argv[optind], sizeof(server) - 1);
        optind++;
    } else {
        strcpy(server, "nemesis");
    }

    if (verbose == TRUE) {  /* Print out all we know */

        fprintf(stderr, "Finding password for User: %s, on server: %s\n",
                username, server);
        fprintf(stderr, "with a pwlen = %i\n", pwlen);

    }

    SMB_Init();          /* Initialize things ... */

    /* We connect to the server and negotiate */

    con = SMB_Connect_Server(NULL, server);

    if (con == NULL) {  /* Error processing */

        fprintf(stderr, "Unable to connect to server %s ...\n", server);

        if (SMB_Get_Last_Error() == SMBlibE_Remote) {

            SMB_Error = SMB_Get_Last_SMB_Err();
            SMB_Get_SMB_Error_Msg(SMBlib_Error_Class(SMB_Error),
                                  SMBlib_Error_Code(SMB_Error),
                                  err_string,
                                  sizeof(err_string) - 1);

        } else {
            SMB_Get_Error_Msg(SMB_Get_Last_Error(), err_string, sizeof(err_string) - 1);
        }

        printf("  %s\n", err_string);
        exit(1);

    }

    /* We need to negotiate a protocol better than PC NetWork Program */

    if (SMB_Negotiate(con, SMB_Prots) < 0) {

        fprintf(stderr, "Unable to negotiate a protocol with server %s ...\n",
                server);

        if (SMB_Get_Last_Error() == SMBlibE_Remote) {

            SMB_Error = SMB_Get_Last_SMB_Err();
            SMB_Get_SMB_Error_Msg(SMBlib_Error_Class(SMB_Error),
                                  SMBlib_Error_Code(SMB_Error),
                                  err_string,
                                  sizeof(err_string) - 1);

        } else {
            SMB_Get_Error_Msg(SMB_Get_Last_Error(), err_string, sizeof(err_string) - 1);
        }

        printf("  %s\n", err_string);
        exit(1);

    }

    sprintf(service_name, sizeof(service_name)-1, "\\\\%s\\%s", server, service); /* Could blow up */

    /* Now loop through all password possibilities ... */

    memset(password, 0, sizeof(password));

    while (next_password(password, pwlen) == TRUE) {

        if ((tree = SMB_Logon_And_TCon(con,
                                       NULL,
                                       username,
                                       password,
                                       service_name, "?????")) == NULL) {

            if (verbose == TRUE) { /* Lets hear about the error */

                fprintf(stderr, "Unable to logon and tree connect to server %s ...\n",
                        server);
                fprintf(stderr, "With username: %s, and password: %s\n",
                        username, print_password(password));

                if (SMB_Get_Last_Error() == SMBlibE_Remote) {

                    SMB_Error = SMB_Get_Last_SMB_Err();
                    SMB_Get_SMB_Error_Msg(SMBlib_Error_Class(SMB_Error),
                                          SMBlib_Error_Code(SMB_Error),
                                          err_string,
                                          sizeof(err_string) - 1);

                } else {
                    SMB_Get_Error_Msg(SMB_Get_Last_Error(), err_string, sizeof(err_string) - 1);
                }

                printf("  %s\n", err_string);

            }
        } else { /* Password match */

            fprintf(stderr, "Logged in with password:%s\n",
                    print_password(password));

            /* Exit now ... */

            exit(0);

        }

    }

    fprintf(stderr, "Passwords exhausted.");

}

