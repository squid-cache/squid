/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * Copyright (C) 2002 Rodrigo Campos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Author: Rodrigo Campos (rodrigo@geekbunker.org)
 *
 */
#include "squid.h"
#include "helpers/defines.h"
#include "rfc1738.h"
#include "util.h"

#include <cstdlib>
#include <cstring>
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_GRP_H
#include <grp.h>
#endif

struct ip_user_dict {
    unsigned long address; // IP address (assumes IPv4)
    unsigned long netmask; // IP netmask
    char *username;
    struct ip_user_dict *next_entry;
};

int match_user(char *, char *);
int match_group(char *, char *);
struct ip_user_dict *load_dict(FILE *);
int dict_lookup(struct ip_user_dict *, char *, char *);

/** Size of lines read from the dictionary file */
#define DICT_BUFFER_SIZE    8196

/** This function parses the dictionary file and loads it
 * in memory. All IP addresses are processed with a bitwise AND
 * with their netmasks before they are stored.
 * If there?s no netmask (no /) in the in the lhs , a mask
 * 255.255.255.255 is assumed.
 * It returns a pointer to the first entry of the linked list
 */
struct ip_user_dict *
load_dict(FILE * FH) {
    struct ip_user_dict *current_entry; /* the structure used to
                       store data */
    struct ip_user_dict *first_entry = NULL;    /* the head of the
                           linked list */
    char line[DICT_BUFFER_SIZE]; /* the buffer for the lines read
                   from the dict file */
    char *tmpbuf;           /* for the address before the
                   bitwise AND */

    /* the pointer to the first entry in the linked list */
    first_entry = static_cast<struct ip_user_dict*>(xmalloc(sizeof(struct ip_user_dict)));
    current_entry = first_entry;

    unsigned int lineCount = 0;
    while (fgets(line, sizeof(line), FH) != NULL) {
        ++lineCount;
        if (line[0] == '#') {
            continue;
        }

        char *cp; // a char pointer used to parse each line.
        if ((cp = strchr (line, '\n')) != NULL) {
            /* chop \n characters */
            *cp = '\0';
        }
        if (strtok(line, "\t ") != NULL) {
            // NP: line begins with IP/mask. Skipped to the end of it with this strtok()

            /* get the username */
            char *username;
            if ((username = strtok(NULL, "\t ")) == NULL) {
                debug("Missing username on line %u of dictionary file\n", lineCount);
                continue;
            }

            /* look for a netmask */
            if ((cp = strtok (line, "/")) != NULL) {
                /* store the ip address in a temporary buffer */
                tmpbuf = cp;
                cp = strtok (NULL, "/");
                if (cp != NULL) {
                    /* if we have a slash in the lhs, we have a netmask */
                    current_entry->netmask = (inet_addr(cp));
                    current_entry->address =
                        (((inet_addr (tmpbuf))) & current_entry->netmask);
                } else {
                    /* when theres no slash, we figure the netmask is /32 */
                    current_entry->address = (inet_addr(tmpbuf));
                    current_entry->netmask = (inet_addr("255.255.255.255"));
                }
            }
            /* get space for the username */
            current_entry->username =
                (char*)calloc(strlen(username) + 1, sizeof(char));
            strcpy(current_entry->username, username);

            /* get space and point current_entry to the new entry */
            current_entry->next_entry =
                static_cast<struct ip_user_dict*>(xmalloc(sizeof(struct ip_user_dict)));
            current_entry = current_entry->next_entry;
        }

    }

    /* Return a pointer to the first entry linked list */
    return first_entry;
}

/** This function looks for a matching ip/mask in
 * the dict file loaded in memory.
 * It returns 1 if it finds a match or 0 if no match is found
 */
int
dict_lookup(struct ip_user_dict *first_entry, char *username,
            char *address)
{
    /* Move the pointer to the first entry of the linked list. */
    struct ip_user_dict *current_entry = first_entry;

    while (current_entry->username != NULL) {
        debug("user: %s\naddr: %lu\nmask: %lu\n\n",
              current_entry->username, current_entry->address,
              current_entry->netmask);

        if ((inet_addr (address) & (unsigned long) current_entry->
                netmask) == current_entry->address) {
            /* If the username contains an @ we assume it?s a group and
               call the corresponding function */
            if ((strchr (current_entry->username, '@')) == NULL) {
                if ((match_user (current_entry->username, username)) == 1)
                    return 1;
            } else {
                if ((match_group (current_entry->username, username)) == 1)
                    return 1;
            }
        }
        current_entry = current_entry->next_entry;
    }

    /* If no match was found we return 0 */
    return 0;
}

int
match_user(char *dict_username, char *username)
{
    if ((strcmp(dict_username, username)) == 0) {
        return 1;
    } else {
        if ((strcmp(dict_username, "ALL")) == 0) {
            return 1;
        }
    }
    return 0;
}               /* match_user */

int
match_group(char *dict_group, char *username)
{
    struct group *g;        /* a struct to hold group entries */
    ++dict_group;           /* the @ should be the first char
                   so we rip it off by incrementing
                   * the pointer by one */

    if ((g = getgrnam(dict_group)) == NULL) {
        debug("Group does not exist '%s'\n", dict_group);
        return 0;
    } else {
        while (*(g->gr_mem) != NULL) {
            if (strcmp(*((g->gr_mem)++), username) == 0) {
                return 1;
            }
        }
    }
    return 0;

}

static void
usage(const char *program_name)
{
    fprintf (stderr, "Usage:\n%s [-d] -f <configuration file>\n",
             program_name);
}

int
main (int argc, char *argv[])
{
    char *filename = NULL;
    char *program_name = argv[0];
    char *cp;
    char *username, *address;
    char line[HELPER_INPUT_BUFFER];
    struct ip_user_dict *current_entry;
    int ch;

    setvbuf (stdout, NULL, _IOLBF, 0);
    while ((ch = getopt(argc, argv, "df:h")) != -1) {
        switch (ch) {
        case 'f':
            filename = optarg;
            break;
        case 'd':
            debug_enabled = 1;
            break;
        case 'h':
            usage(program_name);
            exit (0);
        default:
            fprintf(stderr, "%s: FATAL: Unknown parameter option '%c'", program_name, ch);
            usage(program_name);
            exit (1);
        }
    }
    if (filename == NULL) {
        fprintf(stderr, "%s: FATAL: No Filename configured.", program_name);
        usage(program_name);
        exit(1);
    }
    FILE *FH = fopen(filename, "r");
    if (!FH) {
        fprintf(stderr, "%s: FATAL: Unable to open file '%s': %s", program_name, filename, xstrerror());
        exit(1);
    }
    current_entry = load_dict(FH);

    while (fgets(line, HELPER_INPUT_BUFFER, stdin)) {
        if ((cp = strchr (line, '\n')) == NULL) {
            /* too large message received.. skip and deny */
            fprintf(stderr, "%s: ERROR: Input Too Large: %s\n", program_name, line);
            while (fgets(line, sizeof(line), stdin)) {
                fprintf(stderr, "%s: ERROR: Input Too Large..: %s\n", program_name, line);
                if (strchr(line, '\n') != NULL)
                    break;
            }
            SEND_BH(HLP_MSG("Input Too Large."));
            continue;
        }
        *cp = '\0';
        address = strtok(line, " \t");
        username = strtok(NULL, " \t");
        if (!address || !username) {
            debug("%s: unable to read tokens\n", program_name);
            SEND_BH(HLP_MSG("Invalid Input."));
            continue;
        }
        rfc1738_unescape(address);
        rfc1738_unescape(username);
        int result = dict_lookup(current_entry, username, address);
        debug("%s: result: %d\n", program_name, result);
        if (result != 0) {
            SEND_OK("");
        } else {
            SEND_ERR("");
        }
    }

    fclose (FH);
    return 0;
}

