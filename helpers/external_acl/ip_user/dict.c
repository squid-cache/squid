/* $Id: dict.c,v 1.2 2003/01/23 00:36:01 robertc Exp $ 
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
			  
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ip_user.h"

#ifndef DEBUG
#undef DEBUG
#endif


/* This function parses the dictionary file and loads it 
 * in memory. All IP addresses are processed with a bitwise AND
 * with their netmasks before they are stored.
 * If there´s no netmask (no /) in the in the lhs , a mask
 * 255.255.255.255 is assumed.
 * It returns a pointer to the first entry of the linked list
 */
struct ip_user_dict *
load_dict (FILE * FH)
{
  struct ip_user_dict *current_entry;	/* the structure used to
					   store data */
  struct ip_user_dict *first_entry = NULL;	/* the head of the
						   linked list */
  char line[BUFSIZE];		/* the buffer for the lines read
				   from the dict file */
  char *cp;			/* a char pointer used to parse
				   each line */
  char *username;		/* for the username */
  char *tmpbuf;			/* for the address before the
				   bitwise AND */

  /* the pointer to the first entry in the linked list */
  first_entry = malloc (sizeof (struct ip_user_dict));
  current_entry = first_entry;

  while ((cp = fgets (line, sizeof (line), FH)) != NULL) {
		  if (line[0] == '#') {
				  continue;
		  }
    if ((cp = strchr (line, '\n')) != NULL) {
      /* chop \n characters */
      *cp = '\0';
    }
    if ((cp = strtok (line, "\t ")) != NULL) {
      /* get the username */
      username = strtok (NULL, "\t ");
      /* look for a netmask */
      if ((cp = strtok (line, "/")) != NULL) {
	/* store the ip address in a temporary buffer */
	tmpbuf = cp;
	cp = strtok (NULL, "/");
	if (cp != NULL) {
	  /* if we have a slash in the lhs, we have a netmask */
	  current_entry->netmask = (inet_addr (cp));
	  current_entry->address =
	    (((inet_addr (tmpbuf))) & current_entry->netmask);
	} else {
	  /* when theres no slash, we figure the netmask is /32 */
	  current_entry->address = (inet_addr (tmpbuf));
	  current_entry->netmask = (inet_addr ("255.255.255.255"));
	}
      }
      /* get space for the username */
      current_entry->username =
	calloc (strlen (username) + 1, sizeof (char));
      strcpy (current_entry->username, username);

      /* get space and point current_entry to the new entry */
      current_entry->next_entry =
	malloc (sizeof (struct ip_user_dict));
      current_entry = current_entry->next_entry;
    }

  }

  /* Return a pointer to the first entry linked list */
  return first_entry;
}				/* load_dict */

/* This function looks for a matching ip/mask in
 * the dict file loaded in memory.
 * It returns 1 if it finds a match or 0 if no match is found
 */
int
dict_lookup (struct ip_user_dict *first_entry, char *username,
	     char *address)
{
  /* Move the pointer to the first entry of the linked list. */
  struct ip_user_dict *current_entry = first_entry;

  while (current_entry->username != NULL) {
#ifdef DEBUG
    printf ("user: %s\naddr: %lu\nmask: %lu\n\n",
	    current_entry->username, current_entry->address,
	    current_entry->netmask);
#endif

    if ((inet_addr (address) & (unsigned long) current_entry->
	 netmask) == current_entry->address) {
      /* If the username contains an @ we assume it´s a group and
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
}				/* dict_lookup */
