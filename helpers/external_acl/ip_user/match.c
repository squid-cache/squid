/* $Id: match.c,v 1.2 2003/01/23 00:36:01 robertc Exp $ 
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
#include <string.h>
#include <sys/types.h>
#include <grp.h>


int
match_user (char *dict_username, char *username)
{
  if ((strcmp (dict_username, username)) == 0) {
    return 1;
  } else {
    if ((strcmp (dict_username, "ALL")) == 0) {
      return 1;
    }
  }
  return 0;
}				/* match_user */

int
match_group (char *dict_group, char *username)
{
  struct group *g;		/* a struct to hold group entries */
  dict_group++;			/* the @ should be the first char
				   so we rip it off by incrementing 
				   * the pointer by one */

  if ((g = getgrnam (dict_group)) == NULL) {
    fprintf (stderr, "helper: Group does not exist '%s'\n",
	     dict_group);
    return 0;
  } else {
    while (*(g->gr_mem) != NULL) {
      if (strcmp (*((g->gr_mem)++), username) == 0) {
	return 1;
      }
    }
  }
  return 0;

}				/* match_group */
