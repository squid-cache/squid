/* $Id: ip_user.h,v 1.2 2003/01/23 00:36:01 robertc Exp $
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




struct ip_user_dict
{
  unsigned long address;
  unsigned long netmask;
  char *username;
  struct ip_user_dict *next_entry;
};

extern int match_user(char *, char *);
extern int match_group(char *, char *);
extern struct ip_user_dict *load_dict(FILE *);
extern int dict_lookup(struct ip_user_dict *, char *, char *);


#define BUFSIZE 1024
