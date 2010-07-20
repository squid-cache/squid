/* squid_edir_iplookup - Copyright (C) 2009, 2010 Chad E. Naugle
 *
 ********************************************************************************
 *
 *  This file is part of squid_edir_iplookup.
 *
 *  squid_edir_iplookup is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  squid_edir_iplookup is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with squid_edir_iplookup.  If not, see <http://www.gnu.org/licenses/>.
 *
 ********************************************************************************
 *
 * main.h --
 *
 * Main program includes & conf_t struct typedef for program configuration.
 *
 */

#ifndef _HAVE_MAIN_H
#define _HAVE_MAIN_H

#ifndef _HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef DEFAULT_PROGRAM_NAME
#define DEFAULT_PROGRAM_NAME		"squid_edir_iplookup"
#endif

/* Must ... include ... these ... */
#include <stdio.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>

#ifdef DEFAULT_MAXLEN
#define MAXLEN		DEFAULT_MAXLEN
#else
#define MAXLEN		1024
#endif
#define MODE_INIT	0x01
#define MODE_DEBUG	0x02
#define MODE_TLS	0x04
#define MODE_IPV4	0x08
#define MODE_IPV6	0x10
#define MODE_KILL	0x20
#define MODE_GROUP	0x40				/* Group is REQUIRED */

/* conf_t - Program configuration struct typedef */
typedef struct {
  char program[MAXLEN];
  char basedn[MAXLEN];
  char host[MAXLEN];
  char dn[MAXLEN];
  char passwd[MAXLEN];
  char search_filter[MAXLEN];				/* Base search_filter that gets copied to ldap_t */
  int ver;
  int scope;
  int port;
  unsigned int mode;
} conf_t;

/* extern the struct */
extern conf_t conf;					/* Main configuration struct */
#endif
