/* 
   Unix SMB/CIFS implementation.

   Winbind daemon for ntdom nss module

   Copyright (C) Tim Potter 2000
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the
   Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA  02111-1307, USA.   
*/

#ifndef _WINBIND_NSS_CONFIG_H
#define _WINBIND_NSS_CONFIG_H

/* Include header files from data in config.h file */

#include <config.h>

#include <stdio.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_UNIXSOCKET
#include <sys/un.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <pwd.h>
#include "nsswitch/sys_nss.h"

/* Declarations for functions in winbind_nss.c
   needed in winbind_nss_solaris.c (solaris wrapper to nss) */

NSS_STATUS _nss_winbind_setpwent(void);
NSS_STATUS _nss_winbind_endpwent(void);
NSS_STATUS _nss_winbind_getpwent_r(struct passwd* result, char* buffer,
				   size_t buflen, int* errnop);
NSS_STATUS _nss_winbind_getpwuid_r(uid_t, struct passwd*, char* buffer,
				   size_t buflen, int* errnop);
NSS_STATUS _nss_winbind_getpwnam_r(const char* name, struct passwd* result,
				   char* buffer, size_t buflen, int* errnop);

NSS_STATUS _nss_winbind_setgrent(void);
NSS_STATUS _nss_winbind_endgrent(void);
NSS_STATUS _nss_winbind_getgrent_r(struct group* result, char* buffer,
				   size_t buflen, int* errnop);
NSS_STATUS _nss_winbind_getgrnam_r(const char *name,
				   struct group *result, char *buffer,
				   size_t buflen, int *errnop);
NSS_STATUS _nss_winbind_getgrgid_r(gid_t gid,
				   struct group *result, char *buffer,
				   size_t buflen, int *errnop);

/* I'm trying really hard not to include anything from smb.h with the
   result of some silly looking redeclaration of structures. */

#ifndef _PSTRING
#define _PSTRING
#define PSTRING_LEN 1024
#define FSTRING_LEN 256
typedef char pstring[PSTRING_LEN];
typedef char fstring[FSTRING_LEN];
#endif

#ifndef _BOOL
#define _BOOL			/* So we don't typedef BOOL again in vfs.h */
#define False (0)
#define True (1)
#define Auto (2)
typedef int BOOL;
#endif

#if !defined(uint32)
#if (SIZEOF_INT == 4)
#define uint32 unsigned int
#elif (SIZEOF_LONG == 4)
#define uint32 unsigned long
#elif (SIZEOF_SHORT == 4)
#define uint32 unsigned short
#endif
#endif

#if !defined(uint16)
#if (SIZEOF_SHORT == 4)
#define uint16 __ERROR___CANNOT_DETERMINE_TYPE_FOR_INT16;
#else /* SIZEOF_SHORT != 4 */
#define uint16 unsigned short
#endif /* SIZEOF_SHORT != 4 */
#endif

#ifndef uint8
#define uint8 unsigned char
#endif

/* zero a structure */
#ifndef ZERO_STRUCT
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))
#endif

/* zero a structure given a pointer to the structure */
#ifndef ZERO_STRUCTP
#define ZERO_STRUCTP(x) { if ((x) != NULL) memset((char *)(x), 0, sizeof(*(x))); }
#endif

/* Some systems (SCO) treat UNIX domain sockets as FIFOs */

#ifndef S_IFSOCK
#define S_IFSOCK S_IFIFO
#endif

#ifndef S_ISSOCK
#define S_ISSOCK(mode)  ((mode & S_IFSOCK) == S_IFSOCK)
#endif

#endif
