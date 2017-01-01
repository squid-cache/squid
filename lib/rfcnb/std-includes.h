/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 *
 * RFCNB Standard Includes
 *
 * Copyright (C) 1996, Richard Sharpe
 */

/*
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
 */

#ifndef _RFCNB_STD_INCLUDES_H
#define _RFCNB_STD_INCLUDES_H

/* RFCNB Standard includes ... */
/* One day we will conditionalize these on OS types ... */

#define BOOL int
typedef short int16;

#if HAVE_NETDB_H
#include <netdb.h>
#endif
#include <sys/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <signal.h>
#include <errno.h>
#include <unistd.h>

#define TRUE 1
#define FALSE 0

/* Pick up define for INADDR_NONE */

#ifndef INADDR_NONE
#define INADDR_NONE -1
#endif

#endif /* _RFCNB_STD_INCLUDES_H */

