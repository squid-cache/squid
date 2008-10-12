/* RFCNB Standard includes ... */
/*
 *
 * RFCNB Standard Includes
 *
 * Copyright (C) 1996, Richard Sharpe
 */
/* One day we will conditionalize these on OS types ... */

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

/* the types are provided by squid's configure preocess */
#include "config.h"
#define BOOL int16_t
#define int16 int16_t

#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#define TRUE 1
#define FALSE 0

/* Pick up define for INADDR_NONE */

#ifndef INADDR_NONE
#define INADDR_NONE -1
#endif
