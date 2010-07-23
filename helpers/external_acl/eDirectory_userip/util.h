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
 * util.h --
 *
 * Program utility functions.
 *
 */

#ifndef _HAVE_UTIL_H
#define _HAVE_UTIL_H
#ifndef _HAVE_MAIN_H
#include "main.h"
#endif
#include <stdarg.h>

/* util.c - Functions */
void debug(char *, const char *,...);
void debugx(const char *,...);
void printfx(const char *,...);
int SplitString(char *, size_t, char, char *, size_t);
#endif
