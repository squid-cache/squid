
/*
 * $Id$
 *
 * DEBUG: section 3     Configuration File Parsing
 * AUTHOR: Harvest Derived
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#ifndef SQUID_PARSING_H
#define SQUID_PARSING_H

#include "squid.h"

extern double xatof(const char *token);
extern int xatoi(const char *token);
extern long xatol(const char *token);
extern unsigned short xatos(const char *token);

/**
 * Parse a 64-bit integer value.
 */
extern int64_t GetInteger64(void);

/**
 * Parses an integer value.
 * Uses a method that obeys hexadecimal 0xN syntax needed for certain bitmasks.
 */
extern int GetInteger(void);

extern u_short GetShort(void);

// on success, returns true and sets *p (if any) to the end of the integer
extern bool StringToInt(const char *str, int &result, const char **p, int base);
extern bool StringToInt64(const char *str, int64_t &result, const char **p, int base);

#endif /* SQUID_PARSING_H */
