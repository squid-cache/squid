/*
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
#ifndef SQUID_PACKER_H
#define SQUID_PACKER_H

/* see Packer.cc for description */
class Packer;

/* a common objPackInto interface; used by debugObj */
typedef void (*ObjPackMethod) (void *obj, Packer * p);

#if HAVE_STDIO_H
#include <stdio.h>
#endif
/* append/vprintf's for Packer */
typedef void (*append_f) (void *, const char *buf, int size);
typedef void (*vprintf_f) (void *, const char *fmt, va_list args);

class Packer
{

public:
    /* protected, use interface functions instead */
    append_f append;
    vprintf_f packer_vprintf;
    void *real_handler;		/* first parameter to real append and vprintf */
};

void packerClean(Packer * p);
void packerAppend(Packer * p, const char *buf, int size);
void packerPrintf(Packer * p, const char *fmt,...) PRINTF_FORMAT_ARG2;

#endif /* SQUID_PACKER_H */
