
/*
 * $Id: test_tools.cc,v 1.3 2003/07/08 23:01:47 robertc Exp $
 *
 * AUTHOR: Robert Collins
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
 * Copyright (c) 2003 Robert Collins <robertc@squid-cache.org>
 */

#define _SQUID_EXTERNNEW_
#include "squid.h"
#include <iostream>
#include <sstream>

void
xassert(const char *msg, const char *file, int line)
{
    std::cout << "Assertion failed: (" << msg << ") at " << file << ":" << line << std::endl;
    exit (1);
}
time_t squid_curtime = 0;

int Debug::Levels[MAX_DEBUG_SECTIONS];
int Debug::level;

static void
_db_print_stderr(const char *format, va_list args);

void
#if STDC_HEADERS
_db_print(const char *format,...)
{
#else
_db_print(va_alist)
va_dcl
{
    const char *format = NULL;
#endif

    LOCAL_ARRAY(char, f, BUFSIZ);
    va_list args1;
#if STDC_HEADERS

    va_list args2;
    va_list args3;
#else
#define args2 args1
#define args3 args1
#endif

#if STDC_HEADERS

    va_start(args1, format);

    va_start(args2, format);

    va_start(args3, format);

#else

    format = va_arg(args1, const char *);

#endif

    snprintf(f, BUFSIZ, "%s| %s",
             "stub time", //debugLogTime(squid_curtime),
             format);

    _db_print_stderr(f, args2);

    va_end(args1);

#if STDC_HEADERS

    va_end(args2);

    va_end(args3);

#endif
}

static void
_db_print_stderr(const char *format, va_list args) {
    /* FIXME? */
   // if (opt_debug_stderr < Debug::level)
   if (1 < Debug::level)
        return;

    vfprintf(stderr, format, args);
}

void
fatal(const char *message) {
    debug (0,0) ("Fatal: %s",message);
    exit (1);
}

std::ostream &
Debug::getDebugOut()
{
    assert (CurrentDebug == NULL);
    CurrentDebug = new std::ostringstream();
    return *CurrentDebug;
}

void
Debug::finishDebug()
{
    _db_print("%s\n", CurrentDebug->str().c_str());
    delete CurrentDebug;
    CurrentDebug = NULL;
}

std::ostringstream *Debug::CurrentDebug (NULL);
