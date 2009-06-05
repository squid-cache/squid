/*
 * $Id$
 *
 * DEBUG: section 0     Debug Routines
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
#ifndef SQUID_DEBUG_H
#define SQUID_DEBUG_H

#include "config.h"

#if HAVE_IOSTREAM
#include <iostream>
#endif

#undef assert
#if HAVE_SSTREAM
#include <sstream>
#endif
#if HAVE_IOMANIP
#include <iomanip>
#endif
#if defined(assert)
#undef assert
#endif

#if PURIFY
#define assert(EX) ((void)0)
#elif defined(NODEBUG)
#define assert(EX) ((void)0)
#elif STDC_HEADERS
#define assert(EX)  ((EX)?((void)0):xassert( # EX , __FILE__, __LINE__))
#else
#define assert(EX)  ((EX)?((void)0):xassert("EX", __FILE__, __LINE__))
#endif

/* context-based debugging, the actual type is subject to change */
typedef int Ctx;

/* defined debug section limits */
#define MAX_DEBUG_SECTIONS 100

/* defined names for Debug Levels */
#define DBG_CRITICAL	0	/**< critical messages always shown when they occur */
#define DBG_IMPORTANT	1	/**< important messages always shown when their section is being checked */
/* levels 2-8 are still being discussed amongst the developers */
#define DBG_DATA	9	/**< output is a large data dump only necessary for advanced debugging */

class Debug
{

public:
    static char *debugOptions;
    static char *cache_log;
    static int rotateNumber;
    static int Levels[MAX_DEBUG_SECTIONS];
    static int level;
    static int override_X;
    static int log_stderr;
    static bool log_syslog;

    static std::ostream &getDebugOut();
    static void finishDebug();
    static void parseOptions(char const *);

private:
    // Hack: replaces global ::xassert() to debug debugging assertions
    static void xassert(const char *msg, const char *file, int line);

    static std::ostringstream *CurrentDebug;
    static int TheDepth; // level of nested debugging calls
};

extern FILE *debug_log;

/* Debug stream */
#define debugs(SECTION, LEVEL, CONTENT) \
   do { \
        if ((Debug::level = (LEVEL)) <= Debug::Levels[SECTION]) { \
                Debug::getDebugOut() << CONTENT; \
                Debug::finishDebug(); \
        } \
   } while (/*CONSTCOND*/ 0)

/*
 * HERE is a macro that you can use like this:
 *
 * debugs(1,2, HERE << "some message");
 */
#define HERE __FILE__<<"("<<__LINE__<<") "<<__FUNCTION__<<": "

/*
 * MYNAME is for use at debug levels 0 and 1 where HERE is too messy.
 *
 * debugs(1,1, MYNAME << "WARNING: some message");
 */
#ifdef __PRETTY_FUNCTION__
#define MYNAME __PRETTY_FUNCTION__ << " "
#else
#define MYNAME __FUNCTION__ << " "
#endif

/* some uint8_t do not like streaming control-chars (values 0-31, 127+) */
inline std::ostream& operator <<(std::ostream &os, const uint8_t d)
{
    return (os << (int)d);
}

#endif /* SQUID_DEBUG_H */
