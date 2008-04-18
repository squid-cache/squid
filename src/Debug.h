
/*
 * $Id: Debug.h,v 1.13 2008/02/26 18:43:30 rousskov Exp $
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

#ifndef SQUID_DEBUG
#define SQUID_DEBUG

#include <iostream>
#undef assert
#include <sstream>
#include <iomanip>
#if defined assert
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

class Debug
{

public:
    static int Levels[MAX_DEBUG_SECTIONS];
    static int level;
    static std::ostream &getDebugOut();
    static void finishDebug();
    static void parseOptions(char const *);

private:
    // Hack: replaces global ::xassert() to debug debugging assertions
    static void xassert(const char *msg, const char *file, int line);
	
    static std::ostringstream *CurrentDebug;
    static int TheDepth; // level of nested debugging calls
};

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
 * debugs(1,1, HERE << "some message");
 */
#define HERE __FILE__<<"("<<__LINE__<<") "

/* AYJ: some uint8_t do not like streaming control-chars (values 0-31, 127+) */
inline std::ostream& operator <<(std::ostream &os, const uint8_t d) {
    return (os << (int)d);
}

#endif /* SQUID_DEBUG */
