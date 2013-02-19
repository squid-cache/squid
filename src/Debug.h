/*
 * DEBUG: section 00    Debug Routines
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
Ctx ctx_enter(const char *descr);
void ctx_exit(Ctx ctx);

/* defined debug section limits */
#define MAX_DEBUG_SECTIONS 100

/* defined names for Debug Levels */
#define DBG_CRITICAL	0	/**< critical messages always shown when they occur */
#define DBG_IMPORTANT	1	/**< important messages always shown when their section is being checked */
/* levels 2-8 are still being discussed amongst the developers */
#define DBG_DATA	9	/**< output is a large data dump only necessary for advanced debugging */

#define DBG_PARSE_NOTE(x) (opt_parse_cfg_only?0:(x)) /**< output is always to be displayed on '-k parse' but at level-x normally. */

class Debug
{

public:
    static char *debugOptions;
    static char *cache_log;
    static int rotateNumber;
    static int Levels[MAX_DEBUG_SECTIONS];
    static int level; ///< minimum debugging level required by debugs() call
    static int sectionLevel; ///< maximum debugging level allowed now
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

size_t BuildPrefixInit();
const char * SkipBuildPrefix(const char* path);

/* Debug stream */
#define debugs(SECTION, LEVEL, CONTENT) \
   do { \
        if ((Debug::level = (LEVEL)) <= Debug::Levels[SECTION]) { \
            Debug::sectionLevel = Debug::Levels[SECTION]; \
            std::ostream &_dbo=Debug::getDebugOut(); \
            if (Debug::level > DBG_IMPORTANT) \
                _dbo << SkipBuildPrefix(__FILE__)<<"("<<__LINE__<<") "<<__FUNCTION__<<": "; \
            _dbo << CONTENT; \
            Debug::finishDebug(); \
        } \
   } while (/*CONSTCOND*/ 0)

/** stream manipulator which does nothing.
 * \deprecated Do not add to new code, and remove when editing old code
 *
 * Its purpose is to inactivate calls made following previous debugs()
 * guidelines such as
 * debugs(1,2, HERE << "some message");
 *
 * His former objective is now absorbed in the debugs call itself
 */
inline std::ostream&
HERE(std::ostream& s)
{
    return s;
}

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

/* Legacy debug style. Still used in some places. needs to die... */
#define do_debug(SECTION, LEVEL)   ((Debug::level = (LEVEL)) <= Debug::Levels[SECTION])
#define old_debug(SECTION, LEVEL)  if do_debug((SECTION), (LEVEL)) _db_print

/* Legacy debug function definitions */
void _db_init(const char *logfile, const char *options);
void _db_print(const char *,...) PRINTF_FORMAT_ARG1;
void _db_set_syslog(const char *facility);
void _db_rotate_log(void);

/// Prints raw and/or non-terminated data safely, efficiently, and beautifully.
/// Allows raw data debugging in debugs() statements with low debugging levels
/// by printing only if higher section debugging levels are configured:
///   debugs(11, DBG_IMPORTANT, "always printed" << Raw(may be printed...));
class Raw
{
public:
    Raw(const char *label, const char *data, const size_t size):
            level(-1), label_(label), data_(data), size_(size) {}

    /// limit data printing to at least the given debugging level
    Raw &minLevel(const int aLevel) { level = aLevel; return *this; }

    /// If debugging is prohibited by the current debugs() or section level,
    /// prints nothing. Otherwise, dumps data using one of these formats:
    ///   " label[size]=data" if label was set and data size is positive
    ///   " label[0]" if label was set and data size is zero
    ///   " data" if label was not set and data size is positive
    ///   "" (i.e., prints nothing) if label was not set and data size is zero
    std::ostream &print(std::ostream &os) const;

    /// Minimum section debugging level necessary for printing. By default,
    /// small strings are always printed while large strings are only printed
    /// if DBG_DATA debugging level is enabled.
    int level;

private:
    const char *label_; ///< optional data name or ID; triggers size printing
    const char *data_; ///< raw data to be printed
    size_t size_; ///< data length
};

inline
std::ostream &operator <<(std::ostream &os, const Raw &raw)
{
    return raw.print(os);
}

#endif /* SQUID_DEBUG_H */
