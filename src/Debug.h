/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 00    Debug Routines */

#ifndef SQUID_DEBUG_H
#define SQUID_DEBUG_H

#include <iostream>
#undef assert
#include <sstream>
#include <iomanip>
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
#define DBG_CRITICAL    0   /**< critical messages always shown when they occur */
#define DBG_IMPORTANT   1   /**< important messages always shown when their section is being checked */
/* levels 2-8 are still being discussed amongst the developers */
#define DBG_DATA    9   /**< output is a large data dump only necessary for advanced debugging */

#define DBG_PARSE_NOTE(x) (opt_parse_cfg_only?0:(x)) /**< output is always to be displayed on '-k parse' but at level-x normally. */

class Debug
{

public:
    /// meta-information for debugs() or a similar debugging call
    class Context
    {
    public:
        Context(const int aSectionLevel, const int aLevel);

        int level; ///< minimum debugging level required by the debugs() call
        int sectionLevel; ///< maximum debugging level allowed during the call

    private:
        friend class Debug;
        void rewind(const int aSection, const int aLevel);
        void formatStream();
        Context *upper; ///< previous or parent record in nested debugging calls
        std::ostringstream buf; ///< debugs() output sink
    };

    /// whether debugging the given section and the given level produces output
    static bool Enabled(const int section, const int level)
    {
        return level <= Debug::Levels[section];
    }

    static char *debugOptions;
    static char *cache_log;
    static int rotateNumber;
    static int Levels[MAX_DEBUG_SECTIONS];
    static int override_X;
    static int log_stderr;
    static bool log_syslog;

    static void parseOptions(char const *);

    /// minimum level required by the current debugs() call
    static int Level() { return Current ? Current->level : 1; }
    /// maximum level currently allowed
    static int SectionLevel() { return Current ? Current->sectionLevel : 1; }

    /// opens debugging context and returns output buffer
    static std::ostringstream &Start(const int section, const int level);
    /// logs output buffer created in Start() and closes debugging context
    static void Finish();

private:
    static Context *Current; ///< deepest active context; nil outside debugs()
};

extern FILE *debug_log;

size_t BuildPrefixInit();
const char * SkipBuildPrefix(const char* path);

/* Debug stream */
#define debugs(SECTION, LEVEL, CONTENT) \
   do { \
        const int _dbg_level = (LEVEL); \
        if (Debug::Enabled((SECTION), _dbg_level)) { \
            std::ostream &_dbo = Debug::Start((SECTION), _dbg_level); \
            if (_dbg_level > DBG_IMPORTANT) { \
                _dbo << (SECTION) << ',' << _dbg_level << "| " \
                     << SkipBuildPrefix(__FILE__)<<"("<<__LINE__<<") "<<__FUNCTION__<<": "; \
            } \
            _dbo << CONTENT; \
            Debug::Finish(); \
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

