/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 00    Debug Routines */

#ifndef SQUID_DEBUG_H
#define SQUID_DEBUG_H

#include "base/Here.h"
// XXX should be mem/forward.h once it removes dependencies on typedefs.h
#include "mem/AllocatorProxy.h"

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
        bool forceAlert; ///< the current debugs() will be a syslog ALERT
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

    /// configures the active debugging context to write syslog ALERT
    static void ForceAlert();

    /// prefixes each grouped debugs() line after the first one in the group
    static std::ostream& Extra(std::ostream &os) { return os << "\n    "; }

private:
    static Context *Current; ///< deepest active context; nil outside debugs()
};

/// cache.log FILE or, as the last resort, stderr stream;
/// may be nil during static initialization and destruction!
FILE *DebugStream();
/// change-avoidance macro; new code should call DebugStream() instead
#define debug_log DebugStream()

/// start logging to stderr (instead of cache.log, if any)
void StopUsingDebugLog();

/// a hack for low-level file descriptor manipulations in ipcCreate()
void ResyncDebugLog(FILE *newDestination);

/* Debug stream
 *
 * Unit tests can enable full debugging to stderr for one
 * debug section; to enable this, #define ENABLE_DEBUG_SECTION to the
 * section number before any header
 */
#define debugs(SECTION, LEVEL, CONTENT) \
   do { \
        const int _dbg_level = (LEVEL); \
        if (Debug::Enabled((SECTION), _dbg_level)) { \
            std::ostream &_dbo = Debug::Start((SECTION), _dbg_level); \
            if (_dbg_level > DBG_IMPORTANT) { \
                _dbo << (SECTION) << ',' << _dbg_level << "| " \
                     << Here() << ": "; \
            } \
            _dbo << CONTENT; \
            Debug::Finish(); \
        } \
   } while (/*CONSTCOND*/ 0)

/// Does not change the stream being manipulated. Exists for its side effect:
/// In a debugs() context, forces the message to become a syslog ALERT.
/// Outside of debugs() context, has no effect and should not be used.
std::ostream& ForceAlert(std::ostream& s);

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
        level(-1), label_(label), data_(data), size_(size), useHex_(false), useGap_(true) {}

    /// limit data printing to at least the given debugging level
    Raw &minLevel(const int aLevel) { level = aLevel; return *this; }

    /// print data using two hex digits per byte (decoder: xxd -r -p)
    Raw &hex() { useHex_ = true; return *this; }

    Raw &gap(bool useGap = true) { useGap_ = useGap; return *this; }

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
    void printHex(std::ostream &os) const;

    const char *label_; ///< optional data name or ID; triggers size printing
    const char *data_; ///< raw data to be printed
    size_t size_; ///< data length
    bool useHex_; ///< whether hex() has been called
    bool useGap_; ///< whether to print leading space if label is missing
};

inline
std::ostream &operator <<(std::ostream &os, const Raw &raw)
{
    return raw.print(os);
}

/// debugs objects pointed by possibly nil pointers: label=object
template <class Pointer>
class RawPointerT {
public:
    RawPointerT(const char *aLabel, const Pointer &aPtr):
        label(aLabel), ptr(aPtr) {}
    const char *label; /// the name or description of the being-debugged object
    const Pointer &ptr; /// a possibly nil pointer to the being-debugged object
};

/// convenience wrapper for creating  RawPointerT<> objects
template <class Pointer>
inline RawPointerT<Pointer>
RawPointer(const char *label, const Pointer &ptr)
{
    return RawPointerT<Pointer>(label, ptr);
}

/// prints RawPointerT<>, dereferencing the raw pointer if possible
template <class Pointer>
inline std::ostream &
operator <<(std::ostream &os, const RawPointerT<Pointer> &pd)
{
    os << pd.label << '=';
    if (pd.ptr)
        return os << *pd.ptr;
    else
        return os << "[nil]";
}

/// std::ostream manipulator to print integers as hex numbers prefixed by 0x
template <class Integer>
class AsHex
{
public:
    explicit AsHex(const Integer n): raw(n) {}
    Integer raw; ///< the integer to print
};

template <class Integer>
inline std::ostream &
operator <<(std::ostream &os, const AsHex<Integer> number)
{
    const auto oldFlags = os.flags();
    os << std::hex << std::showbase << number.raw;
    os.setf(oldFlags);
    return os;
}

/// a helper to ease AsHex object creation
template <class Integer>
inline AsHex<Integer> asHex(const Integer n) { return AsHex<Integer>(n); }

#endif /* SQUID_DEBUG_H */

