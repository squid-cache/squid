/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 00    Debug Routines */

#include "squid.h"
#include "Debug.h"
#include "ipc/Kids.h"
#include "SquidTime.h"
#include "util.h"

#include <algorithm>

/* for shutting_down flag in xassert() */
#include "globals.h"

char *Debug::debugOptions = NULL;
int Debug::override_X = 0;
int Debug::log_stderr = -1;
bool Debug::log_syslog = false;
int Debug::Levels[MAX_DEBUG_SECTIONS];
char *Debug::cache_log = NULL;
int Debug::rotateNumber = -1;
static int Ctx_Lock = 0;
static const char *debugLogTime(void);
static const char *debugLogKid(void);
static void ctx_print(void);
#if HAVE_SYSLOG
#ifdef LOG_LOCAL4
static int syslog_facility = 0;
#endif
static void _db_print_syslog(const char *format, va_list args);
#endif
static void _db_print_stderr(const char *format, va_list args);
static void _db_print_file(const char *format, va_list args);

#if _SQUID_WINDOWS_
extern LPCRITICAL_SECTION dbg_mutex;
typedef BOOL (WINAPI * PFInitializeCriticalSectionAndSpinCount) (LPCRITICAL_SECTION, DWORD);
#endif

/// a (FILE*, file name) pair that uses stderr FILE as the last resort
class DebugFile
{
public:
    DebugFile() {}
    ~DebugFile() { clear(); }
    DebugFile(DebugFile &&) = delete; // no copying or moving of any kind

    /// switches to the new pair, absorbing FILE and duping the name
    void reset(FILE *newFile, const char *newName);

    /// go back to the initial state
    void clear() { reset(nullptr, nullptr); }

    /// logging stream; the only method that uses stderr as the last resort
    FILE *file() { return file_ ? file_ : stderr; }

    char *name = nullptr;

private:
    friend void ResyncDebugLog(FILE *newFile);

    FILE *file_ = nullptr; ///< opened "real" file or nil; never stderr
};

/// configured cache.log file or stderr
/// safe during static initialization, even if it has not been constructed yet
static DebugFile TheLog;

FILE *
DebugStream() {
    return TheLog.file();
}

void
StopUsingDebugLog()
{
    TheLog.clear();
}

void
ResyncDebugLog(FILE *newFile)
{
    TheLog.file_ = newFile;
}

void
DebugFile::reset(FILE *newFile, const char *newName)
{
    // callers must use nullptr instead of the used-as-the-last-resort stderr
    assert(newFile != stderr || !stderr);

    if (file_)
        fclose(file_);
    file_ = newFile; // may be nil

    xfree(name);
    name = newName ? xstrdup(newName) : nullptr;

    // all open files must have a name
    // all cleared files must not have a name
    assert(!file_ == !name);
}

void
_db_print(const char *format,...)
{
    char f[BUFSIZ];
    f[0]='\0';
    va_list args1;
    va_list args2;
    va_list args3;

#if _SQUID_WINDOWS_
    /* Multiple WIN32 threads may call this simultaneously */

    if (!dbg_mutex) {
        HMODULE krnl_lib = GetModuleHandle("Kernel32");
        PFInitializeCriticalSectionAndSpinCount InitializeCriticalSectionAndSpinCount = NULL;

        if (krnl_lib)
            InitializeCriticalSectionAndSpinCount =
                (PFInitializeCriticalSectionAndSpinCount) GetProcAddress(krnl_lib,
                        "InitializeCriticalSectionAndSpinCount");

        dbg_mutex = static_cast<CRITICAL_SECTION*>(xcalloc(1, sizeof(CRITICAL_SECTION)));

        if (InitializeCriticalSectionAndSpinCount) {
            /* let multiprocessor systems EnterCriticalSection() fast */

            if (!InitializeCriticalSectionAndSpinCount(dbg_mutex, 4000)) {
                if (debug_log) {
                    fprintf(debug_log, "FATAL: _db_print: can't initialize critical section\n");
                    fflush(debug_log);
                }

                fprintf(stderr, "FATAL: _db_print: can't initialize critical section\n");
                abort();
            } else
                InitializeCriticalSection(dbg_mutex);
        }
    }

    EnterCriticalSection(dbg_mutex);
#endif

    /* give a chance to context-based debugging to print current context */
    if (!Ctx_Lock)
        ctx_print();

    va_start(args1, format);
    va_start(args2, format);
    va_start(args3, format);

    snprintf(f, BUFSIZ, "%s%s| %s",
             debugLogTime(),
             debugLogKid(),
             format);

    _db_print_file(f, args1);
    _db_print_stderr(f, args2);

#if HAVE_SYSLOG
    _db_print_syslog(format, args3);
#endif

#if _SQUID_WINDOWS_
    LeaveCriticalSection(dbg_mutex);
#endif

    va_end(args1);
    va_end(args2);
    va_end(args3);
}

static void
_db_print_file(const char *format, va_list args)
{
    if (debug_log == NULL)
        return;

    /* give a chance to context-based debugging to print current context */
    if (!Ctx_Lock)
        ctx_print();

    vfprintf(debug_log, format, args);
    fflush(debug_log);
}

static void
_db_print_stderr(const char *format, va_list args)
{
    if (Debug::log_stderr < Debug::Level())
        return;

    if (debug_log == stderr)
        return;

    vfprintf(stderr, format, args);
}

#if HAVE_SYSLOG
static void
_db_print_syslog(const char *format, va_list args)
{
    /* level 0,1 go to syslog */

    if (Debug::Level() > 1)
        return;

    if (!Debug::log_syslog)
        return;

    char tmpbuf[BUFSIZ];
    tmpbuf[0] = '\0';

    vsnprintf(tmpbuf, BUFSIZ, format, args);

    tmpbuf[BUFSIZ - 1] = '\0';

    syslog(Debug::Level() == 0 ? LOG_WARNING : LOG_NOTICE, "%s", tmpbuf);
}
#endif /* HAVE_SYSLOG */

static void
debugArg(const char *arg)
{
    int s = 0;
    int l = 0;
    int i;

    if (!strncasecmp(arg, "rotate=", 7)) {
        arg += 7;
        Debug::rotateNumber = atoi(arg);
        return;
    } else if (!strncasecmp(arg, "ALL", 3)) {
        s = -1;
        arg += 4;
    } else {
        s = atoi(arg);
        while (*arg && *arg++ != ',');
    }

    l = atoi(arg);
    assert(s >= -1);

    if (s >= MAX_DEBUG_SECTIONS)
        s = MAX_DEBUG_SECTIONS-1;

    if (l < 0)
        l = 0;

    if (l > 10)
        l = 10;

    if (s >= 0) {
        Debug::Levels[s] = l;
        return;
    }

    for (i = 0; i < MAX_DEBUG_SECTIONS; ++i)
        Debug::Levels[i] = l;
}

static void
debugOpenLog(const char *logfile)
{
    if (logfile == NULL) {
        TheLog.clear();
        return;
    }

    // Bug 4423: ignore the stdio: logging module name if present
    const char *logfilename;
    if (strncmp(logfile, "stdio:",6) == 0)
        logfilename = logfile + 6;
    else
        logfilename = logfile;

    if (auto log = fopen(logfilename, "a+")) {
#if _SQUID_WINDOWS_
        setmode(fileno(log), O_TEXT);
#endif
        TheLog.reset(log, logfilename);
    } else {
        fprintf(stderr, "WARNING: Cannot write log file: %s\n", logfile);
        perror(logfile);
        fprintf(stderr, "         messages will be sent to 'stderr'.\n");
        fflush(stderr);
        TheLog.clear();
    }
}

#if HAVE_SYSLOG
#ifdef LOG_LOCAL4

static struct syslog_facility_name {
    const char *name;
    int facility;
}

syslog_facility_names[] = {

#ifdef LOG_AUTH
    {
        "auth", LOG_AUTH
    },
#endif
#ifdef LOG_AUTHPRIV
    {
        "authpriv", LOG_AUTHPRIV
    },
#endif
#ifdef LOG_CRON
    {
        "cron", LOG_CRON
    },
#endif
#ifdef LOG_DAEMON
    {
        "daemon", LOG_DAEMON
    },
#endif
#ifdef LOG_FTP
    {
        "ftp", LOG_FTP
    },
#endif
#ifdef LOG_KERN
    {
        "kern", LOG_KERN
    },
#endif
#ifdef LOG_LPR
    {
        "lpr", LOG_LPR
    },
#endif
#ifdef LOG_MAIL
    {
        "mail", LOG_MAIL
    },
#endif
#ifdef LOG_NEWS
    {
        "news", LOG_NEWS
    },
#endif
#ifdef LOG_SYSLOG
    {
        "syslog", LOG_SYSLOG
    },
#endif
#ifdef LOG_USER
    {
        "user", LOG_USER
    },
#endif
#ifdef LOG_UUCP
    {
        "uucp", LOG_UUCP
    },
#endif
#ifdef LOG_LOCAL0
    {
        "local0", LOG_LOCAL0
    },
#endif
#ifdef LOG_LOCAL1
    {
        "local1", LOG_LOCAL1
    },
#endif
#ifdef LOG_LOCAL2
    {
        "local2", LOG_LOCAL2
    },
#endif
#ifdef LOG_LOCAL3
    {
        "local3", LOG_LOCAL3
    },
#endif
#ifdef LOG_LOCAL4
    {
        "local4", LOG_LOCAL4
    },
#endif
#ifdef LOG_LOCAL5
    {
        "local5", LOG_LOCAL5
    },
#endif
#ifdef LOG_LOCAL6
    {
        "local6", LOG_LOCAL6
    },
#endif
#ifdef LOG_LOCAL7
    {
        "local7", LOG_LOCAL7
    },
#endif
    {
        NULL, 0
    }
};

#endif

void
_db_set_syslog(const char *facility)
{
    Debug::log_syslog = true;

#ifdef LOG_LOCAL4
#ifdef LOG_DAEMON

    syslog_facility = LOG_DAEMON;
#else

    syslog_facility = LOG_LOCAL4;
#endif /* LOG_DAEMON */

    if (facility) {

        struct syslog_facility_name *n;

        for (n = syslog_facility_names; n->name; ++n) {
            if (strcmp(n->name, facility) == 0) {
                syslog_facility = n->facility;
                return;
            }
        }

        fprintf(stderr, "unknown syslog facility '%s'\n", facility);
        exit(1);
    }

#else
    if (facility)
        fprintf(stderr, "syslog facility type not supported on your system\n");

#endif /* LOG_LOCAL4 */
}

#endif

void
Debug::parseOptions(char const *options)
{
    int i;
    char *p = NULL;
    char *s = NULL;

    if (override_X) {
        debugs(0, 9, "command-line -X overrides: " << options);
        return;
    }

    for (i = 0; i < MAX_DEBUG_SECTIONS; ++i)
        Debug::Levels[i] = 0;

    if (options) {
        p = xstrdup(options);

        for (s = strtok(p, w_space); s; s = strtok(NULL, w_space))
            debugArg(s);

        xfree(p);
    }
}

void
_db_init(const char *logfile, const char *options)
{
    Debug::parseOptions(options);

    debugOpenLog(logfile);

#if HAVE_SYSLOG && defined(LOG_LOCAL4)

    if (Debug::log_syslog)
        openlog(APP_SHORTNAME, LOG_PID | LOG_NDELAY | LOG_CONS, syslog_facility);

#endif /* HAVE_SYSLOG */

    /* Pre-Init TZ env, see bug #2656 */
    tzset();
}

void
_db_rotate_log(void)
{
    if (!TheLog.name)
        return;

#ifdef S_ISREG
    struct stat sb;
    if (stat(TheLog.name, &sb) == 0)
        if (S_ISREG(sb.st_mode) == 0)
            return;
#endif

    char from[MAXPATHLEN];
    from[0] = '\0';

    char to[MAXPATHLEN];
    to[0] = '\0';

    /*
     * NOTE: we cannot use xrename here without having it in a
     * separate file -- tools.c has too many dependencies to be
     * used everywhere debug.c is used.
     */
    /* Rotate numbers 0 through N up one */
    for (int i = Debug::rotateNumber; i > 1;) {
        --i;
        snprintf(from, MAXPATHLEN, "%s.%d", TheLog.name, i - 1);
        snprintf(to, MAXPATHLEN, "%s.%d", TheLog.name, i);
#if _SQUID_WINDOWS_
        remove
        (to);
#endif
        errno = 0;
        if (rename(from, to) == -1) {
            const auto saved_errno = errno;
            debugs(0, DBG_IMPORTANT, "log rotation failed: " << xstrerr(saved_errno));
        }
    }

    /* Rotate the current log to .0 */
    if (Debug::rotateNumber > 0) {
        // form file names before we may clear TheLog below
        snprintf(from, MAXPATHLEN, "%s", TheLog.name);
        snprintf(to, MAXPATHLEN, "%s.%d", TheLog.name, 0);

#if _SQUID_WINDOWS_
        errno = 0;
        if (remove(to) == -1) {
            const auto saved_errno = errno;
            debugs(0, DBG_IMPORTANT, "removal of log file " << to << " failed: " << xstrerr(saved_errno));
        }
        TheLog.clear(); // Windows cannot rename() open files
#endif
        errno = 0;
        if (rename(from, to) == -1) {
            const auto saved_errno = errno;
            debugs(0, DBG_IMPORTANT, "renaming file " << from << " to "
                   << to << "failed: " << xstrerr(saved_errno));
        }
    }

    // Close (if we have not already) and reopen the log because
    // it may have been renamed "manually" before HUP'ing us.
    debugOpenLog(Debug::cache_log);
}

static const char *
debugLogTime(void)
{

    time_t t = getCurrentTime();

    struct tm *tm;
    static char buf[128];
    static time_t last_t = 0;

    if (Debug::Level() > 1) {
        char buf2[128];
        tm = localtime(&t);
        strftime(buf2, 127, "%Y/%m/%d %H:%M:%S", tm);
        buf2[127] = '\0';
        snprintf(buf, 127, "%s.%03d", buf2, (int) current_time.tv_usec / 1000);
        last_t = t;
    } else if (t != last_t) {
        tm = localtime(&t);
        strftime(buf, 127, "%Y/%m/%d %H:%M:%S", tm);
        last_t = t;
    }

    buf[127] = '\0';
    return buf;
}

static const char *
debugLogKid(void)
{
    if (KidIdentifier != 0) {
        static char buf[16];
        if (!*buf) // optimization: fill only once after KidIdentifier is set
            snprintf(buf, sizeof(buf), " kid%d", KidIdentifier);
        return buf;
    }

    return "";
}

void
xassert(const char *msg, const char *file, int line)
{
    debugs(0, DBG_CRITICAL, "assertion failed: " << file << ":" << line << ": \"" << msg << "\"");

    if (!shutting_down)
        abort();
}

/*
 * Context-based Debugging
 *
 * Rationale
 * ---------
 *
 * When you have a long nested processing sequence, it is often impossible
 * for low level routines to know in what larger context they operate. If a
 * routine coredumps, one can restore the context using debugger trace.
 * However, in many case you do not want to coredump, but just want to report
 * a potential problem. A report maybe useless out of problem context.
 *
 * To solve this potential problem, use the following approach:
 *
 * int
 * top_level_foo(const char *url)
 * {
 *      // define current context
 *      // note: we stack but do not dup ctx descriptions!
 *      Ctx ctx = ctx_enter(url);
 *      ...
 *      // go down; middle_level_bar will eventually call bottom_level_boo
 *      middle_level_bar(method, protocol);
 *      ...
 *      // exit, clean after yourself
 *      ctx_exit(ctx);
 * }
 *
 * void
 * bottom_level_boo(int status, void *data)
 * {
 *      // detect exceptional condition, and simply report it, the context
 *      // information will be available somewhere close in the log file
 *      if (status == STRANGE_STATUS)
 *      debugs(13, 6, "DOS attack detected, data: " << data);
 *      ...
 * }
 *
 * Current implementation is extremely simple but still very handy. It has a
 * negligible overhead (descriptions are not duplicated).
 *
 * When the _first_ debug message for a given context is printed, it is
 * prepended with the current context description. Context is printed with
 * the same debugging level as the original message.
 *
 * Note that we do not print context every type you do ctx_enter(). This
 * approach would produce too many useless messages.  For the same reason, a
 * context description is printed at most _once_ even if you have 10
 * debugging messages within one context.
 *
 * Contexts can be nested, of course. You must use ctx_enter() to enter a
 * context (push it onto stack).  It is probably safe to exit several nested
 * contexts at _once_ by calling ctx_exit() at the top level (this will pop
 * all context till current one). However, as in any stack, you cannot start
 * in the middle.
 *
 * Analysis:
 * i)   locate debugging message,
 * ii)  locate current context by going _upstream_ in your log file,
 * iii) hack away.
 *
 *
 * To-Do:
 * -----
 *
 *       decide if we want to dup() descriptions (adds overhead) but allows to
 *       add printf()-style interface
 *
 * implementation:
 * ---------------
 *
 * descriptions for contexts over CTX_MAX_LEVEL limit are ignored, you probably
 * have a bug if your nesting goes that deep.
 */

#define CTX_MAX_LEVEL 255

/*
 * produce a warning when nesting reaches this level and then double
 * the level
 */
static int Ctx_Warn_Level = 32;
/* all descriptions has been printed up to this level */
static int Ctx_Reported_Level = -1;
/* descriptions are still valid or active up to this level */
static int Ctx_Valid_Level = -1;
/* current level, the number of nested ctx_enter() calls */
static int Ctx_Current_Level = -1;
/* saved descriptions (stack) */
static const char *Ctx_Descrs[CTX_MAX_LEVEL + 1];
/* "safe" get secription */
static const char *ctx_get_descr(Ctx ctx);

Ctx
ctx_enter(const char *descr)
{
    ++Ctx_Current_Level;

    if (Ctx_Current_Level <= CTX_MAX_LEVEL)
        Ctx_Descrs[Ctx_Current_Level] = descr;

    if (Ctx_Current_Level == Ctx_Warn_Level) {
        debugs(0, DBG_CRITICAL, "# ctx: suspiciously deep (" << Ctx_Warn_Level << ") nesting:");
        Ctx_Warn_Level *= 2;
    }

    return Ctx_Current_Level;
}

void
ctx_exit(Ctx ctx)
{
    assert(ctx >= 0);
    Ctx_Current_Level = (ctx >= 0) ? ctx - 1 : -1;

    if (Ctx_Valid_Level > Ctx_Current_Level)
        Ctx_Valid_Level = Ctx_Current_Level;
}

/*
 * the idea id to print each context description at most once but provide enough
 * info for deducing the current execution stack
 */
static void
ctx_print(void)
{
    /* lock so _db_print will not call us recursively */
    ++Ctx_Lock;
    /* ok, user saw [0,Ctx_Reported_Level] descriptions */
    /* first inform about entries popped since user saw them */

    if (Ctx_Valid_Level < Ctx_Reported_Level) {
        if (Ctx_Reported_Level != Ctx_Valid_Level + 1)
            _db_print("ctx: exit levels from %2d down to %2d\n",
                      Ctx_Reported_Level, Ctx_Valid_Level + 1);
        else
            _db_print("ctx: exit level %2d\n", Ctx_Reported_Level);

        Ctx_Reported_Level = Ctx_Valid_Level;
    }

    /* report new contexts that were pushed since last report */
    while (Ctx_Reported_Level < Ctx_Current_Level) {
        ++Ctx_Reported_Level;
        ++Ctx_Valid_Level;
        _db_print("ctx: enter level %2d: '%s'\n", Ctx_Reported_Level,
                  ctx_get_descr(Ctx_Reported_Level));
    }

    /* unlock */
    --Ctx_Lock;
}

/* checks for nulls and overflows */
static const char *
ctx_get_descr(Ctx ctx)
{
    if (ctx < 0 || ctx > CTX_MAX_LEVEL)
        return "<lost>";

    return Ctx_Descrs[ctx] ? Ctx_Descrs[ctx] : "<null>";
}

Debug::Context *Debug::Current = nullptr;

Debug::Context::Context(const int aSection, const int aLevel):
    level(aLevel),
    sectionLevel(Levels[aSection]),
    upper(Current)
{
    formatStream();
}

/// Optimization: avoids new Context creation for every debugs().
void
Debug::Context::rewind(const int aSection, const int aLevel)
{
    level = aLevel;
    sectionLevel = Levels[aSection];
    assert(upper == Current);

    buf.str(std::string());
    buf.clear();
    // debugs() users are supposed to preserve format, but
    // some do not, so we have to waste cycles resetting it for all.
    formatStream();
}

/// configures default formatting for the debugging stream
void
Debug::Context::formatStream()
{
    const static std::ostringstream cleanStream;
    buf.flags(cleanStream.flags() | std::ios::fixed);
    buf.width(cleanStream.width());
    buf.precision(2);
    buf.fill(' ');
    // If this is not enough, use copyfmt(cleanStream) which is ~10% slower.
}

std::ostringstream &
Debug::Start(const int section, const int level)
{
    Context *future = nullptr;

    // prepare future context
    if (Current) {
        // all reentrant debugs() calls get here; create a dedicated context
        future = new Context(section, level);
    } else {
        // Optimization: Nearly all debugs() calls get here; avoid allocations
        static Context *topContext = new Context(1, 1);
        topContext->rewind(section, level);
        future = topContext;
    }

    Current = future;

    return future->buf;
}

void
Debug::Finish()
{
    // TODO: Optimize to remove at least one extra copy.
    _db_print("%s\n", Current->buf.str().c_str());

    Context *past = Current;
    Current = past->upper;
    if (Current)
        delete past;
    // else it was a static topContext from Debug::Start()
}

size_t
BuildPrefixInit()
{
    // XXX: This must be kept in sync with the actual debug.cc location
    const char *ThisFileNameTail = "src/debug.cc";

    const char *file=__FILE__;

    // Disable heuristic if it does not work.
    if (!strstr(file, ThisFileNameTail))
        return 0;

    return strlen(file)-strlen(ThisFileNameTail);
}

const char*
SkipBuildPrefix(const char* path)
{
    static const size_t BuildPrefixLength = BuildPrefixInit();

    return path+BuildPrefixLength;
}

/// print data bytes using hex notation
void
Raw::printHex(std::ostream &os) const
{
    const auto savedFill = os.fill('0');
    const auto savedFlags = os.flags(); // std::ios_base::fmtflags
    os << std::hex;
    std::for_each(data_, data_ + size_,
    [&os](const char &c) { os << std::setw(2) << static_cast<uint8_t>(c); });
    os.flags(savedFlags);
    os.fill(savedFill);
}

std::ostream &
Raw::print(std::ostream &os) const
{
    if (label_)
        os << ' ' << label_ << '[' << size_ << ']';

    if (!size_)
        return os;

    // finalize debugging level if no level was set explicitly via minLevel()
    const int finalLevel = (level >= 0) ? level :
                           (size_ > 40 ? DBG_DATA : Debug::SectionLevel());
    if (finalLevel <= Debug::SectionLevel()) {
        os << (label_ ? '=' : ' ');
        if (data_) {
            if (useHex_)
                printHex(os);
            else
                os.write(data_, size_);
        } else {
            os << "[null]";
        }
    }

    return os;
}

