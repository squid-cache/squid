/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * A stub implementation of the Debug.h API.
 * For use by test binaries which do not need the full context debugging
 *
 * Note: it doesn't use the STUB API as the functions defined here must
 * not abort the unit test.
 */
#include "squid.h"
#include "Debug.h"

FILE *debug_log = NULL;
int Debug::TheDepth = 0;

char *Debug::debugOptions;
char *Debug::cache_log= NULL;
int Debug::rotateNumber = 0;
int Debug::Levels[MAX_DEBUG_SECTIONS];
int Debug::level;
int Debug::sectionLevel;
int Debug::override_X = 0;
int Debug::log_stderr = 1;
bool Debug::log_syslog = false;

Ctx
ctx_enter(const char *descr)
{
    return -1;
}

void
ctx_exit(Ctx ctx)
{
}

void
_db_init(const char *logfile, const char *options)
{}

void
_db_set_syslog(const char *facility)
{}

void
_db_rotate_log(void)
{}

static void
_db_print_stderr(const char *format, va_list args);

void
_db_print(const char *format,...)
{
    static char f[BUFSIZ];
    va_list args1;
    va_list args2;
    va_list args3;

    va_start(args1, format);
    va_start(args2, format);
    va_start(args3, format);

    snprintf(f, BUFSIZ, "%s| %s",
             "stub time", //debugLogTime(squid_curtime),
             format);

    _db_print_stderr(f, args2);

    va_end(args1);
    va_end(args2);
    va_end(args3);
}

static void
_db_print_stderr(const char *format, va_list args)
{
    if (1 < Debug::level)
        return;

    vfprintf(stderr, format, args);
}

Debug::OutStream *Debug::CurrentDebug(NULL);

std::ostream &
Debug::getDebugOut()
{
    assert(TheDepth >= 0);
    ++TheDepth;
    if (TheDepth > 1) {
        assert(CurrentDebug);
        *CurrentDebug << std::endl << "reentrant debuging " << TheDepth << "-{";
    } else {
        assert(!CurrentDebug);
        CurrentDebug = new Debug::OutStream;
        // set default formatting flags
        CurrentDebug->setf(std::ios::fixed);
        CurrentDebug->precision(2);
    }
    return *CurrentDebug;
}

void
Debug::parseOptions(char const *)
{
    return;
}

void
Debug::finishDebug()
{
    assert(TheDepth >= 0);
    assert(CurrentDebug);
    if (TheDepth > 1) {
        *CurrentDebug << "}-" << TheDepth << std::endl;
    } else {
        assert(TheDepth == 1);
        _db_print("%s\n", CurrentDebug->str().c_str());
        delete CurrentDebug;
        CurrentDebug = NULL;
    }
    --TheDepth;
}

void
Debug::xassert(const char *msg, const char *file, int line)
{

    if (CurrentDebug) {
        *CurrentDebug << "assertion failed: " << file << ":" << line <<
                      ": \"" << msg << "\"";
    }
    abort();
}

const char*
SkipBuildPrefix(const char* path)
{
    return path;
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
                           (size_ > 40 ? DBG_DATA : Debug::sectionLevel);
    if (finalLevel <= Debug::sectionLevel) {
        os << (label_ ? '=' : ' ');
        os.write(data_, size_);
    }

    return os;
}

