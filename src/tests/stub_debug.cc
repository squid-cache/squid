/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
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

#define STUB_API "debug.cc"
#include "tests/STUB.h"

char *Debug::debugOptions;
char *Debug::cache_log= NULL;
int Debug::rotateNumber = 0;
int Debug::Levels[MAX_DEBUG_SECTIONS];
int Debug::override_X = 0;
int Debug::log_stderr = 1;
bool Debug::log_syslog = false;
void Debug::ForceAlert() STUB

void StopUsingDebugLog() STUB
void ResyncDebugLog(FILE *) STUB

FILE *
DebugStream()
{
    return stderr;
}

Ctx
ctx_enter(const char *)
{
    return -1;
}

void
ctx_exit(Ctx)
{}

void
_db_init(const char *, const char *)
{}

void
_db_set_syslog(const char *)
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
    if (1 < Debug::Level())
        return;

    vfprintf(stderr, format, args);
}

void
Debug::parseOptions(char const *)
{}

Debug::Context *Debug::Current = nullptr;

Debug::Context::Context(const int aSection, const int aLevel):
    level(aLevel),
    sectionLevel(Levels[aSection]),
    upper(Current)
{
    buf.setf(std::ios::fixed);
    buf.precision(2);
}

std::ostringstream &
Debug::Start(const int section, const int level)
{
    Current = new Context(section, level);
    return Current->buf;
}

void
Debug::Finish()
{
    if (Current) {
        _db_print("%s\n", Current->buf.str().c_str());
        delete Current;
        Current = nullptr;
    }
}

std::ostream&
ForceAlert(std::ostream& s)
{
    return s;
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
        if (data_)
            os.write(data_, size_);
        else
            os << "[null]";
    }

    return os;
}

