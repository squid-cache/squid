/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
#include "debug/Stream.h"

#define STUB_API "debug/libdebug.la"
#include "tests/STUB.h"

char *Debug::debugOptions;
char *Debug::cache_log= nullptr;
int Debug::rotateNumber = 0;
int Debug::Levels[MAX_DEBUG_SECTIONS];
int Debug::override_X = 0;
bool Debug::log_syslog = false;
void Debug::ForceAlert() STUB

void ResyncDebugLog(FILE *) STUB

FILE *
DebugStream()
{
    return stderr;
}

void
_db_rotate_log(void)
{}

void
Debug::LogMessage(const Context &context)
{
    if (context.level > DBG_IMPORTANT)
        return;

    if (!stderr)
        return;

    fprintf(stderr, "%s| %s\n",
            "stub time", // debugLogTime(current_time),
            context.buf.str().c_str());
}

bool Debug::StderrEnabled() STUB_RETVAL(false)
void Debug::PrepareToDie() STUB

void
Debug::parseOptions(char const *)
{}

Debug::Context *Debug::Current = nullptr;

Debug::Context::Context(const int aSection, const int aLevel):
    section(aSection),
    level(aLevel),
    sectionLevel(Levels[aSection]),
    upper(Current),
    forceAlert(false)
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
        LogMessage(*Current);
        delete Current;
        Current = nullptr;
    }
}

std::ostream&
ForceAlert(std::ostream& s)
{
    return s;
}

