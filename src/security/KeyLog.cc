/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "acl/Tree.h"
#include "base/CharacterSet.h"
#include "base/CodeContext.h"
#include "ConfigOption.h"
#include "HttpReply.h"
#include "log/File.h"
#include "Parsing.h"
#include "sbuf/Stream.h"
#include "security/CommunicationSecrets.h"
#include "security/KeyLog.h"
#include "security/Session.h"
#include "SquidConfig.h"

Security::KeyLog::KeyLog(ConfigParser &parser)
{
    filename = xstrdup(parser.token("destination").c_str());
    parseOptions(parser, nullptr);
    aclList = parser.optionalAclList();

    // we use a built-in format that does not have/need a dedicated enum value
    assert(!type);
    assert(!logFormat);
    type = Log::Format::CLF_NONE;
}

void
Security::KeyLog::record(const CommunicationSecrets &secrets)
{
    assert(logfile);

    SBufStream os;

    // report current context to ease small-scale triage of logging problems
    os << "# " << logfile->sequence_number;
    if (const auto &ctx = CodeContext::Current())
        os << ' ' << *ctx;
    os << '\n';

    secrets.record(os);
    const auto buf = os.buf();

    logfileLineStart(logfile);
    logfilePrintf(logfile, SQUIDSBUFPH, SQUIDSBUFPRINT(buf));
    logfileLineEnd(logfile);
}

void
Security::KeyLog::dump(std::ostream &os) const
{
    os << filename;
    dumpOptions(os);
    if (aclList) {
        // TODO: Use Acl::dump() after fixing the XXX in dump_acl_list().
        for (const auto &acl: aclList->treeDump("if", &Acl::AllowOrDeny))
            os << ' ' << acl;
    }
}

void
Security::OpenLogs()
{
    if (Config.Log.tlsKeys)
        Config.Log.tlsKeys->open();
}

void
Security::RotateLogs()
{
    if (Config.Log.tlsKeys)
        Config.Log.tlsKeys->rotate();
}

void
Security::CloseLogs()
{
    if (Config.Log.tlsKeys)
        Config.Log.tlsKeys->close();
}

// GCC v6 requires "reopening" of the namespace here, instead of the usual
// definitions like Configuration::Component<T>::Parse():
// error: specialization of Configuration::Component... in different namespace
// TODO: Refactor to use the usual style after we stop GCC v6 support.
namespace Configuration {

template <>
Security::KeyLog *
Configuration::Component<Security::KeyLog*>::Parse(ConfigParser &parser)
{
    return new Security::KeyLog(parser);
}

template <>
void
Configuration::Component<Security::KeyLog*>::Print(std::ostream &os, Security::KeyLog* const & keyLog)
{
    assert(keyLog);
    keyLog->dump(os);
}

template <>
void
Configuration::Component<Security::KeyLog*>::Free(Security::KeyLog * const keyLog)
{
    delete keyLog;
}

} // namespace Configuration

