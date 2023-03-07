/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/ChecklistFiller.h"
#include "acl/FilledChecklist.h"
#include "MasterXaction.h"
#include "security/CommunicationSecrets.h"
#include "security/KeyLog.h"
#include "security/KeyLogger.h"
#include "security/Session.h"
#include "SquidConfig.h"

#include <ostream>

void
Security::KeyLogger::maybeLog(const Connection &sconn, const Acl::ChecklistFiller &caller)
{
    if (!shouldLog(caller)) {
        done_ = true; // do not try again
        return;
    }

    Security::CommunicationSecrets newSecrets(sconn);
    if (!secrets.learnNew(newSecrets)) // no new secrets extracted
        return; // will retry extracting secrets during the next checkpoint()

    // SSLKEYLOGFILE consumers probably discard incomplete record lines. To
    // avoid providing incomplete/unusable info in _each_ record, we always
    // record all the learned secrets, including any previously recorded ones.
    Config.Log.tlsKeys->record(secrets);

    // optimization: here, we assume learned secrets do not change
    if (secrets.gotAll())
        done_ = true;
}

bool
Security::KeyLogger::shouldLog(const Acl::ChecklistFiller &caller) const
{
    // First, always check preconditions that may change, becoming unmet/false

    if (!Config.Log.tlsKeys)
        return false; // default: admin does not want us to log (implicitly)

    if (!Config.Log.tlsKeys->canLog()) {
        debugs(33, 3, "no: problems with the logging module");
        return false;
    }

    if (done_) { // paranoid: we should not even be called w/o transaction
        debugs(33, 2, "BUG: caller problems or logged earlier");
        return false;
    }

    // Second, do the ACL-related checks (that are presumed to be stable)

    // We can keep wanted_ a boolean (instead of a tri-state) member because if
    // shouldLog() returns false, there will be no further shouldLog() calls.
    if (wanted_)
        return true; // was allowed to log earlier

    const auto acls = Config.Log.tlsKeys->aclList;
    if (!acls) {
        debugs(33, 7, "yes: no ACLs");
        wanted_ = true;
        return true;
    }

    ACLFilledChecklist checklist;
    caller.fillChecklist(checklist);
    if (!checklist.fastCheck(acls).allowed()) {
        debugs(33, 4, "no: admin does not want us to log (explicitly)");
        return false;
    }

    debugs(33, 5, "yes: ACLs matched");
    wanted_ = true;
    return true;
}

