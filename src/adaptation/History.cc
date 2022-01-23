/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "adaptation/Config.h"
#include "adaptation/History.h"
#include "base/TextException.h"
#include "Debug.h"
#include "globals.h"
#include "SquidTime.h"

/// impossible services value to identify unset theNextServices
const static char *TheNullServices = ",null,";

Adaptation::History::Entry::Entry(const String &serviceId, const timeval &when):
    service(serviceId), start(when), theRptm(-1), retried(false)
{
}

Adaptation::History::Entry::Entry():
    start(current_time), theRptm(-1), retried(false)
{
}

void Adaptation::History::Entry::stop()
{
    // theRptm may already be set if the access log entry has already been made
    (void)rptm(); // will cache result in theRptm if not set already
}

int Adaptation::History::Entry::rptm()
{
    if (theRptm < 0)
        theRptm = tvSubMsec(start, current_time);
    return theRptm;
}

Adaptation::History::History():
    lastMeta(hoReply),
    allMeta(hoReply),
    theNextServices(TheNullServices)
{
}

int Adaptation::History::recordXactStart(const String &serviceId, const timeval &when, bool retrying)
{
    // the history will be empty on retries if it was enabled after the failure
    if (retrying && !theEntries.empty())
        theEntries.back().retried = true;

    theEntries.push_back(Adaptation::History::Entry(serviceId, when));
    return theEntries.size() - 1; // record position becomes history ID
}

void Adaptation::History::recordXactFinish(int hid)
{
    Must(0 <= hid && hid < static_cast<int>(theEntries.size()));
    theEntries[hid].stop();
}

void Adaptation::History::allLogString(const char *serviceId, SBuf &s)
{
    s.clear();
    bool prevWasRetried = false;
    for (auto &i : theEntries) {
        // TODO: here and below, optimize service ID comparison?
        if (!serviceId || i.service == serviceId) {
            if (!s.isEmpty()) // not the first logged time, must delimit
                s.append(prevWasRetried ? '+' : ',');
            s.appendf("%d", i.rptm());
            // continue; we may have two identical services (e.g., for retries)
        }
        prevWasRetried = i.retried;
    }
}

void Adaptation::History::sumLogString(const char *serviceId, SBuf &s)
{
    s.clear();
    int retriedRptm = 0; // sum of rptm times of retried transactions
    for (auto & i : theEntries) {
        if (i.retried) { // do not log retried xact but accumulate their time
            retriedRptm += i.rptm();
        } else if (!serviceId || i.service == serviceId) {
            if (!s.isEmpty()) // not the first logged time, must delimit
                s.append(',');
            s.appendf("%d", retriedRptm + i.rptm());
            // continue; we may have two identical services (e.g., for retries)
        }

        if (!i.retried)
            retriedRptm = 0;
    }

    // the last transaction is never retried or it would not be the last
    Must(!retriedRptm);
}

void Adaptation::History::updateXxRecord(const char *name, const String &value)
{
    theXxName = name;
    theXxValue = value;
}

bool Adaptation::History::getXxRecord(String &name, String &value) const
{
    if (theXxName.size() <= 0)
        return false;

    name = theXxName;
    value = theXxValue;
    return true;
}

void Adaptation::History::updateNextServices(const String &services)
{
    if (theNextServices != TheNullServices)
        debugs(93,3, HERE << "old services: " << theNextServices);
    debugs(93,3, HERE << "new services: " << services);
    Must(services != TheNullServices);
    theNextServices = services;
}

bool Adaptation::History::extractNextServices(String &value)
{
    if (theNextServices == TheNullServices)
        return false;

    value = theNextServices;
    theNextServices = TheNullServices; // prevents resetting the plan twice
    return true;
}

void Adaptation::History::recordMeta(const HttpHeader *lm)
{
    lastMeta.clean();
    lastMeta.update(lm);

    allMeta.update(lm);
    allMeta.compact();
}

void
Adaptation::History::recordAdaptationService(SBuf &srvId)
{
    theAdaptationServices.push_back(srvId);
}

void
Adaptation::History::setFutureServices(const DynamicGroupCfg &services)
{
    if (!theFutureServices.empty())
        debugs(93,3, HERE << "old future services: " << theFutureServices);
    debugs(93,3, HERE << "new future services: " << services);
    theFutureServices = services; // may be empty
}

bool Adaptation::History::extractFutureServices(DynamicGroupCfg &value)
{
    if (theFutureServices.empty())
        return false;

    value = theFutureServices;
    theFutureServices.clear();
    return true;
}

