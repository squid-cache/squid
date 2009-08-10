#include "config.h"
#include "globals.h"
#include "TextException.h"
#include "SquidTime.h"
#include "HttpRequest.h" /* for alLogformatHasAdaptToken */
#include "adaptation/Config.h"
#include "adaptation/History.h"

/// impossible services value to identify unset theNextServices
const static char *TheNullServices = ",null,";

Adaptation::History::Entry::Entry(const String &sid, const timeval &when):
    service(sid), start(when), theRptm(-1), retried(false)
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


Adaptation::History::History(): theNextServices(TheNullServices) {
}

int Adaptation::History::recordXactStart(const String &sid, const timeval &when, bool retrying)
{
    if (retrying) {
        Must(!theEntries.empty()); // or there would be nothing to retry
        theEntries.back().retried = true;
    }
    theEntries.push_back(Adaptation::History::Entry(sid, when));
    return theEntries.size() - 1; // record position becomes history ID
}

void Adaptation::History::recordXactFinish(int hid)
{
    Must(0 <= hid && hid < static_cast<int>(theEntries.size()));
    theEntries[hid].stop();
}

void Adaptation::History::allLogString(const char *serviceId, String &s)
{
    s="";
    bool prevWasRetried = false;
    // XXX: Fix Vector<> so that we can use const_iterator here
    typedef Adaptation::History::Entries::iterator ECI;
    for (ECI i = theEntries.begin(); i != theEntries.end(); ++i) {
        // TODO: here and below, optimize service ID comparison?
        if (!serviceId || i->service == serviceId) {
            if (s.size() > 0) // not the first logged time, must delimit
                s.append(prevWasRetried ? "+" : ",");

            char buf[64];
            snprintf(buf, sizeof(buf), "%d", i->rptm());
            s.append(buf);

            // continue; we may have two identical services (e.g., for retries)
        }
        prevWasRetried = i->retried;
    }
}

void Adaptation::History::sumLogString(const char *serviceId, String &s)
{
    s="";
    int retriedRptm = 0; // sum of rptm times of retried transactions
    typedef Adaptation::History::Entries::iterator ECI;
    for (ECI i = theEntries.begin(); i != theEntries.end(); ++i) {
        if (i->retried) { // do not log retried xact but accumulate their time
            retriedRptm += i->rptm();
        } else
        if (!serviceId || i->service == serviceId) {
            if (s.size() > 0) // not the first logged time, must delimit
                s.append(",");

            char buf[64];
            snprintf(buf, sizeof(buf), "%d", retriedRptm + i->rptm());
            s.append(buf);

            // continue; we may have two identical services (e.g., for retries)
        }

        if (!i->retried)
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
