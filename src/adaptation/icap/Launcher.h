/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ICAPLAUNCHER_H
#define SQUID_ICAPLAUNCHER_H

#include "adaptation/icap/ServiceRep.h"
#include "adaptation/Initiate.h"
#include "adaptation/Initiator.h"

/*
 * The ICAP Launcher starts an ICAP transaction. If the transaction fails
 * due to what looks like a persistent connection race condition, the launcher
 * starts a new ICAP transaction using a freshly opened connection.
 *
 * ICAPLauncher and one or more ICAP transactions initiated by it form an
 * ICAP "query".
 *
 * An ICAP Initiator deals with the ICAP Launcher and not an individual ICAP
 * transaction because the latter may disappear and be replaced by another
 * transaction.
 *
 * Specific ICAP launchers implement the createXaction() method to create
 * REQMOD, RESPMOD, or OPTIONS transaction from initiator-supplied data.
 *
 * TODO: This class might be the right place to initiate ICAP ACL checks or
 * implement more sophisticated ICAP transaction handling like chaining of
 * ICAP transactions.
 */

namespace Adaptation
{
namespace Icap
{

class Xaction;
class XactAbortInfo;

// Note: Initiate must be the first parent for cbdata to work. We use
// a temporary InitaitorHolder/toCbdata hacks and do not call cbdata
// operations on the initiator directly.
class Launcher: public Adaptation::Initiate, public Adaptation::Initiator
{
public:
    Launcher(const char *aTypeName, Adaptation::ServicePointer &aService);
    virtual ~Launcher();

    // Adaptation::Initiate: asynchronous communication with the initiator
    void noteInitiatorAborted();

    // Adaptation::Initiator: asynchronous communication with the current transaction
    virtual void noteAdaptationAnswer(const Answer &answer);
    virtual void noteXactAbort(XactAbortInfo info);

private:
    bool canRetry(XactAbortInfo &info) const; //< true if can retry in the case of persistent connection failures
    bool canRepeat(XactAbortInfo &info) const; //< true if can repeat in the case of no or unsatisfactory response

protected:
    // Adaptation::Initiate API implementation
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();

    // creates the right ICAP transaction using stored configuration params
    virtual Xaction *createXaction() = 0;

    void launchXaction(const char *xkind);

    Adaptation::ServicePointer theService; ///< ICAP service for all launches
    CbcPointer<Initiate> theXaction; ///< current ICAP transaction
    int theLaunches; // the number of transaction launches
};

/// helper class to pass information about aborted ICAP requests to
/// the Adaptation::Icap::Launcher class
class XactAbortInfo
{
public:
    XactAbortInfo(HttpRequest *anIcapRequest, HttpReply *anIcapReply,
                  bool beRetriable, bool beRepeatable);
    XactAbortInfo(const XactAbortInfo &);
    ~XactAbortInfo();

    std::ostream &print(std::ostream &os) const {
        return os << isRetriable << ',' << isRepeatable;
    }

    HttpRequest *icapRequest;
    HttpReply *icapReply;
    bool isRetriable;
    bool isRepeatable;

private:
    XactAbortInfo &operator =(const XactAbortInfo &); // undefined
};

inline
std::ostream &
operator <<(std::ostream &os, const XactAbortInfo &xai)
{
    return xai.print(os);
}

} // namespace Icap
} // namespace Adaptation

#endif /* SQUID_ICAPLAUNCHER_H */

