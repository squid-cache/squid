/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ADAPTATION_ITERATOR_H
#define SQUID_SRC_ADAPTATION_ITERATOR_H

#include "adaptation/Initiate.h"
#include "adaptation/Initiator.h"
#include "adaptation/ServiceGroups.h"
#include "http/forward.h"
#include "log/forward.h"

namespace Adaptation
{

/* Iterator is started by client or server Initiators. It iterates services
   in a given group, starting transaction launcher for each service, according
   to the service plan. Service plans support adaptation sets and chains.

   Note: Initiate must be the first parent for cbdata to work. We use
   a temporary InitiatorHolder/toCbdata hacks and do not call cbdata
   operations on the initiator directly.
*/

/// iterates services in ServiceGroup, starting adaptation launchers
class Iterator: public Initiate, public Initiator
{
    CBDATA_CHILD(Iterator);

public:
    Iterator(Http::Message *virginHeader, HttpRequest *virginCause,
             const AccessLogEntryPointer &,
             const Adaptation::ServiceGroupPointer &aGroup);
    ~Iterator() override;

    // Adaptation::Initiate: asynchronous communication with the initiator
    void noteInitiatorAborted() override;

    // Adaptation::Initiator: asynchronous communication with the current launcher
    void noteAdaptationAnswer(const Answer &answer) override;

protected:
    // Adaptation::Initiate API implementation
    void start() override;
    bool doneAll() const override;
    void swanSong() override;

    /// launches adaptation for the service selected by the plan
    void step();

    /// replace the current group and plan with service-proposed ones if needed
    bool updatePlan(bool adopt); // returns true iff the plan was replaced

    /// creates service filter for the current step
    ServiceFilter filter() const;

    void handleAdaptedHeader(Http::Message *msg);
    void handleAdaptationBlock(const Answer &answer);
    void handleAdaptationError(bool final);

    ServiceGroupPointer theGroup; ///< the service group we are iterating
    ServicePlan thePlan; ///< which services to use and in what order
    Http::Message *theMsg; ///< the message being adapted (virgin for each step)
    HttpRequest *theCause; ///< the cause of the original virgin message
    AccessLogEntryPointer al; ///< info for the future access.log entry
    CbcPointer<Adaptation::Initiate> theLauncher; ///< current transaction launcher
    int iterations; ///< number of steps initiated
    bool adapted; ///< whether the virgin message has been replaced
};

} // namespace Adaptation

#endif /* SQUID_SRC_ADAPTATION_ITERATOR_H */

