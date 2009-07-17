#ifndef SQUID_ADAPTATION__ITERATOR_H
#define SQUID_ADAPTATION__ITERATOR_H

#include "adaptation/Initiator.h"
#include "adaptation/Initiate.h"
#include "adaptation/ServiceGroups.h"

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
public:
    Iterator(Adaptation::Initiator *anInitiator, 
        HttpMsg *virginHeader, HttpRequest *virginCause,
        const Adaptation::ServiceGroupPointer &aGroup);
    virtual ~Iterator();

    // Adaptation::Initiate: asynchronous communication with the initiator
    void noteInitiatorAborted();

    // Adaptation::Initiator: asynchronous communication with the current launcher
    virtual void noteAdaptationAnswer(HttpMsg *message);
    virtual void noteAdaptationQueryAbort(bool final);

protected:
    // Adaptation::Initiate API implementation
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();

    /// launches adaptation for the service selected by the plan
    void step();

    /// replace the current group and plan with service-proposed ones if needed
    bool updatePlan(bool adopt); // returns true iff the plan was replaced

    /// creates service filter for the current step
    ServiceFilter filter() const;

    ServiceGroupPointer theGroup; ///< the service group we are iterating
    ServicePlan thePlan; ///< which services to use and in what order
    HttpMsg *theMsg; ///< the message being adapted (virgin for each step)
    HttpRequest *theCause; ///< the cause of the original virgin message
    Adaptation::Initiate *theLauncher; ///< current transaction launcher
    int iterations; ///< number of steps initiated
    bool adapted; ///< whether the virgin message has been replaced

    CBDATA_CLASS2(Iterator);
};

} // namespace Adaptation


#endif /* SQUID_ADAPTATION__ITERATOR_H */
