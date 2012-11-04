/*
 * DEBUG: section 93    eCAP Interface
 */

#ifndef SQUID_ECAP_XACTION_REP_H
#define SQUID_ECAP_XACTION_REP_H

#include "BodyPipe.h"
#include "adaptation/Initiate.h"
#include "adaptation/Message.h"
#include "adaptation/ecap/MessageRep.h"
#include "adaptation/ecap/ServiceRep.h"
#include <libecap/common/forward.h>
#include <libecap/common/memory.h>
#include <libecap/host/xaction.h>
#include <libecap/adapter/xaction.h>

namespace Adaptation
{
namespace Ecap
{

/* The eCAP xaction representative maintains information about a single eCAP
   xaction that Squid communicates with. One eCAP module may register many
   eCAP xactions. */
class XactionRep : public Adaptation::Initiate, public libecap::host::Xaction,
        public BodyConsumer, public BodyProducer
{
public:
    XactionRep(HttpMsg *virginHeader, HttpRequest *virginCause, const Adaptation::ServicePointer &service);
    virtual ~XactionRep();

    typedef libecap::shared_ptr<libecap::adapter::Xaction> AdapterXaction;
    void master(const AdapterXaction &aMaster); // establish a link

    // libecap::host::Xaction API
    virtual const libecap::Area option(const libecap::Name &name) const;
    virtual void visitEachOption(libecap::NamedValueVisitor &visitor) const;
    virtual libecap::Message &virgin();
    virtual const libecap::Message &cause();
    virtual libecap::Message &adapted();
    virtual void useVirgin();
    virtual void useAdapted(const libecap::shared_ptr<libecap::Message> &msg);
    virtual void blockVirgin();
    virtual void adaptationDelayed(const libecap::Delay &);
    virtual void adaptationAborted();
    virtual void vbDiscard();
    virtual void vbMake();
    virtual void vbStopMaking();
    virtual void vbMakeMore();
    virtual libecap::Area vbContent(libecap::size_type offset, libecap::size_type size);
    virtual void vbContentShift(libecap::size_type size);
    virtual void noteAbContentDone(bool atEnd);
    virtual void noteAbContentAvailable();

    // libecap::Callable API, via libecap::host::Xaction
    virtual bool callable() const;

    // BodyProducer API
    virtual void noteMoreBodySpaceAvailable(RefCount<BodyPipe> bp);
    virtual void noteBodyConsumerAborted(RefCount<BodyPipe> bp);

    // BodyConsumer API
    virtual void noteMoreBodyDataAvailable(RefCount<BodyPipe> bp);
    virtual void noteBodyProductionEnded(RefCount<BodyPipe> bp);
    virtual void noteBodyProducerAborted(RefCount<BodyPipe> bp);

    //  Initiate API
    virtual void noteInitiatorAborted();

    // AsyncJob API (via Initiate)
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();
    virtual const char *status() const;

protected:
    Service &service();

    Adaptation::Message &answer();

    void sinkVb(const char *reason);
    void preserveVb(const char *reason);
    void forgetVb(const char *reason);

    void moveAbContent();

    void updateHistory(HttpMsg *adapted);
    void terminateMaster();
    void scheduleStop(const char *reason);

    const libecap::Area clientIpValue() const;
    const libecap::Area usernameValue() const;
    const libecap::Area masterxSharedValue(const libecap::Name &name) const;
    /// Return the adaptation meta header value for the given header "name"
    const libecap::Area metaValue(const libecap::Name &name) const;
    /// Return the adaptation meta headers and their values
    void visitEachMetaHeader(libecap::NamedValueVisitor &visitor) const;

private:
    AdapterXaction theMaster; // the actual adaptation xaction we represent
    Adaptation::ServicePointer theService; ///< xaction's adaptation service

    MessageRep theVirginRep;
    MessageRep *theCauseRep;

    typedef libecap::shared_ptr<libecap::Message> MessagePtr;
    MessagePtr theAnswerRep;

    typedef enum { opUndecided, opOn, opComplete, opNever } OperationState;
    OperationState makingVb; //< delivering virgin body from pipe to adapter
    OperationState proxyingAb; // delivering adapted body from adapter to core
    int adaptHistoryId;        ///< adaptation history slot reservation
    bool vbProductionFinished; // whether there can be no more vb bytes
    bool abProductionFinished; // whether adapter has finished producing ab
    bool abProductionAtEnd;    // whether adapter produced a complete ab

    CBDATA_CLASS2(XactionRep);
};

} // namespace Ecap
} // namespace Adaptation

#endif /* SQUID_ECAP_XACTION_REP_H */
