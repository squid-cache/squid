
/*
 * $Id$
 */

#ifndef SQUID_ECAP_XACTION_REP_H
#define SQUID_ECAP_XACTION_REP_H

#include "BodyPipe.h"
#include "adaptation/Initiate.h"
#include "adaptation/Service.h"
#include "adaptation/Message.h"
#include "eCAP/MessageRep.h"
#include <libecap/common/forward.h>
#include <libecap/common/memory.h>
#include <libecap/host/xaction.h>
#include <libecap/adapter/xaction.h>

namespace Ecap {

/* The eCAP xaction representative maintains information about a single eCAP
   xaction that Squid communicates with. One eCAP module may register many 
   eCAP xactions. */
class XactionRep : public Adaptation::Initiate, public libecap::host::Xaction,
    public BodyConsumer, public BodyProducer
{
public:
    XactionRep(Adaptation::Initiator *anInitiator, HttpMsg *virginHeader, HttpRequest *virginCause, const Adaptation::ServicePointer &service);
    virtual ~XactionRep();

	typedef libecap::shared_ptr<libecap::adapter::Xaction> AdapterXaction;
	void master(const AdapterXaction &aMaster); // establish a link

    // libecap::host::Xaction API
    virtual libecap::Message &virgin();
    virtual const libecap::Message &cause();
    virtual libecap::Message &adapted();
    virtual void useVirgin();
    virtual void useAdapted(const libecap::shared_ptr<libecap::Message> &msg);
    virtual void adaptationDelayed(const libecap::Delay &);
    virtual void adaptationAborted();
    virtual void adapterWontConsume();
    virtual void adapterWillConsume();
    virtual void adapterDoneConsuming();
    virtual void consumeVirgin(size_type n);
    virtual void pauseVirginProduction();
    virtual void resumeVirginProduction();
    virtual void setAdaptedBodySize(const libecap::BodySize &size);
    virtual void appendAdapted(const libecap::Area &area);
    virtual void noteAdaptedBodyEnd();

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
    Adaptation::Message &answer();

    bool sendingVirgin() const;
    void dropVirgin(const char *reason);
    bool doneWithAdapted() const;

    void terminateMaster();
    void scheduleStop(const char *reason);

private:
	AdapterXaction theMaster; // the actual adaptation xaction we represent

	MessageRep theVirginRep;
	MessageRep *theCauseRep;

	typedef libecap::shared_ptr<libecap::Message> MessagePtr;
	MessagePtr theAnswerRep;

	CBDATA_CLASS2(XactionRep);
};

} // namespace Ecap

#endif /* SQUID_ECAP_XACTION_REP_H */
