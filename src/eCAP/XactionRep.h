
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
    public BodyProducer, public BodyConsumer
{
public:
    XactionRep(Adaptation::Initiator *anInitiator, HttpMsg *virginHeader, HttpRequest *virginCause, const Adaptation::ServicePointer &service);
    virtual ~XactionRep();

	typedef libecap::shared_ptr<libecap::adapter::Xaction> AdapterXaction;
	void master(const AdapterXaction &aMaster); // establish a link

    // libecap::host::Xaction API
    virtual libecap::Message &virginMessage() ; // request or response
    virtual libecap::Message &virginCause() ; // request for the above response
    virtual void useVirgin() ;  // final answer: no adaptation
    virtual void cloneVirgin() ; // adapted message starts as virgin
    virtual void makeAdaptedRequest() ; // make fresh adapted request
    virtual void makeAdaptedResponse() ; // make fresh adapted response
    virtual libecap::Message &adaptedMessage() ; // request or response
    virtual void useAdapted() ; // final answer: adapted msg is ready
    virtual void useNone() ; // final answer: no answer

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
    virtual void swangSong();
    virtual const char *status() const;

protected:
    void terminateMaster();

private:
	AdapterXaction theMaster; // the actual adaptation xaction we represent

	Adaptation::Message theVirgin;
	Adaptation::Message theCause;
	Adaptation::Message theAnswer;
	MessageRep theVirginRep;
	MessageRep theCauseRep;
	MessageRep theAnswerRep;

	CBDATA_CLASS2(XactionRep);
};

} // namespace Ecap

#endif /* SQUID_ECAP_XACTION_REP_H */
