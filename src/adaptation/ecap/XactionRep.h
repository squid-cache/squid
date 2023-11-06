/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    eCAP Interface */

#ifndef SQUID_ECAP_XACTION_REP_H
#define SQUID_ECAP_XACTION_REP_H

#include "adaptation/ecap/MessageRep.h"
#include "adaptation/ecap/ServiceRep.h"
#include "adaptation/Initiate.h"
#include "adaptation/Message.h"
#include "BodyPipe.h"
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
    CBDATA_CHILD(XactionRep);

public:
    XactionRep(Http::Message *virginHeader, HttpRequest *virginCause, AccessLogEntry::Pointer &alp, const Adaptation::ServicePointer &service);
    ~XactionRep() override;

    typedef libecap::shared_ptr<libecap::adapter::Xaction> AdapterXaction;
    void master(const AdapterXaction &aMaster); // establish a link

    // libecap::host::Xaction API
    const libecap::Area option(const libecap::Name &name) const override;
    void visitEachOption(libecap::NamedValueVisitor &visitor) const override;
    libecap::Message &virgin() override;
    const libecap::Message &cause() override;
    libecap::Message &adapted() override;
    void useVirgin() override;
    void useAdapted(const libecap::shared_ptr<libecap::Message> &msg) override;
    void blockVirgin() override;
    void adaptationDelayed(const libecap::Delay &) override;
    void adaptationAborted() override;
    void resume() override;
    void vbDiscard() override;
    void vbMake() override;
    void vbStopMaking() override;
    void vbMakeMore() override;
    libecap::Area vbContent(libecap::size_type offset, libecap::size_type size) override;
    void vbContentShift(libecap::size_type size) override;
    void noteAbContentDone(bool atEnd) override;
    void noteAbContentAvailable() override;

    // BodyProducer API
    void noteMoreBodySpaceAvailable(RefCount<BodyPipe> bp) override;
    void noteBodyConsumerAborted(RefCount<BodyPipe> bp) override;

    // BodyConsumer API
    void noteMoreBodyDataAvailable(RefCount<BodyPipe> bp) override;
    void noteBodyProductionEnded(RefCount<BodyPipe> bp) override;
    void noteBodyProducerAborted(RefCount<BodyPipe> bp) override;

    // Initiate API
    void noteInitiatorAborted() override;

    // AsyncJob API (via Initiate)
    void start() override;
    bool doneAll() const override;
    void swanSong() override;
    const char *status() const override;

protected:
    Service &service();

    Adaptation::Message &answer();

    void sinkVb(const char *reason);
    void preserveVb(const char *reason);
    void forgetVb(const char *reason);

    void moveAbContent();

    void updateHistory(Http::Message *adapted);
    void terminateMaster();
    void scheduleStop(const char *reason);
    void updateSources(Http::Message *adapted);

    const libecap::Area clientIpValue() const;
    const libecap::Area usernameValue() const;
    const libecap::Area masterxSharedValue(const libecap::Name &name) const;
    /// Return the adaptation meta header value for the given header "name"
    const libecap::Area metaValue(const libecap::Name &name) const;
    /// Return the adaptation meta headers and their values
    void visitEachMetaHeader(libecap::NamedValueVisitor &visitor) const;

    void doResume();

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
    AccessLogEntry::Pointer al; ///< Master transaction AccessLogEntry
};

} // namespace Ecap
} // namespace Adaptation

#endif /* SQUID_ECAP_XACTION_REP_H */

