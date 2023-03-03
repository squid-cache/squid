/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/AsyncJob.h"

#define STUB_API "comm/libcomm.la"
#include "tests/STUB.h"

#include "comm/AcceptLimiter.h"
Comm::AcceptLimiter dummy;
Comm::AcceptLimiter & Comm::AcceptLimiter::Instance() STUB_RETVAL(dummy)
void Comm::AcceptLimiter::defer(const Comm::TcpAcceptor::Pointer &) STUB
void Comm::AcceptLimiter::removeDead(const Comm::TcpAcceptor::Pointer &) STUB
void Comm::AcceptLimiter::kick() STUB

#include "comm/Connection.h"
Comm::Connection::Connection() STUB
Comm::Connection::~Connection() STUB
Comm::ConnectionPointer Comm::Connection::cloneProfile() const STUB_RETVAL(nullptr)
void Comm::Connection::close() STUB
void Comm::Connection::noteClosure() STUB
CachePeer * Comm::Connection::getPeer() const STUB_RETVAL(nullptr)
void Comm::Connection::setPeer(CachePeer *) STUB
ScopedId Comm::Connection::codeContextGist() const STUB_RETVAL(id.detach())
std::ostream &Comm::Connection::detailCodeContext(std::ostream &os) const STUB_RETVAL(os)
InstanceIdDefinitions(Comm::Connection, "conn", uint64_t);

#include "comm/ConnOpener.h"
CBDATA_NAMESPACED_CLASS_INIT(Comm, ConnOpener);
bool Comm::ConnOpener::doneAll() const STUB_RETVAL(false)
void Comm::ConnOpener::start() STUB
void Comm::ConnOpener::swanSong() STUB
Comm::ConnOpener::ConnOpener(const Comm::ConnectionPointer &, const AsyncCall::Pointer &, time_t) : AsyncJob("STUB Comm::ConnOpener") STUB
    Comm::ConnOpener::~ConnOpener() STUB
    void Comm::ConnOpener::setHost(const char *) STUB
    const char * Comm::ConnOpener::getHost() const STUB_RETVAL(nullptr)

#include "comm/forward.h"
    bool Comm::IsConnOpen(const Comm::ConnectionPointer &) STUB_RETVAL(false)

#include "comm/IoCallback.h"
    void Comm::IoCallback::setCallback(iocb_type, AsyncCall::Pointer &, char *, FREE *, int) STUB
    void Comm::IoCallback::selectOrQueueWrite() STUB
    void Comm::IoCallback::cancel(const char *) STUB
    void Comm::IoCallback::finish(Comm::Flag, int) STUB
    Comm::CbEntry *Comm::iocb_table = nullptr;
void Comm::CallbackTableInit() STUB
void Comm::CallbackTableDestruct() STUB

#include "comm/Loops.h"
void Comm::SelectLoopInit(void) STUB
void Comm::SetSelect(int, unsigned int, PF *, void *, time_t) STUB
Comm::Flag Comm::DoSelect(int) STUB_RETVAL(Comm::COMM_ERROR)
void Comm::QuickPollRequired(void) STUB

#include "comm/Read.h"
void Comm::Read(const Comm::ConnectionPointer &, AsyncCall::Pointer &) STUB
bool Comm::MonitorsRead(int) STUB_RETVAL(false)
Comm::Flag Comm::ReadNow(CommIoCbParams &, SBuf &) STUB_RETVAL(Comm::COMM_ERROR)
void Comm::ReadCancel(int, AsyncCall::Pointer &) STUB
//void Comm::HandleRead(int, void*) STUB

void comm_read_base(const Comm::ConnectionPointer &, char *, int, AsyncCall::Pointer &) STUB
void comm_read_cancel(int, IOCB *, void *) STUB

#include "comm/TcpAcceptor.h"
//Comm::TcpAcceptor(const Comm::ConnectionPointer &, const char *, const Subscription::Pointer &) STUB
void Comm::TcpAcceptor::subscribe(const Subscription::Pointer &) STUB
void Comm::TcpAcceptor::unsubscribe(const char *) STUB
void Comm::TcpAcceptor::acceptNext() STUB
void Comm::TcpAcceptor::notify(const Comm::Flag, const Comm::ConnectionPointer &) const STUB

#include "comm/Tcp.h"
void Comm::ApplyTcpKeepAlive(int, const TcpKeepAlive &) STUB

#include "comm/Write.h"
void Comm::Write(const Comm::ConnectionPointer &, const char *, int, AsyncCall::Pointer &, FREE *) STUB
void Comm::Write(const Comm::ConnectionPointer &, MemBuf *, AsyncCall::Pointer &) STUB
void Comm::WriteCancel(const Comm::ConnectionPointer &, const char *) STUB
/*PF*/ void Comm::HandleWrite(int, void*) STUB

std::ostream &Comm::operator <<(std::ostream &os, const Connection &) STUB_RETVAL(os << "[Connection object]")

