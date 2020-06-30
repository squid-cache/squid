/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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
void Comm::AcceptLimiter::defer(const Comm::TcpAcceptor::Pointer &afd) STUB
void Comm::AcceptLimiter::removeDead(const Comm::TcpAcceptor::Pointer &afd) STUB
void Comm::AcceptLimiter::kick() STUB

#include "comm/Connection.h"
Comm::Connection::Connection() STUB
Comm::Connection::~Connection() STUB
Comm::ConnectionPointer Comm::Connection::cloneIdentDetails() const STUB_RETVAL(nullptr)
Comm::ConnectionPointer Comm::Connection::cloneDestinationDetails() const STUB_RETVAL(nullptr)
void Comm::Connection::close() STUB
CachePeer * Comm::Connection::getPeer() const STUB_RETVAL(NULL)
void Comm::Connection::setPeer(CachePeer * p) STUB
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
    const char * Comm::ConnOpener::getHost() const STUB_RETVAL(NULL)

#include "comm/forward.h"
    bool Comm::IsConnOpen(const Comm::ConnectionPointer &) STUB_RETVAL(false)

#include "comm/IoCallback.h"
    void Comm::IoCallback::setCallback(iocb_type, AsyncCall::Pointer &, char *, FREE *, int) STUB
    void Comm::IoCallback::selectOrQueueWrite() STUB
    void Comm::IoCallback::cancel(const char *reason) STUB
    void Comm::IoCallback::finish(Comm::Flag code, int xerrn) STUB
    Comm::CbEntry *Comm::iocb_table = NULL;
void Comm::CallbackTableInit() STUB
void Comm::CallbackTableDestruct() STUB

#include "comm/Loops.h"
void Comm::SelectLoopInit(void) STUB
void Comm::SetSelect(int, unsigned int, PF *, void *, time_t) STUB
Comm::Flag Comm::DoSelect(int) STUB_RETVAL(Comm::COMM_ERROR)
void Comm::QuickPollRequired(void) STUB

#include "comm/Read.h"
void Comm::Read(const Comm::ConnectionPointer &conn, AsyncCall::Pointer &callback) STUB
bool Comm::MonitorsRead(int fd) STUB_RETVAL(false)
Comm::Flag Comm::ReadNow(CommIoCbParams &params, SBuf &buf) STUB_RETVAL(Comm::COMM_ERROR)
void Comm::ReadCancel(int fd, AsyncCall::Pointer &callback) STUB
//void Comm::HandleRead(int, void*) STUB

void comm_read_base(const Comm::ConnectionPointer &conn, char *buf, int len, AsyncCall::Pointer &callback) STUB
void comm_read_cancel(int fd, IOCB *callback, void *data) STUB

#include "comm/TcpAcceptor.h"
//Comm::TcpAcceptor(const Comm::ConnectionPointer &conn, const char *note, const Subscription::Pointer &aSub) STUB
void Comm::TcpAcceptor::subscribe(const Subscription::Pointer &aSub) STUB
void Comm::TcpAcceptor::unsubscribe(const char *) STUB
void Comm::TcpAcceptor::acceptNext() STUB
void Comm::TcpAcceptor::notify(const Comm::Flag flag, const Comm::ConnectionPointer &) const STUB

#include "comm/Write.h"
void Comm::Write(const Comm::ConnectionPointer &, const char *, int, AsyncCall::Pointer &, FREE *) STUB
void Comm::Write(const Comm::ConnectionPointer &conn, MemBuf *mb, AsyncCall::Pointer &callback) STUB
void Comm::WriteCancel(const Comm::ConnectionPointer &conn, const char *reason) STUB
/*PF*/ void Comm::HandleWrite(int, void*) STUB

std::ostream &operator << (std::ostream &os, const Comm::Connection &conn) STUB_RETVAL(os << "[Connection object]")

