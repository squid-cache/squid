/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/Loops.h"
// #include "comm/Read.h"
#include "fde.h"

#define STUB_API "comm.cc"
#include "tests/STUB.h"

#include <ostream>

// void comm_read(const Comm::ConnectionPointer &, char *, int, IOCB *, void *) STUB
// void comm_read(const Comm::ConnectionPointer &, char*, int, AsyncCall::Pointer &) STUB

/* should be in stub_libbase */
#include "base/DelayedAsyncCalls.h"
void DelayedAsyncCalls::delay(const AsyncCall::Pointer &) STUB
void DelayedAsyncCalls::schedule() STUB

#include "comm.h"
bool comm_iocallbackpending(void) STUB_RETVAL(false)
int commSetNonBlocking(int) STUB_RETVAL(Comm::COMM_ERROR)
int commUnsetNonBlocking(int) STUB_RETVAL(-1)
void commSetCloseOnExec(int) STUB_NOP
void _comm_close(int, char const *, int) STUB
void old_comm_reset_close(int) STUB
void comm_reset_close(const Comm::ConnectionPointer &) STUB
int comm_connect_addr(int, const Ip::Address &) STUB_RETVAL(-1)

void comm_init(void) STUB
void comm_exit(void) STUB
int comm_open(int, int, Ip::Address &, int, const char *) STUB_RETVAL(-1)
int comm_open_uds(int, int, struct sockaddr_un*, int) STUB_RETVAL(-1)
void comm_import_opened(const Comm::ConnectionPointer &, const char *, struct addrinfo *) STUB
int comm_open_listener(int, int, Ip::Address &, int, const char *) STUB_RETVAL(-1)
void comm_open_listener(int, int, Comm::ConnectionPointer &, const char *) STUB
unsigned short comm_local_port(int) STUB_RETVAL(0)
int comm_udp_sendto(int, const Ip::Address &, const void *, int) STUB_RETVAL(-1)
void commCallCloseHandlers(int) STUB
void commUnsetFdTimeout(int) STUB
// int commSetTimeout(const Comm::ConnectionPointer &, int, AsyncCall::Pointer&) STUB_RETVAL(-1)
int commSetConnTimeout(const Comm::ConnectionPointer &, int, AsyncCall::Pointer &) STUB_RETVAL(-1)
int commUnsetConnTimeout(const Comm::ConnectionPointer &) STUB_RETVAL(-1)
int ignoreErrno(int) STUB_RETVAL(-1)
void commCloseAllSockets(void) STUB
void checkTimeouts(void) STUB
AsyncCall::Pointer comm_add_close_handler(int, CLCB *, void *) STUB
void comm_add_close_handler(int, AsyncCall::Pointer &) STUB
void comm_remove_close_handler(int, CLCB *, void *) STUB
void comm_remove_close_handler(int, AsyncCall::Pointer &)STUB
int comm_udp_recvfrom(int, void *, size_t, int, Ip::Address &) STUB_RETVAL(-1)
int comm_udp_recv(int, void *, size_t, int) STUB_RETVAL(-1)
ssize_t comm_udp_send(int, const void *, size_t, int) STUB_RETVAL(-1)
bool comm_has_incomplete_write(int) STUB_RETVAL(false)
void commStartHalfClosedMonitor(int) STUB
bool commHasHalfClosedMonitor(int) STUB_RETVAL(false)
int CommSelectEngine::checkEvents(int) STUB_RETVAL(0)

