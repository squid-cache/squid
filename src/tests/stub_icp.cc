/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "comm/Connection.h"
#include "ICP.h"

#define STUB_API "icp_*.cc"
#include "tests/STUB.h"

icp_common_t::icp_common_t() STUB
icp_common_t::icp_common_t(char *buf, unsigned int len) STUB
void icp_common_t::handleReply(char *buf, Ip::Address &from) STUB
icp_common_t *icp_common_t::CreateMessage(icp_opcode opcode, int flags, const char *url, int reqnum, int pad) STUB_RETVAL(nullptr)
icp_opcode icp_common_t::getOpCode() const STUB_RETVAL(ICP_INVALID)
ICPState::ICPState(icp_common_t &aHeader, HttpRequest *aRequest) STUB
ICPState::~ICPState() STUB
bool ICPState::confirmAndPrepHit(const StoreEntry &) STUB_RETVAL(false)
LogTags *ICPState::loggingTags() STUB_RETVAL(nullptr)
void ICPState::fillChecklist(ACLFilledChecklist&) const STUB

Comm::ConnectionPointer icpIncomingConn;
Comm::ConnectionPointer icpOutgoingConn;
Ip::Address theIcpPublicHostID;

HttpRequest* icpGetRequest(char *url, int reqnum, int fd, Ip::Address &from) STUB_RETVAL(NULL)
bool icpAccessAllowed(Ip::Address &from, HttpRequest * icp_request) STUB_RETVAL(false)
void icpCreateAndSend(icp_opcode, int flags, char const *url, int reqnum, int pad, int fd, const Ip::Address &from, AccessLogEntryPointer) STUB
icp_opcode icpGetCommonOpcode() STUB_RETVAL(ICP_INVALID)
void icpDenyAccess(Ip::Address &from, char *url, int reqnum, int fd) STUB
void icpHandleIcpV3(int, Ip::Address &, char *, int) STUB
void icpConnectionsOpen(void) STUB
void icpConnectionShutdown(void) STUB
void icpConnectionClose(void) STUB
int icpSetCacheKey(const cache_key * key) STUB_RETVAL(0)
const cache_key *icpGetCacheKey(const char *url, int reqnum) STUB_RETVAL(NULL)

#include "icp_opcode.h"
// dynamically generated
#include "icp_opcode.cc"

