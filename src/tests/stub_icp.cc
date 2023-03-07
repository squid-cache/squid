/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
icp_common_t::icp_common_t(char *, unsigned int) STUB
void icp_common_t::handleReply(char *, Ip::Address &) STUB
icp_common_t *icp_common_t::CreateMessage(icp_opcode, int, const char *, int, int) STUB_RETVAL(nullptr)
icp_opcode icp_common_t::getOpCode() const STUB_RETVAL(ICP_INVALID)
ICPState::ICPState(icp_common_t &, HttpRequest *) STUB
ICPState::~ICPState() STUB
bool ICPState::confirmAndPrepHit(const StoreEntry &) const STUB_RETVAL(false)
LogTags *ICPState::loggingTags() const STUB_RETVAL(nullptr)
void ICPState::fillChecklist(ACLFilledChecklist&) const STUB

Comm::ConnectionPointer icpIncomingConn;
Comm::ConnectionPointer icpOutgoingConn;
Ip::Address theIcpPublicHostID;

HttpRequest* icpGetRequest(char *, int, int, Ip::Address &) STUB_RETVAL(nullptr)
bool icpAccessAllowed(Ip::Address &, HttpRequest *) STUB_RETVAL(false)
void icpCreateAndSend(icp_opcode, int, char const *, int, int, int, const Ip::Address &, AccessLogEntryPointer) STUB
icp_opcode icpGetCommonOpcode() STUB_RETVAL(ICP_INVALID)
void icpDenyAccess(Ip::Address &, char *, int, int) STUB
void icpHandleIcpV3(int, Ip::Address &, char *, int) STUB
void icpConnectionShutdown(void) STUB
int icpSetCacheKey(const cache_key *) STUB_RETVAL(0)
const cache_key *icpGetCacheKey(const char *, int) STUB_RETVAL(nullptr)

#include "icp_opcode.h"
// dynamically generated
#include "icp_opcode.cc"

