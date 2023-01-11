/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ICP_H
#define SQUID_ICP_H

/**
 \defgroup ServerProtocolICPAPI ICP
 \ingroup ServerProtocol
 */

#include "base/RefCount.h"
#include "comm/forward.h"
#include "icp_opcode.h"
#include "ip/Address.h"
#include "LogTags.h"
#include "store_key_md5.h"
#include "StoreClient.h"

class AccessLogEntry;
class HttpRequest;

typedef RefCount<AccessLogEntry> AccessLogEntryPointer;

/**
 * Wire-level ICP header.
 * DO NOT add or move fields.
 * DO NOT add virtual methods.
 */
class icp_common_t {
public:
    /** opcode */
    unsigned char opcode;
    /** version number */
    unsigned char version;
    /** total length (bytes) */
    unsigned short length;
    /** req number (req'd for UDP) */
    uint32_t reqnum;
    uint32_t flags;
    uint32_t pad;
    /** sender host id */
    uint32_t shostid;

    icp_common_t();
    icp_common_t(char *buf, unsigned int len);

    void handleReply(char *buf, Ip::Address &from);
    icp_opcode getOpCode() const;

    /// \returns newly allocated buffer with an ICP message, including header
    static icp_common_t *CreateMessage(icp_opcode opcode, int flags, const char *url, int reqnum, int pad);
};

// TODO: mempool this
class ICPState: public StoreClient
{

public:
    ICPState(icp_common_t &aHeader, HttpRequest *aRequest);
    virtual ~ICPState();

    icp_common_t header;
    HttpRequest *request;
    int fd;

    Ip::Address from;
    char *url;

protected:
    /* StoreClient API */
    virtual LogTags *loggingTags() override;
    virtual void fillChecklist(ACLFilledChecklist &) const override;

    /// either confirms and starts processing a cache hit or returns false
    bool confirmAndPrepHit(const StoreEntry &);

    mutable AccessLogEntryPointer al;
};

extern Comm::ConnectionPointer icpIncomingConn;
extern Comm::ConnectionPointer icpOutgoingConn;
extern Ip::Address theIcpPublicHostID;

/// \ingroup ServerProtocolICPAPI
HttpRequest* icpGetRequest(char *url, int reqnum, int fd, Ip::Address &from);

/// \ingroup ServerProtocolICPAPI
bool icpAccessAllowed(Ip::Address &from, HttpRequest * icp_request);

/// \ingroup ServerProtocolICPAPI
void icpCreateAndSend(icp_opcode, int flags, char const *url, int reqnum, int pad, int fd, const Ip::Address &from, AccessLogEntryPointer);

/// \ingroup ServerProtocolICPAPI
icp_opcode icpGetCommonOpcode();

/// \ingroup ServerProtocolICPAPI
void icpDenyAccess(Ip::Address &from, char *url, int reqnum, int fd);

/// \ingroup ServerProtocolICPAPI
PF icpHandleUdp;

/// \ingroup ServerProtocolICPAPI
void icpHandleIcpV3(int, Ip::Address &, char *, int);

/// \ingroup ServerProtocolICPAPI
void icpOpenPorts(void);

/// \ingroup ServerProtocolICPAPI
void icpConnectionShutdown(void);

/// \ingroup ServerProtocolICPAPI
void icpClosePorts(void);

/// \ingroup ServerProtocolICPAPI
int icpSetCacheKey(const cache_key * key);

/// \ingroup ServerProtocolICPAPI
const cache_key *icpGetCacheKey(const char *url, int reqnum);

#endif /* SQUID_ICP_H */

