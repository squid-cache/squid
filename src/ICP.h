/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
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

#include "comm/forward.h"
#include "icp_opcode.h"
#include "ip/Address.h"
#include "LogTags.h"
#include "store_key_md5.h"
#include "StoreClient.h"

class HttpRequest;

/**
 \ingroup ServerProtocolICPAPI
 *
 * This struct is the wire-level header.
 * DO NOT add more move fields on pain of breakage.
 * DO NOT add virtual methods.
 */
struct _icp_common_t {
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

/// \todo I don't believe this header is included in non-c++ code anywhere
///     the struct should become a public POD class and kill these ifdef.
#ifdef __cplusplus

    _icp_common_t();
    _icp_common_t(char *buf, unsigned int len);

    void handleReply(char *buf, Ip::Address &from);
    static _icp_common_t *createMessage(icp_opcode opcode, int flags, const char *url, int reqnum, int pad);
    icp_opcode getOpCode() const;
#endif
};
typedef struct _icp_common_t icp_common_t;

#ifdef __cplusplus

/**
 \ingroup ServerProtocolICPAPI
 \todo mempool this
 */
class ICPState
{

public:
    ICPState(icp_common_t &aHeader, HttpRequest *aRequest);
    virtual ~ICPState();
    icp_common_t header;
    HttpRequest *request;
    int fd;

    Ip::Address from;
    char *url;
};

#endif

/// \ingroup ServerProtocolICPAPI
struct icpUdpData {

    /// IP address for the remote end. Because we reply to packets from unknown non-peers.
    Ip::Address address;

    void *msg;
    size_t len;
    icpUdpData *next;
#ifndef LESS_TIMING

    struct timeval start;
#endif

    LogTags logcode;

    struct timeval queue_time;
};

extern Comm::ConnectionPointer icpIncomingConn;
extern Comm::ConnectionPointer icpOutgoingConn;
extern Ip::Address theIcpPublicHostID;

/// \ingroup ServerProtocolICPAPI
HttpRequest* icpGetRequest(char *url, int reqnum, int fd, Ip::Address &from);

/// \ingroup ServerProtocolICPAPI
bool icpAccessAllowed(Ip::Address &from, HttpRequest * icp_request);

/// \ingroup ServerProtocolICPAPI
void icpCreateAndSend(icp_opcode, int flags, char const *url, int reqnum, int pad, int fd, const Ip::Address &from);

/// \ingroup ServerProtocolICPAPI
icp_opcode icpGetCommonOpcode();

/// \ingroup ServerProtocolICPAPI
int icpUdpSend(int, const Ip::Address &, icp_common_t *, const LogTags &, int);

/// \ingroup ServerProtocolICPAPI
LogTags icpLogFromICPCode(icp_opcode opcode);

/// \ingroup ServerProtocolICPAPI
void icpDenyAccess(Ip::Address &from, char *url, int reqnum, int fd);

/// \ingroup ServerProtocolICPAPI
PF icpHandleUdp;

/// \ingroup ServerProtocolICPAPI
PF icpUdpSendQueue;

/// \ingroup ServerProtocolICPAPI
void icpHandleIcpV3(int, Ip::Address &, char *, int);

/// \ingroup ServerProtocolICPAPI
int icpCheckUdpHit(StoreEntry *, HttpRequest * request);

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

