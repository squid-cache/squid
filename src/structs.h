/*
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */
#ifndef SQUID_STRUCTS_H
#define SQUID_STRUCTS_H

#define PEER_MULTICAST_SIBLINGS 1

#include "cbdata.h"
#include "defines.h"
#include "dlink.h"
#include "hash.h"
#include "HttpHeader.h"
#include "HttpHeaderTools.h"
#include "ip/Address.h"

class ACLChecklist;
class ACLList;
class PeerDigest;

#if SQUID_SNMP

#include "snmp_session.h"
// POD
class snmp_request_t
{
public:
    u_char *buf;
    u_char *outbuf;
    int len;
    int sock;
    long reqid;
    int outlen;

    Ip::Address from;

    struct snmp_pdu *PDU;
    ACLChecklist *acl_checklist;
    u_char *community;

    struct snmp_session session;
};

#endif /* SQUID_SNMP */

struct acl_tos {
    acl_tos *next;
    ACLList *aclList;
    tos_t tos;
};

struct acl_nfmark {
    acl_nfmark *next;
    ACLList *aclList;
    nfmark_t nfmark;
};

struct acl_size_t {
    acl_size_t *next;
    ACLList *aclList;
    int64_t size;
};

#if USE_DELAY_POOLS
#include "DelayConfig.h"
#include "ClientDelayConfig.h"
#endif

#if USE_ICMP
#include "icmp/IcmpConfig.h"
#endif

#include "HelperChildConfig.h"

class CpuAffinityMap;

// POD
class close_handler
{
public:
    PF *handler;
    void *data;
    close_handler *next;
};

// POD
class dread_ctrl
{
public:
    int fd;
    off_t offset;
    int req_len;
    char *buf;
    int end_of_file;
    DRCB *handler;
    void *client_data;
};

// POD
class dwrite_q
{
public:
    off_t file_offset;
    char *buf;
    size_t len;
    size_t buf_offset;
    dwrite_q *next;
    FREE *free_func;
};

struct _fde_disk {
    DWCB *wrt_handle;
    void *wrt_handle_data;
    dwrite_q *write_q;
    dwrite_q *write_q_tail;
    off_t offset;
};

// POD
class http_state_flags
{
public:
    unsigned int proxying:1;
    unsigned int keepalive:1;
    unsigned int only_if_cached:1;
    unsigned int handling1xx:1; ///< we are ignoring or forwarding 1xx response
    unsigned int headers_parsed:1;
    unsigned int front_end_https:2;
    unsigned int originpeer:1;
    unsigned int keepalive_broken:1;
    unsigned int abuse_detected:1;
    unsigned int request_sent:1;
    unsigned int do_next_read:1;
    unsigned int consume_body_data:1;
    unsigned int chunked:1; ///< reading a chunked response; TODO: rename
    unsigned int chunked_request:1; ///< writing a chunked request
    unsigned int sentLastChunk:1; ///< do not try to write last-chunk again
};

// POD
class domain_ping
{
public:
    char *domain;
    int do_ping;		/* boolean */
    domain_ping *next;
};

// POD
class domain_type
{
public:
    char *domain;
    peer_t type;
    domain_type *next;
};

#if USE_SSL
struct _sslproxy_cert_sign {
    int alg;
    ACLList *aclList;
    sslproxy_cert_sign *next;
};

struct _sslproxy_cert_adapt {
    int alg;
    char *param;
    ACLList *aclList;
    sslproxy_cert_adapt *next;
};
#endif

#endif /* SQUID_STRUCTS_H */
