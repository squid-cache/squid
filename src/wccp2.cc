/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 80    WCCP Support */

#include "squid.h"

#if USE_WCCPv2

#include "cache_cf.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/Loops.h"
#include "ConfigParser.h"
#include "event.h"
#include "ip/Address.h"
#include "md5.h"
#include "Parsing.h"
#include "SquidConfig.h"
#include "Store.h"

#if HAVE_NETDB_H
#include <netdb.h>
#endif

#define WCCP_PORT 2048
#define WCCP_RESPONSE_SIZE 12448
#define WCCP_BUCKETS 256

static int theWccp2Connection = -1;
static int wccp2_connected = 0;

static PF wccp2HandleUdp;
static EVH wccp2HereIam;
static EVH wccp2AssignBuckets;

/* KDW WCCP V2 */

#define WCCP2_HASH_ASSIGNMENT       0x00
#define WCCP2_MASK_ASSIGNMENT       0x01

#define WCCP2_NONE_SECURITY_LEN 0
#define WCCP2_MD5_SECURITY_LEN  SQUID_MD5_DIGEST_LENGTH // 16

/* Useful defines */
#define WCCP2_NUMPORTS  8
#define WCCP2_PASSWORD_LEN  8 + 1 /* + 1 for C-string NUL terminator */

/* WCCPv2 Pakcet format structures */
/* Defined in draft-wilson-wccp-v2-12-oct-2001.txt */

/** \interface WCCPv2_Protocol
 * Generic header struct
 */
struct wccp2_item_header_t {
    uint16_t type;
    uint16_t length;
};

/* item type values */
#define WCCP2_SECURITY_INFO     0
#define WCCP2_SERVICE_INFO      1
#define WCCP2_ROUTER_ID_INFO        2
#define WCCP2_WC_ID_INFO        3
#define WCCP2_RTR_VIEW_INFO     4
#define WCCP2_WC_VIEW_INFO      5
#define WCCP2_REDIRECT_ASSIGNMENT   6
#define WCCP2_QUERY_INFO        7
#define WCCP2_CAPABILITY_INFO       8
#define WCCP2_ALT_ASSIGNMENT        13
#define WCCP2_ASSIGN_MAP        14
#define WCCP2_COMMAND_EXTENSION     15

/** \interface WCCPv2_Protocol
 * Sect 5.5  WCCP Message Header
 */
struct wccp2_message_header_t {
    uint32_t type;
    uint16_t version;
#define WCCP2_VERSION          0x200

    uint16_t length;
};
static struct wccp2_message_header_t wccp2_here_i_am_header;

/* message types */
#define WCCP2_HERE_I_AM           10
#define WCCP2_I_SEE_YOU           11
#define WCCP2_REDIRECT_ASSIGN     12
#define WCCP2_REMOVAL_QUERY       13

/** \interface WCCPv2_Protocol
 * Sect 5.6.1 Security Info Component
 *
 * Basic security Header. Matches "no security" case exactly.
 */
struct wccp2_security_none_t {
    uint16_t security_type;
    uint16_t security_length;
    uint32_t security_option;
};

/* security options */
#define WCCP2_NO_SECURITY       0
#define WCCP2_MD5_SECURITY      1

/** \interface WCCPv2_Protocol
 * Sect 5.6.1 Security Info Component
 *
 * Extended security section. Matches "MD5 security" type exactly.
 * Including the security header.
 */
struct wccp2_security_md5_t {
    uint16_t security_type;
    uint16_t security_length;
    uint32_t security_option;
    uint8_t security_implementation[WCCP2_MD5_SECURITY_LEN];
};

/* Service info struct */

/** \interface WCCPv2_Protocol
 * Sect 5.6.2 Service Info Component
 */
struct wccp2_service_info_t {
    uint16_t service_type;
    uint16_t service_length;
    uint8_t service;
    uint8_t service_id;
    uint8_t service_priority;
    uint8_t service_protocol;
    uint32_t service_flags;
    uint16_t port0;
    uint16_t port1;
    uint16_t port2;
    uint16_t port3;
    uint16_t port4;
    uint16_t port5;
    uint16_t port6;
    uint16_t port7;
};
/* services */
#define WCCP2_SERVICE_STANDARD      0
#define WCCP2_SERVICE_DYNAMIC       1

/* service IDs */
#define WCCP2_SERVICE_ID_HTTP       0x00

/* service flags */
#define WCCP2_SERVICE_SRC_IP_HASH   0x1
#define WCCP2_SERVICE_DST_IP_HASH   0x2
#define WCCP2_SERVICE_SRC_PORT_HASH 0x4
#define WCCP2_SERVICE_DST_PORT_HASH 0x8
#define WCCP2_SERVICE_PORTS_DEFINED 0x10
#define WCCP2_SERVICE_PORTS_SOURCE  0x20
#define WCCP2_SERVICE_SRC_IP_ALT_HASH   0x100
#define WCCP2_SERVICE_DST_IP_ALT_HASH   0x200
#define WCCP2_SERVICE_SRC_PORT_ALT_HASH 0x400
#define WCCP2_SERVICE_DST_PORT_ALT_HASH 0x800

/* TODO the following structures need to be re-defined for correct full operation.
 wccp2_cache_identity_element needs to be merged as a sub-struct of
 wccp2_identity_info_t (identity_type);  which frees up the identifty info
 structures so mask_assigment_data_element can become variable length
 and cope with multiple fail-over caches hanging off one router.
 */

/** \interface WCCPv2_Protocol
 * Sect 5.7.2 Web-Cache Identity Element
 */
struct wccp2_cache_identity_info_t {
    struct in_addr addr;
    uint16_t hash_revision;
    uint16_t bits;
//#define WCCP2_HASH_ASSIGNMENT_DATA  0x0

    /* 5.7.2 Hash Assignment Data Element */
    char buckets[32]; /* Draft indicates 8x 32-bit buckets but it's just a mask so doesn't matter how we define. */
    uint16_t weight;
    uint16_t status;
};

/** \interface WCCPv2_Protocol
 * Sect 5.6.4 Web-Cache Identity Info Component
 */
struct wccp2_identity_info_t {
    uint16_t cache_identity_type;
    uint16_t cache_identity_length;

    struct wccp2_cache_identity_info_t cache_identity;
};

static struct wccp2_identity_info_t wccp2_identity_info;

/** \interface WCCPv2_Protocol
 * Sect 5.7.7 Mask Element
 */
struct wccp2_mask_element_t {
    uint32_t source_ip_mask;
    uint32_t dest_ip_mask;
    uint16_t source_port_mask;
    uint16_t dest_port_mask;
    uint32_t number_values;
};

/** \interface WCCPv2_Protocol
 * Sect 5.7.2 Web-Cache Identity Element
 */
struct wccp2_cache_mask_identity_info_t {
    struct in_addr addr;
    uint16_t hash_revision;
    uint16_t bits;
#define WCCP2_MASK_ASSIGNMENT_DATA  (0x2)

    /* Sect 5.7.2 Mask Assignment Data Element
     *
     * NP: draft specifies a variable-length set of keys here.
     *     the following fields only matche the special case Squid sends outbound (single-cache).
     */
    uint32_t mask_element_count;

    /* Sect 5.7.6 Mask/Value Set Element */
    /* special case: single mask element. no values. */
    struct wccp2_mask_element_t mask;

    /* Sect 5.7.2 Mask Assignment Data Element */
    uint16_t weight;
    uint16_t status;
};

/** \interface WCCPv2_Protocol
 * Sect 5.6.4 Web-Cache Identity Info Component
 */
struct wccp2_mask_identity_info_t {
    uint16_t cache_identity_type;
    uint16_t cache_identity_length;

    struct wccp2_cache_mask_identity_info_t cache_identity;
};

static struct wccp2_mask_identity_info_t wccp2_mask_identity_info;

/** \interface WCCPv2_Protocol
 * Sect 5.6.5 Router View Info Component
 * Sect 5.6.6 Web Cache View Info Component
 *
 * first three fields. (shared by both view components)
 */
struct wccp2_cache_view_header_t {
    uint16_t cache_view_type;
    uint16_t cache_view_length;
    uint32_t cache_view_version;
};

static struct wccp2_cache_view_header_t wccp2_cache_view_header;

/// \interface WCCPv2_Protocol
/* NP: special-case 5.6.5 or 5.6.6 * View Info when no routers or caches are advertised? */
struct wccp2_cache_view_info_t {
    uint32_t num_routers;
    uint32_t num_caches;
};

static struct wccp2_cache_view_info_t wccp2_cache_view_info;

/** \interface WCCPv2_Protocol
 * Sect 5.7.1 Router ID Element
 */
struct wccp2_router_id_element_t {
    struct in_addr router_address;
    uint32_t received_id;
};

// unused (for now)
// static struct wccp2_router_id_element_t wccp2_router_id_element;

/** \interface WCCPv2_Protocol
 * Sect 5.6.9 Capabilities Info Component
 */
struct wccp2_capability_info_header_t {
    uint16_t capability_info_type;
    uint16_t capability_info_length;
    /* dynamic length capabilities list */
};

static struct wccp2_capability_info_header_t wccp2_capability_info_header;

/** \interface WCCPv2_Protocol
 * 5.7.5 Capability Element
 */
struct wccp2_capability_element_t {
    uint16_t capability_type;
    uint16_t capability_length;
    uint32_t capability_value;
};
static struct wccp2_capability_element_t wccp2_capability_element;

/* capability types */
#define WCCP2_CAPABILITY_FORWARDING_METHOD  0x01
#define WCCP2_CAPABILITY_ASSIGNMENT_METHOD  0x02
#define WCCP2_CAPABILITY_RETURN_METHOD      0x03
// 0x04 ?? - advertised by a 4507 (ios v15.1) Cisco switch
// 0x05 ?? - advertised by a 4507 (ios v15.1) Cisco switch

/* capability values */
#define WCCP2_METHOD_GRE        0x00000001
#define WCCP2_METHOD_L2         0x00000002
/* when type=WCCP2_CAPABILITY_FORWARDING_METHOD */
#define WCCP2_FORWARDING_METHOD_GRE WCCP2_METHOD_GRE
#define WCCP2_FORWARDING_METHOD_L2  WCCP2_METHOD_L2
/* when type=WCCP2_CAPABILITY_ASSIGNMENT_METHOD */
#define WCCP2_ASSIGNMENT_METHOD_HASH    0x00000001
#define WCCP2_ASSIGNMENT_METHOD_MASK    0x00000002
/* when type=WCCP2_CAPABILITY_RETURN_METHOD */
#define WCCP2_PACKET_RETURN_METHOD_GRE  WCCP2_METHOD_GRE
#define WCCP2_PACKET_RETURN_METHOD_L2   WCCP2_METHOD_L2

/** \interface WCCPv2_Protocol
 * 5.7.8 Value Element
 */
struct wccp2_value_element_t {
    uint32_t source_ip_value;
    uint32_t dest_ip_value;
    uint16_t source_port_value;
    uint16_t dest_port_value;

    struct in_addr cache_ip;
};

/* RECEIVED PACKET STRUCTURE */

/** \interface WCCPv2_Protocol
 * 5.2 'I See You' Message
 */
struct wccp2_i_see_you_t {
    uint32_t type;
    uint16_t version;
    uint16_t length;
    char data[WCCP_RESPONSE_SIZE];
};

static struct wccp2_i_see_you_t wccp2_i_see_you;

/** \interface WCCPv2_Protocol
 * 5.7.4 Router Assignment Element
 */
struct wccp2_router_assign_element_t {
    struct in_addr router_address;
    uint32_t received_id;
    uint32_t change_number;
};

/* Router identity struct */

/** \interface WCCPv2_Protocol
 * 5.6.3 Router Identity Info Component (partial)
 */
struct router_identity_info_t {

    struct wccp2_item_header_t header;

    struct wccp2_router_id_element_t router_id_element;

    struct in_addr router_address;
    uint32_t number_caches;
    /* dynamic list of cache IP addresses */
};

/* The received packet for a mask assignment is unusual */

/** \interface WCCPv2_Protocol
 * Sect 5.7.7 Mask Element  ???
 * see code below. apparently the supposed IP address at position num1 can be equal to 3.
 */
struct cache_mask_info_t {
    struct in_addr addr;
    uint32_t num1;
    uint32_t num2;
    uint32_t num3;
};

/** \interface WCCPv2_Protocol
 * 5.7.3 Assignment Key Element
 */
struct assignment_key_t {
    struct in_addr master_ip;
    uint32_t master_number;
};

/** \interface WCCPv2_Protocol
 * 5.6.5 Router View Info Component (first three fields)
 */
struct router_view_t {
    struct wccp2_item_header_t header;
    uint32_t change_number;
    struct assignment_key_t assignment_key;
    /* dynamic lists of routers and caches elided */
};

/* Lists used to keep track of caches, routers and services */

/// \interface WCCPv2_Protocol
struct wccp2_cache_list_t {

    struct in_addr cache_ip;

    int weight;

    struct wccp2_cache_list_t *next;
};

/// \interface WCCPv2_Protocol
struct wccp2_router_list_t {

    struct wccp2_router_id_element_t *info;

    struct in_addr local_ip;

    struct in_addr router_sendto_address;
    uint32_t member_change;
    uint32_t num_caches;

    struct wccp2_cache_list_t cache_list_head;

    struct wccp2_router_list_t *next;
};

static int wccp2_numrouters;

/// \interface WCCPv2_Protocol
struct wccp2_service_list_t {

    struct wccp2_service_info_t info;
    uint32_t num_routers;

    struct wccp2_router_list_t router_list_head;
    int lowest_ip;
    uint32_t change_num;

    char *wccp2_identity_info_ptr;

    struct wccp2_security_md5_t *security_info;

    struct wccp2_service_info_t *service_info;
    char wccp_packet[WCCP_RESPONSE_SIZE];
    size_t wccp_packet_size;

    struct wccp2_service_list_t *next;
    char wccp_password[WCCP2_PASSWORD_LEN];     /* hold the trailing C-string NUL */
    uint32_t wccp2_security_type;
};

static struct wccp2_service_list_t *wccp2_service_list_head = NULL;

int empty_portlist[WCCP2_NUMPORTS] = {0, 0, 0, 0, 0, 0, 0, 0};

/* END WCCP V2 PROTOCL TYPES DEFINITION */

void wccp2_add_service_list(int service, int service_id, int service_priority,
                            int service_proto, int service_flags, int ports[], int security_type, char *password);
static void wccp2SortCacheList(struct wccp2_cache_list_t *head);

/*
 * The functions used during startup:
 * wccp2Init
 * wccp2ConnectionOpen
 * wccp2ConnectionClose
 */

static void
wccp2InitServices(void)
{
    debugs(80, 5, "wccp2InitServices: called");
}

static void
wccp2_update_service(struct wccp2_service_list_t *srv, int service,
                     int service_id, int service_priority, int service_proto, int service_flags,
                     int ports[])
{
    /* XXX check what needs to be wrapped in htons()! */
    srv->info.service = service;
    srv->info.service_id = service_id;
    srv->info.service_priority = service_priority;
    srv->info.service_protocol = service_proto;
    srv->info.service_flags = htonl(service_flags);
    srv->info.port0 = htons(ports[0]);
    srv->info.port1 = htons(ports[1]);
    srv->info.port2 = htons(ports[2]);
    srv->info.port3 = htons(ports[3]);
    srv->info.port4 = htons(ports[4]);
    srv->info.port5 = htons(ports[5]);
    srv->info.port6 = htons(ports[6]);
    srv->info.port7 = htons(ports[7]);
}

void
wccp2_add_service_list(int service, int service_id, int service_priority,
                       int service_proto, int service_flags, int ports[], int security_type,
                       char *password)
{

    struct wccp2_service_list_t *wccp2_service_list_ptr;

    wccp2_service_list_ptr = (wccp2_service_list_t *) xcalloc(1, sizeof(struct wccp2_service_list_t));

    debugs(80, 5, "wccp2_add_service_list: added service id " << service_id);

    /* XXX check what needs to be wrapped in htons()! */
    wccp2_service_list_ptr->info.service_type = htons(WCCP2_SERVICE_INFO);

    wccp2_service_list_ptr->info.service_length = htons(sizeof(struct wccp2_service_info_t) - 4);
    wccp2_service_list_ptr->change_num = 0;
    wccp2_update_service(wccp2_service_list_ptr, service, service_id,
                         service_priority, service_proto, service_flags, ports);
    wccp2_service_list_ptr->wccp2_security_type = security_type;
    memset(wccp2_service_list_ptr->wccp_password, 0, WCCP2_PASSWORD_LEN);
    xstrncpy(wccp2_service_list_ptr->wccp_password, password, WCCP2_PASSWORD_LEN);
    /* add to linked list - XXX this should use the Squid dlink* routines! */
    wccp2_service_list_ptr->next = wccp2_service_list_head;
    wccp2_service_list_head = wccp2_service_list_ptr;
}

static struct wccp2_service_list_t *
wccp2_get_service_by_id(int service, int service_id) {

    struct wccp2_service_list_t *p;

    p = wccp2_service_list_head;

    while (p != NULL) {
        if (p->info.service == service && p->info.service_id == service_id) {
            return p;
        }

        p = p->next;
    }

    return NULL;
}

/*
 * Update the md5 security header, if possible
 *
 * Returns: 1 if we set it, 0 if not (eg, no security section, or non-md5)
 */
static char
wccp2_update_md5_security(char *password, char *ptr, char *packet, int len)
{
    uint8_t md5Digest[SQUID_MD5_DIGEST_LENGTH];
    char pwd[WCCP2_PASSWORD_LEN];
    SquidMD5_CTX M;

    struct wccp2_security_md5_t *ws;

    debugs(80, 5, "wccp2_update_md5_security: called");

    /* The password field, for the MD5 hash, needs to be 8 bytes and NUL padded. */
    memset(pwd, 0, sizeof(pwd));
    xstrncpy(pwd, password, sizeof(pwd));

    ws = (struct wccp2_security_md5_t *) ptr;
    assert(ntohs(ws->security_type) == WCCP2_SECURITY_INFO);
    /* Its the security part */

    if (ntohl(ws->security_option) != WCCP2_MD5_SECURITY) {
        debugs(80, 5, "wccp2_update_md5_security: this service ain't md5'ing, abort");
        return 0;
    }

    /* And now its the MD5 section! */
    /* According to the draft, the MD5 security hash is the combination of
     * the 8-octet password (padded w/ NUL bytes) and the entire WCCP packet,
     * including the WCCP message header. The WCCP security implementation
     * area should be zero'ed before calculating the MD5 hash.
     */
    /* XXX eventually we should be able to kill md5Digest and blit it directly in */
    memset(ws->security_implementation, 0, sizeof(ws->security_implementation));

    SquidMD5Init(&M);

    static_assert(sizeof(pwd) - 1 == 8, "WCCP2 password has exactly 8 (padded) octets, excluding storage-terminating NUL");

    SquidMD5Update(&M, pwd, sizeof(pwd) - 1);

    SquidMD5Update(&M, packet, len);

    SquidMD5Final(md5Digest, &M);

    memcpy(ws->security_implementation, md5Digest, sizeof(md5Digest));

    /* Finished! */
    return 1;
}

/*
 * Check the given WCCP2 packet against the given password.
 */
static char

wccp2_check_security(struct wccp2_service_list_t *srv, char *security, char *packet, int len)
{

    struct wccp2_security_md5_t *ws = (struct wccp2_security_md5_t *) security;
    uint8_t md5Digest[SQUID_MD5_DIGEST_LENGTH], md5_challenge[SQUID_MD5_DIGEST_LENGTH];
    char pwd[WCCP2_PASSWORD_LEN];
    SquidMD5_CTX M;

    /* Make sure the security type matches what we expect */

    if (ntohl(ws->security_option) != srv->wccp2_security_type) {
        debugs(80, DBG_IMPORTANT, "wccp2_check_security: received packet has the wrong security option");
        return 0;
    }

    if (srv->wccp2_security_type == WCCP2_NO_SECURITY) {
        return 1;
    }

    if (srv->wccp2_security_type != WCCP2_MD5_SECURITY) {
        debugs(80, DBG_IMPORTANT, "wccp2_check_security: invalid security option");
        return 0;
    }

    /* If execution makes it here then we have an MD5 security */

    /* The password field, for the MD5 hash, needs to be 8 bytes and NUL padded. */
    memset(pwd, 0, sizeof(pwd));
    xstrncpy(pwd, srv->wccp_password, sizeof(pwd));

    /* Take a copy of the challenge: we need to NUL it before comparing */
    memcpy(md5_challenge, ws->security_implementation, sizeof(md5_challenge));

    memset(ws->security_implementation, 0, sizeof(ws->security_implementation));

    SquidMD5Init(&M);

    static_assert(sizeof(pwd) - 1 == 8, "WCCP2 password has exactly 8 (padded) octets, excluding storage-terminating NUL");

    SquidMD5Update(&M, pwd, sizeof(pwd) - 1);

    SquidMD5Update(&M, packet, len);

    SquidMD5Final(md5Digest, &M);

    return (memcmp(md5Digest, md5_challenge, SQUID_MD5_DIGEST_LENGTH) == 0);
}

void
wccp2Init(void)
{
    Ip::Address_list *s;
    char *ptr;
    uint32_t service_flags;

    struct wccp2_service_list_t *service_list_ptr;

    struct wccp2_router_list_t *router_list_ptr;

    debugs(80, 5, "wccp2Init: Called");

    if (wccp2_connected == 1)
        return;

    wccp2_numrouters = 0;

    /* Calculate the number of routers configured in the config file */
    for (s = Config.Wccp2.router; s; s = s->next) {
        if (!s->s.isAnyAddr()) {
            /* Increment the counter */
            ++wccp2_numrouters;
        }
    }

    if (wccp2_numrouters == 0) {
        return;
    }

    struct wccp2_security_md5_t wccp2_security_md5;
    memset(&wccp2_security_md5, 0, sizeof(wccp2_security_md5));

    /* Initialise the list of services */
    wccp2InitServices();

    service_list_ptr = wccp2_service_list_head;

    while (service_list_ptr != NULL) {
        /* Set up our list pointers */
        router_list_ptr = &service_list_ptr->router_list_head;

        /* start the wccp header */
        wccp2_here_i_am_header.type = htonl(WCCP2_HERE_I_AM);
        wccp2_here_i_am_header.version = htons(WCCP2_VERSION);
        wccp2_here_i_am_header.length = 0;
        ptr = service_list_ptr->wccp_packet + sizeof(wccp2_here_i_am_header);

        /* add the security section */
        /* XXX this is ugly */

        if (service_list_ptr->wccp2_security_type == WCCP2_MD5_SECURITY) {
            wccp2_security_md5.security_option = htonl(WCCP2_MD5_SECURITY);

            wccp2_security_md5.security_length = htons(sizeof(struct wccp2_security_md5_t) - 4);
        } else if (service_list_ptr->wccp2_security_type == WCCP2_NO_SECURITY) {
            wccp2_security_md5.security_option = htonl(WCCP2_NO_SECURITY);
            /* XXX I hate magic length numbers! */
            wccp2_security_md5.security_length = htons(4);
        } else {
            fatalf("Bad WCCP2 security type\n");
        }

        wccp2_here_i_am_header.length += ntohs(wccp2_security_md5.security_length) + 4;
        assert(wccp2_here_i_am_header.length <= WCCP_RESPONSE_SIZE);
        wccp2_security_md5.security_type = htons(WCCP2_SECURITY_INFO);

        service_list_ptr->security_info = (struct wccp2_security_md5_t *) ptr;

        if (service_list_ptr->wccp2_security_type == WCCP2_MD5_SECURITY) {
            memcpy(ptr, &wccp2_security_md5, sizeof(struct wccp2_security_md5_t));
            ptr += sizeof(struct wccp2_security_md5_t);
        } else {
            /* assume NONE, and XXX I hate magic length numbers */
            memcpy(ptr, &wccp2_security_md5, 8);
            ptr += 8;
        }

        /* Add the service info section */

        wccp2_here_i_am_header.length += sizeof(struct wccp2_service_info_t);

        assert(wccp2_here_i_am_header.length <= WCCP_RESPONSE_SIZE);

        memcpy(ptr, &service_list_ptr->info, sizeof(struct wccp2_service_info_t));

        service_list_ptr->service_info = (struct wccp2_service_info_t *) ptr;

        ptr += sizeof(struct wccp2_service_info_t);

        /* Add the cache identity section */

        switch (Config.Wccp2.assignment_method) {

        case WCCP2_ASSIGNMENT_METHOD_HASH:

            wccp2_here_i_am_header.length += sizeof(struct wccp2_identity_info_t);
            assert(wccp2_here_i_am_header.length <= WCCP_RESPONSE_SIZE);
            wccp2_identity_info.cache_identity_type = htons(WCCP2_WC_ID_INFO);
            wccp2_identity_info.cache_identity_length = htons(sizeof(wccp2_identity_info.cache_identity));
            memset(&wccp2_identity_info.cache_identity.addr, '\0', sizeof(struct in_addr));
            memset(&wccp2_identity_info.cache_identity.hash_revision, '\0', sizeof(wccp2_identity_info.cache_identity.hash_revision));
            memset(&wccp2_identity_info.cache_identity.bits, '\0', sizeof(wccp2_identity_info.cache_identity.bits));
            memset(&wccp2_identity_info.cache_identity.buckets, '\0', sizeof(wccp2_identity_info.cache_identity.buckets));
            wccp2_identity_info.cache_identity.weight = htons(Config.Wccp2.weight);
            memset(&wccp2_identity_info.cache_identity.status, '\0', sizeof(wccp2_identity_info.cache_identity.status));

            memcpy(ptr, &wccp2_identity_info, sizeof(struct wccp2_identity_info_t));
            service_list_ptr->wccp2_identity_info_ptr = ptr;

            ptr += sizeof(struct wccp2_identity_info_t);
            break;

        case WCCP2_ASSIGNMENT_METHOD_MASK:

            wccp2_here_i_am_header.length += sizeof(struct wccp2_mask_identity_info_t);
            assert(wccp2_here_i_am_header.length <= WCCP_RESPONSE_SIZE);
            wccp2_mask_identity_info.cache_identity_type = htons(WCCP2_WC_ID_INFO);
            wccp2_mask_identity_info.cache_identity_length = htons(sizeof(wccp2_mask_identity_info.cache_identity));
            memset(&wccp2_mask_identity_info.cache_identity.addr, '\0', sizeof(struct in_addr));
            wccp2_mask_identity_info.cache_identity.bits = htons(WCCP2_MASK_ASSIGNMENT_DATA);
            wccp2_mask_identity_info.cache_identity.mask_element_count = htonl(1);
            service_flags = ntohl(service_list_ptr->service_info->service_flags);

            memset(&wccp2_mask_identity_info.cache_identity.mask, 0, sizeof(struct wccp2_mask_element_t));

            if ((service_flags & WCCP2_SERVICE_SRC_IP_HASH) || (service_flags & WCCP2_SERVICE_SRC_IP_ALT_HASH)) {
                wccp2_mask_identity_info.cache_identity.mask.source_ip_mask = htonl(0x00001741);
            } else if ((service_list_ptr->info.service == WCCP2_SERVICE_STANDARD) || (service_flags & WCCP2_SERVICE_DST_IP_HASH) || (service_flags & WCCP2_SERVICE_DST_IP_ALT_HASH)) {
                wccp2_mask_identity_info.cache_identity.mask.dest_ip_mask = htonl(0x00001741);
            } else if ((service_flags & WCCP2_SERVICE_SRC_PORT_HASH) || (service_flags & WCCP2_SERVICE_SRC_PORT_ALT_HASH)) {
                wccp2_mask_identity_info.cache_identity.mask.source_port_mask = htons(0x1741);
            } else if ((service_flags & WCCP2_SERVICE_DST_PORT_HASH) || (service_flags & WCCP2_SERVICE_DST_PORT_ALT_HASH)) {
                wccp2_mask_identity_info.cache_identity.mask.dest_port_mask = htons(0x1741);
            } else {
                fatalf("Unknown service hash method\n");
            }

            wccp2_mask_identity_info.cache_identity.weight = 0;
            wccp2_mask_identity_info.cache_identity.status = 0;

            memcpy(ptr, &wccp2_mask_identity_info, sizeof(struct wccp2_mask_identity_info_t));
            service_list_ptr->wccp2_identity_info_ptr = ptr;

            ptr += sizeof(struct wccp2_mask_identity_info_t);
            break;

        default:
            fatalf("Unknown Wccp2 assignment method\n");
        }

        /* Add the cache view section */
        wccp2_here_i_am_header.length += sizeof(wccp2_cache_view_header);

        assert(wccp2_here_i_am_header.length <= WCCP_RESPONSE_SIZE);

        wccp2_cache_view_header.cache_view_type = htons(WCCP2_WC_VIEW_INFO);

        wccp2_cache_view_header.cache_view_length = htons(sizeof(wccp2_cache_view_header) - 4 +
                sizeof(wccp2_cache_view_info) + (wccp2_numrouters * sizeof(wccp2_router_id_element_t)));

        wccp2_cache_view_header.cache_view_version = htonl(1);

        memcpy(ptr, &wccp2_cache_view_header, sizeof(wccp2_cache_view_header));

        ptr += sizeof(wccp2_cache_view_header);

        /* Add the number of routers to the packet */
        wccp2_here_i_am_header.length += sizeof(service_list_ptr->num_routers);

        assert(wccp2_here_i_am_header.length <= WCCP_RESPONSE_SIZE);

        service_list_ptr->num_routers = htonl(wccp2_numrouters);

        memcpy(ptr, &service_list_ptr->num_routers, sizeof(service_list_ptr->num_routers));

        ptr += sizeof(service_list_ptr->num_routers);

        /* Add each router.  Keep this functionality here to make sure the received_id can be updated in the packet */
        for (s = Config.Wccp2.router; s; s = s->next) {
            if (!s->s.isAnyAddr()) {

                wccp2_here_i_am_header.length += sizeof(struct wccp2_router_id_element_t);
                assert(wccp2_here_i_am_header.length <= WCCP_RESPONSE_SIZE);

                /* Add a pointer to the router list for this router */

                router_list_ptr->info = (struct wccp2_router_id_element_t *) ptr;
                s->s.getInAddr(router_list_ptr->info->router_address);
                router_list_ptr->info->received_id = htonl(0);
                s->s.getInAddr(router_list_ptr->router_sendto_address);
                router_list_ptr->member_change = htonl(0);

                /* Build the next struct */

                router_list_ptr->next = (wccp2_router_list_t*) xcalloc(1, sizeof(struct wccp2_router_list_t));

                /* update the pointer */
                router_list_ptr = router_list_ptr->next;
                router_list_ptr->next = NULL;

                /* no need to copy memory - we've just set the values directly in the packet above */

                ptr += sizeof(struct wccp2_router_id_element_t);
            }
        }

        /* Add the number of caches (0) */
        wccp2_here_i_am_header.length += sizeof(wccp2_cache_view_info.num_caches);

        assert(wccp2_here_i_am_header.length <= WCCP_RESPONSE_SIZE);

        wccp2_cache_view_info.num_caches = htonl(0);

        memcpy(ptr, &wccp2_cache_view_info.num_caches, sizeof(wccp2_cache_view_info.num_caches));

        ptr += sizeof(wccp2_cache_view_info.num_caches);

        /* Add the extra capability header */
        wccp2_here_i_am_header.length += sizeof(wccp2_capability_info_header);

        assert(wccp2_here_i_am_header.length <= WCCP_RESPONSE_SIZE);

        wccp2_capability_info_header.capability_info_type = htons(WCCP2_CAPABILITY_INFO);

        wccp2_capability_info_header.capability_info_length = htons(3 * sizeof(wccp2_capability_element));

        memcpy(ptr, &wccp2_capability_info_header, sizeof(wccp2_capability_info_header));

        ptr += sizeof(wccp2_capability_info_header);

        /* Add the forwarding method */
        wccp2_here_i_am_header.length += sizeof(wccp2_capability_element);

        assert(wccp2_here_i_am_header.length <= WCCP_RESPONSE_SIZE);

        wccp2_capability_element.capability_type = htons(WCCP2_CAPABILITY_FORWARDING_METHOD);

        wccp2_capability_element.capability_length = htons(sizeof(wccp2_capability_element.capability_value));

        wccp2_capability_element.capability_value = htonl(Config.Wccp2.forwarding_method);

        memcpy(ptr, &wccp2_capability_element, sizeof(wccp2_capability_element));

        ptr += sizeof(wccp2_capability_element);

        /* Add the assignment method */
        wccp2_here_i_am_header.length += sizeof(wccp2_capability_element);

        assert(wccp2_here_i_am_header.length <= WCCP_RESPONSE_SIZE);

        wccp2_capability_element.capability_type = htons(WCCP2_CAPABILITY_ASSIGNMENT_METHOD);

        wccp2_capability_element.capability_length = htons(sizeof(wccp2_capability_element.capability_value));

        wccp2_capability_element.capability_value = htonl(Config.Wccp2.assignment_method);

        memcpy(ptr, &wccp2_capability_element, sizeof(wccp2_capability_element));

        ptr += sizeof(wccp2_capability_element);

        /* Add the return method */
        wccp2_here_i_am_header.length += sizeof(wccp2_capability_element);

        assert(wccp2_here_i_am_header.length <= WCCP_RESPONSE_SIZE);

        wccp2_capability_element.capability_type = htons(WCCP2_CAPABILITY_RETURN_METHOD);

        wccp2_capability_element.capability_length = htons(sizeof(wccp2_capability_element.capability_value));

        wccp2_capability_element.capability_value = htonl(Config.Wccp2.return_method);

        memcpy(ptr, &wccp2_capability_element, sizeof(wccp2_capability_element));

        ptr += sizeof(wccp2_capability_element);

        /* Finally, fix the total length to network order, and copy to the appropriate memory blob */
        wccp2_here_i_am_header.length = htons(wccp2_here_i_am_header.length);

        memcpy(&service_list_ptr->wccp_packet, &wccp2_here_i_am_header, sizeof(wccp2_here_i_am_header));

        service_list_ptr->wccp_packet_size = ntohs(wccp2_here_i_am_header.length) + sizeof(wccp2_here_i_am_header);

        /* Add the event if everything initialised correctly */
        debugs(80,3,"wccp2Init: scheduled 'HERE_I_AM' message to " << wccp2_numrouters << "routers.");
        if (wccp2_numrouters) {
            if (!eventFind(wccp2HereIam, NULL)) {
                eventAdd("wccp2HereIam", wccp2HereIam, NULL, 1, 1);
            } else
                debugs(80,3,"wccp2Init: skip duplicate 'HERE_I_AM'.");
        }

        service_list_ptr = service_list_ptr->next;
    }
}

void
wccp2ConnectionOpen(void)
{
    struct sockaddr_in router, local, null;
    socklen_t local_len, router_len;

    struct wccp2_service_list_t *service_list_ptr;

    struct wccp2_router_list_t *router_list_ptr;

    debugs(80, 5, "wccp2ConnectionOpen: Called");

    if (wccp2_numrouters == 0 || !wccp2_service_list_head) {
        debugs(80, 2, "WCCPv2 Disabled. No IPv4 Router(s) configured.");
        return;
    }

    if ( !Config.Wccp2.address.setIPv4() ) {
        debugs(80, DBG_CRITICAL, "WCCPv2 Disabled. Local address " << Config.Wccp2.address << " is not an IPv4 address.");
        return;
    }

    Config.Wccp2.address.port(WCCP_PORT);
    theWccp2Connection = comm_open_listener(SOCK_DGRAM,
                                            0,
                                            Config.Wccp2.address,
                                            COMM_NONBLOCKING,
                                            "WCCPv2 Socket");

    if (theWccp2Connection < 0)
        fatal("Cannot open WCCP Port");

#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
    {
        int i = IP_PMTUDISC_DONT;
        if (setsockopt(theWccp2Connection, SOL_IP, IP_MTU_DISCOVER, &i, sizeof i) < 0) {
            int xerrno = errno;
            debugs(80, 2, "WARNING: Path MTU discovery could not be disabled on FD " << theWccp2Connection << ": " << xstrerr(xerrno));
        }
    }

#endif
    Comm::SetSelect(theWccp2Connection, COMM_SELECT_READ, wccp2HandleUdp, NULL, 0);

    debugs(80, DBG_IMPORTANT, "Accepting WCCPv2 messages on port " << WCCP_PORT << ", FD " << theWccp2Connection << ".");
    debugs(80, DBG_IMPORTANT, "Initialising all WCCPv2 lists");

    /* Initialise all routers on all services */
    memset(&null, 0, sizeof(null));

    null.sin_family = AF_UNSPEC;

    service_list_ptr = wccp2_service_list_head;

    while (service_list_ptr != NULL) {
        for (router_list_ptr = &service_list_ptr->router_list_head; router_list_ptr->next != NULL; router_list_ptr = router_list_ptr->next) {
            router_len = sizeof(router);
            memset(&router, '\0', router_len);
            router.sin_family = AF_INET;
            router.sin_port = htons(WCCP_PORT);
            router.sin_addr = router_list_ptr->router_sendto_address;

            if (connect(theWccp2Connection, (struct sockaddr *) &router, router_len))
                fatal("Unable to connect WCCP out socket");

            local_len = sizeof(local);

            memset(&local, '\0', local_len);

            if (getsockname(theWccp2Connection, (struct sockaddr *) &local, &local_len))
                fatal("Unable to getsockname on WCCP out socket");

            router_list_ptr->local_ip = local.sin_addr;

            /* Disconnect the sending socket. Note: FreeBSD returns error
             * but disconnects anyway so we have to just assume it worked
             */
            if (wccp2_numrouters > 1) {
                (void)connect(theWccp2Connection, (struct sockaddr *) &null, router_len);
            }
        }

        service_list_ptr = service_list_ptr->next;
    }

    wccp2_connected = 1;
}

void
wccp2ConnectionClose(void)
{

    struct wccp2_service_list_t *service_list_ptr;

    struct wccp2_service_list_t *service_list_ptr_next;

    struct wccp2_router_list_t *router_list_ptr;

    struct wccp2_router_list_t *router_list_next;

    struct wccp2_cache_list_t *cache_list_ptr;

    struct wccp2_cache_list_t *cache_list_ptr_next;

    if (wccp2_connected == 0) {
        return;
    }

    /* TODO A shutting-down cache should generate a removal query, informing the router
     * (and therefore the caches in the group) that this cache is going
     * away and no new traffic should be forwarded to it.
     */

    if (theWccp2Connection > -1) {
        debugs(80, DBG_IMPORTANT, "FD " << theWccp2Connection << " Closing WCCPv2 socket");
        comm_close(theWccp2Connection);
        theWccp2Connection = -1;
    }

    /* free all stored router state */
    service_list_ptr = wccp2_service_list_head;

    while (service_list_ptr != NULL) {
        for (router_list_ptr = &service_list_ptr->router_list_head; router_list_ptr != NULL; router_list_ptr = router_list_next) {
            for (cache_list_ptr = &router_list_ptr->cache_list_head; cache_list_ptr; cache_list_ptr = cache_list_ptr_next) {
                cache_list_ptr_next = cache_list_ptr->next;

                if (cache_list_ptr != &router_list_ptr->cache_list_head) {
                    xfree(cache_list_ptr);
                } else {

                    memset(cache_list_ptr, '\0', sizeof(struct wccp2_cache_list_t));
                }
            }

            router_list_next = router_list_ptr->next;

            if (router_list_ptr != &service_list_ptr->router_list_head) {
                xfree(router_list_ptr);
            } else {

                memset(router_list_ptr, '\0', sizeof(struct wccp2_router_list_t));
            }
        }

        service_list_ptr_next = service_list_ptr->next;
        xfree(service_list_ptr);
        service_list_ptr = service_list_ptr_next;
    }

    wccp2_service_list_head = NULL;
    eventDelete(wccp2HereIam, NULL);
    eventDelete(wccp2AssignBuckets, NULL);
    eventDelete(wccp2HereIam, NULL);
    wccp2_connected = 0;
}

/*
 * Functions for handling the requests.
 */

/*
 * Accept the UDP packet
 */
static void
wccp2HandleUdp(int sock, void *)
{
    struct wccp2_service_list_t *service_list_ptr;

    struct wccp2_router_list_t *router_list_ptr;

    struct wccp2_cache_list_t *cache_list_ptr;

    struct wccp2_cache_list_t *cache_list_ptr_next;

    /* These structs form the parts of the packet */

    struct wccp2_item_header_t *header = NULL;

    struct wccp2_security_none_t *security_info = NULL;

    struct wccp2_service_info_t *service_info = NULL;

    struct router_identity_info_t *router_identity_info = NULL;

    struct router_view_t *router_view_header = NULL;

    struct wccp2_cache_mask_identity_info_t *cache_mask_identity = NULL;

    struct cache_mask_info_t *cache_mask_info = NULL;

    struct wccp2_cache_identity_info_t *cache_identity = NULL;

    struct wccp2_capability_info_header_t *router_capability_header = NULL;

    struct wccp2_capability_element_t *router_capability_element;

    struct sockaddr_in from;

    struct in_addr cache_address;
    int len, found;
    short int data_length, offset;
    uint32_t tmp;
    char *ptr;
    int num_caches;

    debugs(80, 6, "wccp2HandleUdp: Called.");

    Comm::SetSelect(sock, COMM_SELECT_READ, wccp2HandleUdp, NULL, 0);

    // TODO: drop conversion boundary
    Ip::Address from_tmp;
    from_tmp.setIPv4();

    len = comm_udp_recvfrom(sock,
                            &wccp2_i_see_you,
                            WCCP_RESPONSE_SIZE,
                            0,
                            from_tmp);

    if (len < 0)
        return;

    if (ntohs(wccp2_i_see_you.version) != WCCP2_VERSION)
        return;

    if (ntohl(wccp2_i_see_you.type) != WCCP2_I_SEE_YOU)
        return;

    // XXX: drop conversion boundary
    from_tmp.getSockAddr(from);

    debugs(80, 3, "Incoming WCCPv2 I_SEE_YOU length " << ntohs(wccp2_i_see_you.length) << ".");

    /* Record the total data length */
    data_length = ntohs(wccp2_i_see_you.length);

    offset = 0;

    if (data_length > len) {
        debugs(80, DBG_IMPORTANT, "ERROR: Malformed WCCPv2 packet claiming it's bigger than received data");
        return;
    }

    /* Go through the data structure */
    while (data_length > offset) {

        char *data = wccp2_i_see_you.data;

        header = (struct wccp2_item_header_t *) &data[offset];

        switch (ntohs(header->type)) {

        case WCCP2_SECURITY_INFO:

            if (security_info != NULL) {
                debugs(80, DBG_IMPORTANT, "Duplicate security definition");
                return;
            }

            security_info = (struct wccp2_security_none_t *) &wccp2_i_see_you.data[offset];
            break;

        case WCCP2_SERVICE_INFO:

            if (service_info != NULL) {
                debugs(80, DBG_IMPORTANT, "Duplicate service_info definition");
                return;
            }

            service_info = (struct wccp2_service_info_t *) &wccp2_i_see_you.data[offset];
            break;

        case WCCP2_ROUTER_ID_INFO:

            if (router_identity_info != NULL) {
                debugs(80, DBG_IMPORTANT, "Duplicate router_identity_info definition");
                return;
            }

            router_identity_info = (struct router_identity_info_t *) &wccp2_i_see_you.data[offset];
            break;

        case WCCP2_RTR_VIEW_INFO:

            if (router_view_header != NULL) {
                debugs(80, DBG_IMPORTANT, "Duplicate router_view definition");
                return;
            }

            router_view_header = (struct router_view_t *) &wccp2_i_see_you.data[offset];
            break;

        case WCCP2_CAPABILITY_INFO:

            if (router_capability_header != NULL) {
                debugs(80, DBG_IMPORTANT, "Duplicate router_capability definition");
                return;
            }

            router_capability_header = (struct wccp2_capability_info_header_t *) &wccp2_i_see_you.data[offset];
            break;

        /* Nothing to do for the types below */

        case WCCP2_ASSIGN_MAP:
        case WCCP2_REDIRECT_ASSIGNMENT:
            break;

        default:
            debugs(80, DBG_IMPORTANT, "Unknown record type in WCCPv2 Packet (" << ntohs(header->type) << ").");
        }

        offset += sizeof(struct wccp2_item_header_t);
        offset += ntohs(header->length);

        if (offset > data_length) {
            debugs(80, DBG_IMPORTANT, "Error: WCCPv2 packet tried to tell us there is data beyond the end of the packet");
            return;
        }
    }

    if ((security_info == NULL) || (service_info == NULL) || (router_identity_info == NULL) || (router_view_header == NULL)) {
        debugs(80, DBG_IMPORTANT, "Incomplete WCCPv2 Packet");
        return;
    }

    debugs(80, 5, "Complete packet received");

    /* Check that the service in the packet is configured on this router */
    service_list_ptr = wccp2_service_list_head;

    while (service_list_ptr != NULL) {
        if (service_info->service_id == service_list_ptr->service_info->service_id) {
            break;
        }

        service_list_ptr = service_list_ptr->next;
    }

    if (service_list_ptr == NULL) {
        debugs(80, DBG_IMPORTANT, "WCCPv2 Unknown service received from router (" << service_info->service_id << ")");
        return;
    }

    if (ntohl(security_info->security_option) != ntohl(service_list_ptr->security_info->security_option)) {
        debugs(80, DBG_IMPORTANT, "Invalid security option in WCCPv2 Packet (" << ntohl(security_info->security_option) << " vs " << ntohl(service_list_ptr->security_info->security_option) << ").");
        return;
    }

    if (!wccp2_check_security(service_list_ptr, (char *) security_info, (char *) &wccp2_i_see_you, len)) {
        debugs(80, DBG_IMPORTANT, "Received WCCPv2 Packet failed authentication");
        return;
    }

    /* Check that the router address is configured on this router */
    for (router_list_ptr = &service_list_ptr->router_list_head; router_list_ptr->next != NULL; router_list_ptr = router_list_ptr->next) {
        if (router_list_ptr->router_sendto_address.s_addr == from.sin_addr.s_addr)
            break;
    }

    if (router_list_ptr->next == NULL) {
        debugs(80, DBG_IMPORTANT, "WCCPv2 Packet received from unknown router");
        return;
    }

    /* Set the router id */
    router_list_ptr->info->router_address = router_identity_info->router_id_element.router_address;

    /* Increment the received id in the packet */
    if (ntohl(router_list_ptr->info->received_id) != ntohl(router_identity_info->router_id_element.received_id)) {
        debugs(80, 3, "Incoming WCCP2_I_SEE_YOU Received ID old=" << ntohl(router_list_ptr->info->received_id) << " new=" << ntohl(router_identity_info->router_id_element.received_id) << ".");
        router_list_ptr->info->received_id = router_identity_info->router_id_element.received_id;
    }

    /* TODO: check return/forwarding methods */
    if (router_capability_header == NULL) {
        if ((Config.Wccp2.return_method != WCCP2_PACKET_RETURN_METHOD_GRE) || (Config.Wccp2.forwarding_method != WCCP2_FORWARDING_METHOD_GRE)) {
            debugs(80, DBG_IMPORTANT, "wccp2HandleUdp: fatal error - A WCCP router does not support the forwarding method specified, only GRE supported");
            wccp2ConnectionClose();
            return;
        }
    } else {

        char *end = ((char *) router_capability_header) + sizeof(*router_capability_header) + ntohs(router_capability_header->capability_info_length) - sizeof(struct wccp2_capability_info_header_t);

        router_capability_element = (struct wccp2_capability_element_t *) (((char *) router_capability_header) + sizeof(*router_capability_header));

        while ((char *) router_capability_element <= end) {

            switch (ntohs(router_capability_element->capability_type)) {

            case WCCP2_CAPABILITY_FORWARDING_METHOD:

                if (!(ntohl(router_capability_element->capability_value) & Config.Wccp2.forwarding_method)) {
                    debugs(80, DBG_IMPORTANT, "wccp2HandleUdp: fatal error - A WCCP router has specified a different forwarding method " << ntohl(router_capability_element->capability_value) << ", expected " << Config.Wccp2.forwarding_method);
                    wccp2ConnectionClose();
                    return;
                }

                break;

            case WCCP2_CAPABILITY_ASSIGNMENT_METHOD:

                if (!(ntohl(router_capability_element->capability_value) & Config.Wccp2.assignment_method)) {
                    debugs(80, DBG_IMPORTANT, "wccp2HandleUdp: fatal error - A WCCP router has specified a different assignment method " << ntohl(router_capability_element->capability_value) << ", expected "<< Config.Wccp2.assignment_method);
                    wccp2ConnectionClose();
                    return;
                }

                break;

            case WCCP2_CAPABILITY_RETURN_METHOD:

                if (!(ntohl(router_capability_element->capability_value) & Config.Wccp2.return_method)) {
                    debugs(80, DBG_IMPORTANT, "wccp2HandleUdp: fatal error - A WCCP router has specified a different return method " << ntohl(router_capability_element->capability_value) << ", expected " << Config.Wccp2.return_method);
                    wccp2ConnectionClose();
                    return;
                }

                break;

            case 4:
            case 5:
                break; // ignore silently for now

            default:
                debugs(80, DBG_IMPORTANT, "Unknown capability type in WCCPv2 Packet (" << ntohs(router_capability_element->capability_type) << ").");
            }

            router_capability_element = (struct wccp2_capability_element_t *) (((char *) router_capability_element) + sizeof(struct wccp2_item_header_t) + ntohs(router_capability_element->capability_length));
        }
    }

    debugs(80, 5, "Cleaning out cache list");
    /* clean out the old cache list */

    for (cache_list_ptr = &router_list_ptr->cache_list_head; cache_list_ptr; cache_list_ptr = cache_list_ptr_next) {
        cache_list_ptr_next = cache_list_ptr->next;

        if (cache_list_ptr != &router_list_ptr->cache_list_head) {
            xfree(cache_list_ptr);
        }
    }

    router_list_ptr->num_caches = htonl(0);
    num_caches = 0;

    /* Check to see if we're the master cache and update the cache list */
    found = 0;
    service_list_ptr->lowest_ip = 1;
    cache_list_ptr = &router_list_ptr->cache_list_head;

    /* to find the list of caches, we start at the end of the router view header */

    ptr = (char *) (router_view_header) + sizeof(struct router_view_t);

    /* Then we read the number of routers */
    memcpy(&tmp, ptr, sizeof(tmp));

    /* skip the number plus all the ip's */

    ptr += sizeof(tmp) + (ntohl(tmp) * sizeof(struct in_addr));

    /* Then read the number of caches */
    memcpy(&tmp, ptr, sizeof(tmp));
    ptr += sizeof(tmp);

    if (ntohl(tmp) != 0) {
        /* search through the list of received-from ip addresses */

        for (num_caches = 0; num_caches < (int) ntohl(tmp); ++num_caches) {
            /* Get a copy of the ip */
            memset(&cache_address, 0, sizeof(cache_address)); // Make GCC happy

            switch (Config.Wccp2.assignment_method) {

            case WCCP2_ASSIGNMENT_METHOD_HASH:

                cache_identity = (struct wccp2_cache_identity_info_t *) ptr;

                ptr += sizeof(struct wccp2_cache_identity_info_t);

                memcpy(&cache_address, &cache_identity->addr, sizeof(struct in_addr));

                cache_list_ptr->weight = ntohs(cache_identity->weight);
                break;

            case WCCP2_ASSIGNMENT_METHOD_MASK:

                cache_mask_info = (struct cache_mask_info_t *) ptr;

                /* The mask assignment has an undocumented variable length entry here */

                if (ntohl(cache_mask_info->num1) == 3) {

                    cache_mask_identity = (struct wccp2_cache_mask_identity_info_t *) ptr;

                    ptr += sizeof(struct wccp2_cache_mask_identity_info_t);

                    memcpy(&cache_address, &cache_mask_identity->addr, sizeof(struct in_addr));
                } else {

                    ptr += sizeof(struct cache_mask_info_t);

                    memcpy(&cache_address, &cache_mask_info->addr, sizeof(struct in_addr));
                }

                cache_list_ptr->weight = 0;
                break;

            default:
                fatalf("Unknown Wccp2 assignment method\n");
            }

            /* Update the cache list */
            cache_list_ptr->cache_ip = cache_address;

            cache_list_ptr->next = (wccp2_cache_list_t*) xcalloc(1, sizeof(struct wccp2_cache_list_t));

            cache_list_ptr = cache_list_ptr->next;

            cache_list_ptr->next = NULL;

            debugs (80, 5,  "checking cache list: (" << std::hex << cache_address.s_addr << ":" <<  router_list_ptr->local_ip.s_addr << ")");

            /* Check to see if it's the master, or us */

            if (cache_address.s_addr == router_list_ptr->local_ip.s_addr) {
                found = 1;
            }

            if (cache_address.s_addr < router_list_ptr->local_ip.s_addr) {
                service_list_ptr->lowest_ip = 0;
            }
        }
    } else {
        debugs(80, 5, "Adding ourselves as the only cache");

        /* Update the cache list */
        cache_list_ptr->cache_ip = router_list_ptr->local_ip;

        cache_list_ptr->next = (wccp2_cache_list_t*) xcalloc(1, sizeof(struct wccp2_cache_list_t));
        cache_list_ptr = cache_list_ptr->next;
        cache_list_ptr->next = NULL;

        service_list_ptr->lowest_ip = 1;
        found = 1;
        num_caches = 1;
    }

    wccp2SortCacheList(&router_list_ptr->cache_list_head);

    router_list_ptr->num_caches = htonl(num_caches);

    if ((found == 1) && (service_list_ptr->lowest_ip == 1)) {
        if (ntohl(router_view_header->change_number) != router_list_ptr->member_change) {
            debugs(80, 4, "Change detected - queueing up new assignment");
            router_list_ptr->member_change = ntohl(router_view_header->change_number);
            eventDelete(wccp2AssignBuckets, NULL);
            eventAdd("wccp2AssignBuckets", wccp2AssignBuckets, NULL, 15.0, 1);
        } else {
            debugs(80, 5, "Change not detected (" << ntohl(router_view_header->change_number) << " = " << router_list_ptr->member_change << ")");
        }
    } else {
        eventDelete(wccp2AssignBuckets, NULL);
        debugs(80, 5, "I am not the lowest ip cache - not assigning buckets");
    }
}

static void
wccp2HereIam(void *)
{
    struct wccp2_service_list_t *service_list_ptr;

    struct wccp2_router_list_t *router_list_ptr;

    struct wccp2_identity_info_t *wccp2_identity_info_ptr;

    struct wccp2_mask_identity_info_t *wccp2_mask_identity_info_ptr;

    Ip::Address router;

    debugs(80, 6, "wccp2HereIam: Called");

    if (wccp2_connected == 0) {
        debugs(80, DBG_IMPORTANT, "wccp2HereIam: wccp2 socket closed.  Shutting down WCCP2");
        return;
    }

    /* Wait if store dirs are rebuilding */
    if (StoreController::store_dirs_rebuilding && Config.Wccp2.rebuildwait) {
        eventAdd("wccp2HereIam", wccp2HereIam, NULL, 1.0, 1);
        return;
    }

    router.port(WCCP_PORT);

    /* for each router on each service send a packet */
    service_list_ptr = wccp2_service_list_head;

    while (service_list_ptr != NULL) {
        debugs(80, 5, "wccp2HereIam: sending to service id " << service_list_ptr->info.service_id);

        for (router_list_ptr = &service_list_ptr->router_list_head; router_list_ptr->next != NULL; router_list_ptr = router_list_ptr->next) {
            router = router_list_ptr->router_sendto_address;

            /* Set the cache id (ip) */

            switch (Config.Wccp2.assignment_method) {

            case WCCP2_ASSIGNMENT_METHOD_HASH:

                wccp2_identity_info_ptr = (struct wccp2_identity_info_t *) service_list_ptr->wccp2_identity_info_ptr;
                wccp2_identity_info_ptr->cache_identity.addr = router_list_ptr->local_ip;
                break;

            case WCCP2_ASSIGNMENT_METHOD_MASK:

                wccp2_mask_identity_info_ptr = (struct wccp2_mask_identity_info_t *) service_list_ptr->wccp2_identity_info_ptr;
                wccp2_mask_identity_info_ptr->cache_identity.addr = router_list_ptr->local_ip;
                break;

            default:
                fatalf("Unknown Wccp2 assignment method\n");
            }

            /* Security update, if needed */

            if (service_list_ptr->wccp2_security_type == WCCP2_MD5_SECURITY) {
                wccp2_update_md5_security(service_list_ptr->wccp_password, (char *) service_list_ptr->security_info, service_list_ptr->wccp_packet, service_list_ptr->wccp_packet_size);
            }

            debugs(80, 3, "Sending HereIam packet size " << service_list_ptr->wccp_packet_size);
            /* Send the packet */

            if (wccp2_numrouters > 1) {
                comm_udp_sendto(theWccp2Connection,
                                router,
                                &service_list_ptr->wccp_packet,
                                service_list_ptr->wccp_packet_size);
            } else {
                if (send(theWccp2Connection, &service_list_ptr->wccp_packet, service_list_ptr->wccp_packet_size, 0) < static_cast<int>(service_list_ptr->wccp_packet_size)) {
                    int xerrno = errno;
                    debugs(80, 2, "ERROR: failed to send WCCPv2 HERE_I_AM packet to " << router << " : " << xstrerr(xerrno));
                }
            }
        }

        service_list_ptr = service_list_ptr->next;
    }

    eventAdd("wccp2HereIam", wccp2HereIam, NULL, 10.0, 1);
}

static void
wccp2AssignBuckets(void *)
{
    struct wccp2_service_list_t *service_list_ptr;

    struct wccp2_router_list_t *router_list_ptr;

    struct wccp2_cache_list_t *cache_list_ptr;
    char wccp_packet[WCCP_RESPONSE_SIZE];
    short int offset, saved_offset, assignment_offset, alt_assignment_offset;

    struct sockaddr_in router;
    int router_len;
    int bucket_counter;
    uint32_t service_flags;
    unsigned short port = WCCP_PORT;

    /* Packet segments */

    struct wccp2_message_header_t *main_header;

    struct wccp2_security_md5_t *security = NULL;
    /* service from service struct */

    struct wccp2_item_header_t *assignment_header;

    struct wccp2_item_header_t *alt_assignment_type_header = NULL;

    struct assignment_key_t *assignment_key;
    /* number of routers */

    struct wccp2_router_assign_element_t *router_assign;
    /* number of caches */

    struct in_addr *cache_address;
    /* Alternative assignement mask/values */
    int num_maskval;

    struct wccp2_mask_element_t *mask_element;

    struct wccp2_value_element_t *value_element;
    int valuecounter, value;
    char *buckets;

    assignment_offset = alt_assignment_offset = 0;

    router_len = sizeof(router);
    memset(&router, '\0', router_len);
    router.sin_family = AF_INET;
    router.sin_port = htons(port);

    /* Start main header - fill in length later */
    offset = 0;

    main_header = (struct wccp2_message_header_t *) &wccp_packet[offset];
    main_header->type = htonl(WCCP2_REDIRECT_ASSIGN);
    main_header->version = htons(WCCP2_VERSION);

    debugs(80, 2, "Running wccp2AssignBuckets");
    service_list_ptr = wccp2_service_list_head;

    while (service_list_ptr != NULL) {
        /* If we're not the lowest, we don't need to worry */

        if (service_list_ptr->lowest_ip == 0) {
            /* XXX eww */
            service_list_ptr = service_list_ptr->next;
            continue;
        }

        /* reset the offset */

        offset = sizeof(struct wccp2_message_header_t);

        /* build packet header from hereIam packet */
        /* Security info */
        /* XXX this should be made more generic! */
        /* XXX and I hate magic numbers! */
        switch (service_list_ptr->wccp2_security_type) {

        case WCCP2_NO_SECURITY:

            security = (struct wccp2_security_md5_t *) &wccp_packet[offset];
            memcpy(security, service_list_ptr->security_info, 8);
            offset += 8;
            break;

        case WCCP2_MD5_SECURITY:

            security = (struct wccp2_security_md5_t *) &wccp_packet[offset];

            memcpy(security, service_list_ptr->security_info, sizeof(struct wccp2_security_md5_t));

            offset += sizeof(struct wccp2_security_md5_t);
            break;

        default:
            fatalf("Unknown Wccp2 security type\n");
        }

        /* Service info */

        memcpy(&wccp_packet[offset], service_list_ptr->service_info, sizeof(struct wccp2_service_info_t));

        offset += sizeof(struct wccp2_service_info_t);

        /* assignment header - fill in length later */

        assignment_header = (struct wccp2_item_header_t *) &wccp_packet[offset];

        switch (Config.Wccp2.assignment_method) {

        case WCCP2_ASSIGNMENT_METHOD_HASH:
            assignment_header->type = htons(WCCP2_REDIRECT_ASSIGNMENT);

            offset += sizeof(struct wccp2_item_header_t);
            assignment_offset = offset;
            break;

        case WCCP2_ASSIGNMENT_METHOD_MASK:
            assignment_header->type = htons(WCCP2_ALT_ASSIGNMENT);

            offset += sizeof(struct wccp2_item_header_t);
            assignment_offset = offset;

            /* The alternative assignment has an extra header, fill in length later */

            alt_assignment_type_header = (struct wccp2_item_header_t *) &wccp_packet[offset];
            alt_assignment_type_header->type = htons(WCCP2_MASK_ASSIGNMENT);

            offset += sizeof(struct wccp2_item_header_t);
            alt_assignment_offset = offset;

            break;

        default:
            fatalf("Unknown Wccp2 assignment method\n");
        }

        /* Assignment key - fill in master ip later */

        assignment_key = (struct assignment_key_t *) &wccp_packet[offset];

        ++service_list_ptr->change_num;
        assignment_key->master_number = htonl(service_list_ptr->change_num);

        offset += sizeof(struct assignment_key_t);

        /* Number of routers */
        memcpy(&wccp_packet[offset], &service_list_ptr->num_routers, sizeof(service_list_ptr->num_routers));

        offset += sizeof(service_list_ptr->num_routers);

        for (router_list_ptr = &service_list_ptr->router_list_head; router_list_ptr->next != NULL; router_list_ptr = router_list_ptr->next) {

            /* Add routers */

            router_assign = (struct wccp2_router_assign_element_t *) &wccp_packet[offset];
            router_assign->router_address = router_list_ptr->info->router_address;
            router_assign->received_id = router_list_ptr->info->received_id;
            router_assign->change_number = htonl(router_list_ptr->member_change);

            offset += sizeof(struct wccp2_router_assign_element_t);
        }

        saved_offset = offset;

        for (router_list_ptr = &service_list_ptr->router_list_head; router_list_ptr->next != NULL; router_list_ptr = router_list_ptr->next) {
            unsigned long *weight = (unsigned long *)xcalloc(sizeof(*weight), ntohl(router_list_ptr->num_caches));
            unsigned long total_weight = 0;
            int num_caches = ntohl(router_list_ptr->num_caches);

            offset = saved_offset;

            switch (Config.Wccp2.assignment_method) {

            case WCCP2_ASSIGNMENT_METHOD_HASH:
                /* Number of caches */
                memcpy(&wccp_packet[offset], &router_list_ptr->num_caches, sizeof(router_list_ptr->num_caches));
                offset += sizeof(router_list_ptr->num_caches);

                if (num_caches) {
                    int cache;

                    for (cache = 0, cache_list_ptr = &router_list_ptr->cache_list_head; cache_list_ptr->next; cache_list_ptr = cache_list_ptr->next, ++cache) {
                        /* add caches */

                        cache_address = (struct in_addr *) &wccp_packet[offset];

                        memcpy(cache_address, &cache_list_ptr->cache_ip, sizeof(struct in_addr));
                        total_weight += cache_list_ptr->weight << 12;
                        weight[cache] = cache_list_ptr->weight << 12;

                        offset += sizeof(struct in_addr);
                    }
                }

                /* Add buckets */
                buckets = (char *) &wccp_packet[offset];

                memset(buckets, '\0', WCCP_BUCKETS);

                if (num_caches != 0) {
                    if (total_weight == 0) {
                        for (bucket_counter = 0; bucket_counter < WCCP_BUCKETS; ++bucket_counter) {
                            buckets[bucket_counter] = (char) (bucket_counter % num_caches);
                        }
                    } else {
                        unsigned long *assigned = (unsigned long *)xcalloc(sizeof(*assigned), num_caches);
                        unsigned long done = 0;
                        int cache = -1;
                        unsigned long per_bucket = total_weight / WCCP_BUCKETS;

                        for (bucket_counter = 0; bucket_counter < WCCP_BUCKETS; ++bucket_counter) {
                            int n;
                            unsigned long step;

                            for (n = num_caches; n; --n) {
                                ++cache;

                                if (cache >= num_caches)
                                    cache = 0;

                                if (!weight[cache]) {
                                    ++n;
                                    continue;
                                }

                                if (assigned[cache] <= done)
                                    break;
                            }

                            buckets[bucket_counter] = (char) cache;
                            step = per_bucket * total_weight / weight[cache];
                            assigned[cache] += step;
                            done += per_bucket;
                        }

                        safe_free(assigned);
                    }
                }

                offset += (WCCP_BUCKETS * sizeof(char));
                safe_free(weight);
                break;

            case WCCP2_ASSIGNMENT_METHOD_MASK:
                num_maskval = htonl(1);
                memcpy(&wccp_packet[offset], &num_maskval, sizeof(int));
                offset += sizeof(int);

                mask_element = (struct wccp2_mask_element_t *) &wccp_packet[offset];
                service_flags = ntohl(service_list_ptr->service_info->service_flags);

                if ((service_flags & WCCP2_SERVICE_SRC_IP_HASH) || (service_flags & WCCP2_SERVICE_SRC_IP_ALT_HASH)) {
                    mask_element->source_ip_mask = htonl(0x00001741);
                    mask_element->dest_ip_mask = 0;
                    mask_element->source_port_mask = 0;
                    mask_element->dest_port_mask = 0;
                } else if ((service_list_ptr->info.service == WCCP2_SERVICE_STANDARD) || (service_flags & WCCP2_SERVICE_DST_IP_HASH) || (service_flags & WCCP2_SERVICE_DST_IP_ALT_HASH)) {
                    mask_element->source_ip_mask = 0;
                    mask_element->dest_ip_mask = htonl(0x00001741);
                    mask_element->source_port_mask = 0;
                    mask_element->dest_port_mask = 0;
                } else if ((service_flags & WCCP2_SERVICE_SRC_PORT_HASH) || (service_flags & WCCP2_SERVICE_SRC_PORT_ALT_HASH)) {
                    mask_element->source_ip_mask = 0;
                    mask_element->dest_ip_mask = 0;
                    mask_element->source_port_mask = htons(0x1741);
                    mask_element->dest_port_mask = 0;
                } else if ((service_flags & WCCP2_SERVICE_DST_PORT_HASH) || (service_flags & WCCP2_SERVICE_DST_PORT_ALT_HASH)) {
                    mask_element->source_ip_mask = 0;
                    mask_element->dest_ip_mask = 0;
                    mask_element->source_port_mask = 0;
                    mask_element->dest_port_mask = htons(0x1741);
                } else {
                    fatalf("Unknown service hash method\n");
                }

                mask_element->number_values = htonl(64);

                offset += sizeof(struct wccp2_mask_element_t);

                cache_list_ptr = &router_list_ptr->cache_list_head;
                value = 0;

                for (valuecounter = 0; valuecounter < 64; ++valuecounter) {

                    value_element = (struct wccp2_value_element_t *) &wccp_packet[offset];

                    /* Update the value according the the "correct" formula */

                    for (; (value & 0x1741) != value; ++value) {
                        assert(value <= 0x1741);
                    }

                    if ((service_flags & WCCP2_SERVICE_SRC_IP_HASH) || (service_flags & WCCP2_SERVICE_SRC_IP_ALT_HASH)) {
                        value_element->source_ip_value = htonl(value);
                        value_element->dest_ip_value = 0;
                        value_element->source_port_value = 0;
                        value_element->dest_port_value = 0;
                    } else if ((service_list_ptr->info.service == WCCP2_SERVICE_STANDARD) || (service_flags & WCCP2_SERVICE_DST_IP_HASH) || (service_flags & WCCP2_SERVICE_DST_IP_ALT_HASH)) {
                        value_element->source_ip_value = 0;
                        value_element->dest_ip_value = htonl(value);
                        value_element->source_port_value = 0;
                        value_element->dest_port_value = 0;
                    } else if ((service_flags & WCCP2_SERVICE_SRC_PORT_HASH) || (service_flags & WCCP2_SERVICE_SRC_PORT_ALT_HASH)) {
                        value_element->source_ip_value = 0;
                        value_element->dest_ip_value = 0;
                        value_element->source_port_value = htons(value);
                        value_element->dest_port_value = 0;
                    } else if ((service_flags & WCCP2_SERVICE_DST_PORT_HASH) || (service_flags & WCCP2_SERVICE_DST_PORT_ALT_HASH)) {
                        value_element->source_ip_value = 0;
                        value_element->dest_ip_value = 0;
                        value_element->source_port_value = 0;
                        value_element->dest_port_value = htons(value);
                    } else {
                        fatalf("Unknown service hash method\n");
                    }

                    value_element->cache_ip = cache_list_ptr->cache_ip;

                    offset += sizeof(struct wccp2_value_element_t);
                    ++value;

                    /* Assign the next value to the next cache */

                    if ((cache_list_ptr->next) && (cache_list_ptr->next->next))
                        cache_list_ptr = cache_list_ptr->next;
                    else
                        cache_list_ptr = &router_list_ptr->cache_list_head;
                }

                /* Fill in length */
                alt_assignment_type_header->length = htons(offset - alt_assignment_offset);

                break;

            default:
                fatalf("Unknown Wccp2 assignment method\n");
            }

            /* Fill in length */

            assignment_header->length = htons(offset - assignment_offset);

            /* Fill in assignment key */
            assignment_key->master_ip = router_list_ptr->local_ip;

            /* finish length */

            main_header->length = htons(offset - sizeof(struct wccp2_message_header_t));

            /* set the destination address */
            router.sin_addr = router_list_ptr->router_sendto_address;

            /* Security update, if needed */

            if (service_list_ptr->wccp2_security_type == WCCP2_MD5_SECURITY) {
                wccp2_update_md5_security(service_list_ptr->wccp_password, (char *) security, wccp_packet, offset);
            }

            if (ntohl(router_list_ptr->num_caches)) {
                /* send packet */

                // XXX: drop temp conversion
                Ip::Address tmp_rtr(router);

                if (wccp2_numrouters > 1) {
                    comm_udp_sendto(theWccp2Connection,
                                    tmp_rtr,
                                    &wccp_packet,
                                    offset);
                } else {
                    if (send(theWccp2Connection, &wccp_packet, offset, 0) < static_cast<int>(offset)) {
                        int xerrno = errno;
                        debugs(80, 2, "ERROR: failed to send WCCPv2 HERE_I_AM packet to " << tmp_rtr << " : " << xstrerr(xerrno));
                    }
                }
            }
            safe_free(weight);
        }

        service_list_ptr = service_list_ptr->next;
    }
}

/*
 * Configuration option parsing code
 */

/**
 * Parse wccp2_return_method and wccp2_forwarding_method options
 * they can be '1' aka 'gre' or  '2' aka 'l2'
 * repesenting the integer numeric of the same.
 */
void
parse_wccp2_method(int *method)
{
    char *t;

    /* Snarf the method */
    if ((t = ConfigParser::NextToken()) == NULL) {
        debugs(80, DBG_CRITICAL, "wccp2_*_method: missing setting.");
        self_destruct();
        return;
    }

    /* update configuration if its valid */
    if (strcmp(t, "gre") == 0 || strcmp(t, "1") == 0) {
        *method = WCCP2_METHOD_GRE;
    } else if (strcmp(t, "l2") == 0 || strcmp(t, "2") == 0) {
        *method = WCCP2_METHOD_L2;
    } else {
        debugs(80, DBG_CRITICAL, "wccp2_*_method: unknown setting, got " << t );
        self_destruct();
    }
}

void
dump_wccp2_method(StoreEntry * e, const char *label, int v)
{
    switch (v) {
    case WCCP2_METHOD_GRE:
        storeAppendPrintf(e, "%s gre\n", label);
        break;
    case WCCP2_METHOD_L2:
        storeAppendPrintf(e, "%s l2\n", label);
        break;
    default:
        debugs(80, DBG_CRITICAL, "FATAL: WCCPv2 configured method (" << v << ") is not valid.");
        self_destruct();
    }
}

void
free_wccp2_method(int *)
{ }

/**
 * Parse wccp2_assignment_method option
 * they can be '1' aka 'hash' or  '2' aka 'mask'
 * repesenting the integer numeric of the same.
 */
void
parse_wccp2_amethod(int *method)
{
    char *t;

    /* Snarf the method */
    if ((t = ConfigParser::NextToken()) == NULL) {
        debugs(80, DBG_CRITICAL, "wccp2_assignment_method: missing setting.");
        self_destruct();
        return;
    }

    /* update configuration if its valid */
    if (strcmp(t, "hash") == 0 || strcmp(t, "1") == 0) {
        *method = WCCP2_ASSIGNMENT_METHOD_HASH;
    } else if (strcmp(t, "mask") == 0 || strcmp(t, "2") == 0) {
        *method = WCCP2_ASSIGNMENT_METHOD_MASK;
    } else {
        debugs(80, DBG_CRITICAL, "wccp2_assignment_method: unknown setting, got " << t );
        self_destruct();
    }
}

void
dump_wccp2_amethod(StoreEntry * e, const char *label, int v)
{
    switch (v) {
    case WCCP2_ASSIGNMENT_METHOD_HASH:
        storeAppendPrintf(e, "%s hash\n", label);
        break;
    case WCCP2_ASSIGNMENT_METHOD_MASK:
        storeAppendPrintf(e, "%s mask\n", label);
        break;
    default:
        debugs(80, DBG_CRITICAL, "FATAL: WCCPv2 configured " << label << " (" << v << ") is not valid.");
        self_destruct();
    }
}

void
free_wccp2_amethod(int *)
{}

/*
 * Format:
 *
 * wccp2_service {standard|dynamic} {id} (password=password)
 */
void
parse_wccp2_service(void *)
{
    char *t;
    int service = 0;
    int service_id = 0;
    int security_type = WCCP2_NO_SECURITY;
    char wccp_password[WCCP2_PASSWORD_LEN];

    if (wccp2_connected == 1) {
        debugs(80, DBG_IMPORTANT, "WCCPv2: Somehow reparsing the configuration without having shut down WCCP! Try reloading squid again.");
        return;
    }

    /* Snarf the type */
    if ((t = ConfigParser::NextToken()) == NULL) {
        debugs(80, DBG_CRITICAL, "wccp2ParseServiceInfo: missing service info type (standard|dynamic)");
        self_destruct();
        return;
    }

    if (strcmp(t, "standard") == 0) {
        service = WCCP2_SERVICE_STANDARD;
    } else if (strcmp(t, "dynamic") == 0) {
        service = WCCP2_SERVICE_DYNAMIC;
    } else {
        debugs(80, DBG_CRITICAL, "wccp2ParseServiceInfo: bad service info type (expected standard|dynamic, got " << t << ")");
        self_destruct();
        return;
    }

    /* Snarf the ID */
    service_id = GetInteger();

    if (service_id < 0 || service_id > 255) {
        debugs(80, DBG_CRITICAL, "ERROR: invalid WCCP service id " << service_id << " (must be between 0 .. 255)");
        self_destruct();
        return;
    }

    memset(wccp_password, 0, sizeof(wccp_password));
    /* Handle password, if any */

    if ((t = ConfigParser::NextToken()) != NULL) {
        if (strncmp(t, "password=", 9) == 0) {
            security_type = WCCP2_MD5_SECURITY;
            xstrncpy(wccp_password, t + 9, sizeof(wccp_password));
        }
    }

    /* Create a placeholder service record */
    wccp2_add_service_list(service, service_id, 0, 0, 0, empty_portlist, security_type, wccp_password);
}

void
dump_wccp2_service(StoreEntry * e, const char *label, void *)
{
    struct wccp2_service_list_t *srv;
    srv = wccp2_service_list_head;

    while (srv != NULL) {
        debugs(80, 3, "dump_wccp2_service: id " << srv->info.service_id << ", type " << srv->info.service);
        storeAppendPrintf(e, "%s %s %d", label,
                          (srv->info.service == WCCP2_SERVICE_DYNAMIC) ? "dynamic" : "standard",
                          srv->info.service_id);

        if (srv->wccp2_security_type == WCCP2_MD5_SECURITY) {
            storeAppendPrintf(e, " %s", srv->wccp_password);
        }

        storeAppendPrintf(e, "\n");

        srv = srv->next;
    }
}

void
free_wccp2_service(void *)
{}

int
check_null_wccp2_service(void *)
{
    return !wccp2_service_list_head;
}

/*
 * Format:
 *
 * wccp2_service_info {id} stuff..
 *
 * Where stuff is:
 *
 * + flags=flag,flag,flag..
 * + proto=protocol (tcp|udp)
 * + ports=port,port,port (up to a max of 8)
 * + priority=priority (0->255)
 *
 * The flags here are:
 * src_ip_hash, dst_ip_hash, source_port_hash, dst_port_hash, ports_defined,
 * ports_source, src_ip_alt_hash, dst_ip_alt_hash, src_port_alt_hash, dst_port_alt_hash
 */
static int
parse_wccp2_service_flags(char *flags)
{
    if (!flags)
        return 0;

    char *flag = flags;
    int retflag = 0;

    while (size_t len = strcspn(flag, ",")) {

        if (strncmp(flag, "src_ip_hash", len) == 0) {
            retflag |= WCCP2_SERVICE_SRC_IP_HASH;
        } else if (strncmp(flag, "dst_ip_hash", len) == 0) {
            retflag |= WCCP2_SERVICE_DST_IP_HASH;
        } else if (strncmp(flag, "source_port_hash", len) == 0) {
            retflag |= WCCP2_SERVICE_SRC_PORT_HASH;
        } else if (strncmp(flag, "dst_port_hash", len) == 0) {
            retflag |= WCCP2_SERVICE_DST_PORT_HASH;
        } else if (strncmp(flag, "ports_source", len) == 0) {
            retflag |= WCCP2_SERVICE_PORTS_SOURCE;
        } else if (strncmp(flag, "src_ip_alt_hash", len) == 0) {
            retflag |= WCCP2_SERVICE_SRC_IP_ALT_HASH;
        } else if (strncmp(flag, "dst_ip_alt_hash", len) == 0) {
            retflag |= WCCP2_SERVICE_DST_IP_ALT_HASH;
        } else if (strncmp(flag, "src_port_alt_hash", len) == 0) {
            retflag |= WCCP2_SERVICE_SRC_PORT_ALT_HASH;
        } else if (strncmp(flag, "dst_port_alt_hash", len) == 0) {
            retflag |= WCCP2_SERVICE_DST_PORT_ALT_HASH;
        } else {
            flag[len] = '\0';
            fatalf("Unknown wccp2 service flag: %s\n", flag);
        }

        if (flag[len] == '\0')
            break;

        flag += len+1;
    }

    return retflag;
}

static void
parse_wccp2_service_ports(char *options, int portlist[])
{
    if (!options) {
        return;
    }

    int i = 0;
    char *tmp = options;
    static char copy[10];

    while (size_t len = strcspn(tmp, ",")) {
        if (i >= WCCP2_NUMPORTS) {
            fatalf("parse_wccp2_service_ports: too many ports (maximum: 8) in list '%s'\n", options);
        }
        if (len > 6) { // 6 because "65535,"
            fatalf("parse_wccp2_service_ports: port value '%s' isn't valid (1..65535)\n", tmp);
        }

        memcpy(copy, tmp, len);
        copy[len] = '\0';
        int p = xatoi(copy);

        if (p < 1 || p > 65535) {
            fatalf("parse_wccp2_service_ports: port value '%s' isn't valid (1..65535)\n", tmp);
        }

        portlist[i] = p;
        ++i;
        if (tmp[len] == '\0')
            return;
        tmp += len+1;
    }
}

void
parse_wccp2_service_info(void *)
{
    char *t, *end;
    int service_id = 0;
    int flags = 0;
    int portlist[WCCP2_NUMPORTS];
    int protocol = -1;      /* IPPROTO_TCP | IPPROTO_UDP */

    struct wccp2_service_list_t *srv;
    int priority = -1;

    if (wccp2_connected == 1) {
        debugs(80, DBG_IMPORTANT, "WCCPv2: Somehow reparsing the configuration without having shut down WCCP! Try reloading squid again.");
        return;
    }

    debugs(80, 5, "parse_wccp2_service_info: called");
    memset(portlist, 0, sizeof(portlist));
    /* First argument: id */
    service_id = GetInteger();

    if (service_id < 0 || service_id > 255) {
        debugs(80, DBG_CRITICAL, "ERROR: invalid WCCP service id " << service_id << " (must be between 0 .. 255)");
        self_destruct();
        return;
    }

    /* Next: find the (hopefully!) existing service */
    srv = wccp2_get_service_by_id(WCCP2_SERVICE_DYNAMIC, service_id);

    if (srv == NULL) {
        fatalf("parse_wccp2_service_info: unknown dynamic service id %d: you need to define it using wccp2_service (and make sure you wish to configure it as a dynamic service.)\n", service_id);
    }

    /* Next: loop until we don't have any more tokens */
    while ((t = ConfigParser::NextToken()) != NULL) {
        if (strncmp(t, "flags=", 6) == 0) {
            /* XXX eww, string pointer math */
            flags = parse_wccp2_service_flags(t + 6);
        } else if (strncmp(t, "ports=", 6) == 0) {
            parse_wccp2_service_ports(t + 6, portlist);
            flags |= WCCP2_SERVICE_PORTS_DEFINED;
        } else if (strncmp(t, "protocol=tcp", 12) == 0) {
            protocol = IPPROTO_TCP;
        } else if (strncmp(t, "protocol=udp", 12) == 0) {
            protocol = IPPROTO_UDP;
        } else if (strncmp(t, "protocol=", 9) == 0) {
            fatalf("parse_wccp2_service_info: id %d: unknown protocol (%s) - must be tcp or udp!\n", service_id, t);
        } else if (strncmp(t, "priority=", 9) == 0) {
            priority = strtol(t + 9, &end, 0);

            if (priority < 0 || priority > 255) {
                fatalf("parse_wccp2_service_info: id %d: %s out of range (0..255)!\n", service_id, t);
            }
        } else {
            fatalf("parse_wccp2_service_info: id %d: unknown option '%s'\n", service_id, t);
        }
    }

    /* Check everything is set */
    if (priority == -1) {
        fatalf("parse_wccp2_service_info: service %d: no priority defined (valid: 0..255)!\n", service_id);
    }

    if (protocol == -1) {
        fatalf("parse_wccp2_service_info: service %d: no protocol defined (valid: tcp or udp)!\n", service_id);
    }

    if (!(flags & WCCP2_SERVICE_PORTS_DEFINED)) {
        fatalf("parse_wccp2_service_info: service %d: no ports defined!\n", service_id);
    }

    /* rightio! now we can update */
    wccp2_update_service(srv, WCCP2_SERVICE_DYNAMIC, service_id, priority,
                         protocol, flags, portlist);

    /* Done! */
}

void
dump_wccp2_service_info(StoreEntry * e, const char *label, void *)
{
    struct wccp2_service_list_t *srv;
    int flags;
    srv = wccp2_service_list_head;

    while (srv != NULL) {
        debugs(80, 3, "dump_wccp2_service_info: id " << srv->info.service_id << " (type " << srv->info.service << ")");

        /* We don't need to spit out information for standard services */

        if (srv->info.service == WCCP2_SERVICE_STANDARD) {
            debugs(80, 3, "dump_wccp2_service_info: id " << srv->info.service_id << ": standard service, not dumping info");

            /* XXX eww */
            srv = srv->next;
            continue;
        }

        storeAppendPrintf(e, "%s %d", label, srv->info.service_id);

        /* priority */
        storeAppendPrintf(e, " priority=%d", srv->info.service_priority);

        /* flags */
        flags = ntohl(srv->info.service_flags);

        bool comma = false;
        if (flags != 0) {
            storeAppendPrintf(e, " flags=");

            if (flags & WCCP2_SERVICE_SRC_IP_HASH) {
                storeAppendPrintf(e, "src_ip_hash");
                comma = true;
            }

            if (flags & WCCP2_SERVICE_DST_IP_HASH) {
                storeAppendPrintf(e, "%sdst_ip_hash", comma ? "," : "");
                comma = true;
            }

            if (flags & WCCP2_SERVICE_SRC_PORT_HASH) {
                storeAppendPrintf(e, "%ssource_port_hash", comma ? "," : "");
                comma = true;
            }

            if (flags & WCCP2_SERVICE_DST_PORT_HASH) {
                storeAppendPrintf(e, "%sdst_port_hash", comma ? "," : "");
                comma = true;
            }

            if (flags & WCCP2_SERVICE_PORTS_DEFINED) {
                storeAppendPrintf(e, "%sports_defined", comma ? "," : "");
                comma = true;
            }

            if (flags & WCCP2_SERVICE_PORTS_SOURCE) {
                storeAppendPrintf(e, "%sports_source", comma ? "," : "");
                comma = true;
            }

            if (flags & WCCP2_SERVICE_SRC_IP_ALT_HASH) {
                storeAppendPrintf(e, "%ssrc_ip_alt_hash", comma ? "," : "");
                comma = true;
            }

            if (flags & WCCP2_SERVICE_DST_IP_ALT_HASH) {
                storeAppendPrintf(e, "%ssrc_ip_alt_hash", comma ? "," : "");
                comma = true;
            }

            if (flags & WCCP2_SERVICE_SRC_PORT_ALT_HASH) {
                storeAppendPrintf(e, "%ssrc_port_alt_hash", comma ? "," : "");
                comma = true;
            }

            if (flags & WCCP2_SERVICE_DST_PORT_ALT_HASH) {
                storeAppendPrintf(e, "%sdst_port_alt_hash", comma ? "," : "");
                //comma = true; // uncomment if more options added
            }
        }

        /* ports */
        comma = false;

        if (srv->info.port0 != 0) {
            storeAppendPrintf(e, " ports=%d", ntohs(srv->info.port0));
            comma = true;
        }

        if (srv->info.port1 != 0) {
            storeAppendPrintf(e, "%s%d", comma ? "," : "ports=", ntohs(srv->info.port1));
            comma = true;
        }

        if (srv->info.port2 != 0) {
            storeAppendPrintf(e, "%s%d", comma ? "," : "ports=", ntohs(srv->info.port2));
            comma = true;
        }

        if (srv->info.port3 != 0) {
            storeAppendPrintf(e, "%s%d", comma ? "," : "ports=", ntohs(srv->info.port3));
            comma = true;
        }

        if (srv->info.port4 != 0) {
            storeAppendPrintf(e, "%s%d", comma ? "," : "ports=", ntohs(srv->info.port4));
            comma = true;
        }

        if (srv->info.port5 != 0) {
            storeAppendPrintf(e, "%s%d", comma ? "," : "ports=", ntohs(srv->info.port5));
            comma = true;
        }

        if (srv->info.port6 != 0) {
            storeAppendPrintf(e, "%s%d", comma ? "," : "ports=", ntohs(srv->info.port6));
            comma = true;
        }

        if (srv->info.port7 != 0) {
            storeAppendPrintf(e, "%s%d", comma ? "," : "ports=", ntohs(srv->info.port7));
            // comma = true; // uncomment if more options are added
        }

        /* protocol */
        storeAppendPrintf(e, " protocol=%s", (srv->info.service_protocol == IPPROTO_TCP) ? "tcp" : "udp");

        storeAppendPrintf(e, "\n");

        srv = srv->next;
    }
}

/* Sort the cache list by doing a "selection sort" by IP address */
static void
wccp2SortCacheList(struct wccp2_cache_list_t *head)
{
    struct wccp2_cache_list_t tmp;
    struct wccp2_cache_list_t *this_item;
    struct wccp2_cache_list_t *find_item;
    struct wccp2_cache_list_t *next_lowest;

    /* Go through each position in the list one at a time */
    for (this_item = head; this_item->next; this_item = this_item->next) {
        /* Find the item with the lowest IP */
        next_lowest = this_item;

        for (find_item = this_item; find_item->next; find_item = find_item->next) {
            if (find_item->cache_ip.s_addr < next_lowest->cache_ip.s_addr) {
                next_lowest = find_item;
            }
        }
        /* Swap if we need to */
        if (next_lowest != this_item) {
            /* First make a copy of the current item */
            memcpy(&tmp, this_item, sizeof(struct wccp2_cache_list_t));

            /* Next update the pointers to maintain the linked list */
            tmp.next = next_lowest->next;
            next_lowest->next = this_item->next;

            /* Finally copy the updated items to their correct location */
            memcpy(this_item, next_lowest, sizeof(struct wccp2_cache_list_t));
            memcpy(next_lowest, &tmp, sizeof(struct wccp2_cache_list_t));
        }
    }
}

void
free_wccp2_service_info(void *)
{}

#endif /* USE_WCCPv2 */

