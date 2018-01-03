/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_DEFINES_H
#define SQUID_DEFINES_H

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#ifndef BUFSIZ
#define BUFSIZ  4096            /* make unreasonable guess */
#endif

#define BROWSERNAMELEN 128

#define ACL_SUNDAY  0x01
#define ACL_MONDAY  0x02
#define ACL_TUESDAY 0x04
#define ACL_WEDNESDAY   0x08
#define ACL_THURSDAY    0x10
#define ACL_FRIDAY  0x20
#define ACL_SATURDAY    0x40
#define ACL_ALLWEEK 0x7F
#define ACL_WEEKDAYS    0x3E

/* Select types. */
#define COMM_SELECT_READ   (0x1)
#define COMM_SELECT_WRITE  (0x2)

#define DISK_OK                   (0)
#define DISK_ERROR               (-1)
#define DISK_EOF                 (-2)
#define DISK_NO_SPACE_LEFT       (-6)

#define DNS_INBUF_SZ 4096

#define FD_DESC_SZ      64

#define FQDN_LOOKUP_IF_MISS 0x01
#define FQDN_MAX_NAMES 5

#define HTTP_REPLY_FIELD_SZ 128

#define BUF_TYPE_8K     1
#define BUF_TYPE_MALLOC 2

#define ANONYMIZER_NONE     0
#define ANONYMIZER_STANDARD 1
#define ANONYMIZER_PARANOID 2

#define USER_IDENT_SZ 64
#define IDENT_NONE 0
#define IDENT_PENDING 1
#define IDENT_DONE 2

#define IP_LOOKUP_IF_MISS   0x01

#define MAX_MIME 4096

/* Mark a neighbor cache as dead if it doesn't answer this many pings */
#define HIER_MAX_DEFICIT  20

#define ICP_FLAG_HIT_OBJ     0x80000000ul
#define ICP_FLAG_SRC_RTT     0x40000000ul

/* Version */
#define ICP_VERSION_2       2
#define ICP_VERSION_3       3
#define ICP_VERSION_CURRENT ICP_VERSION_2

#define DIRECT_UNKNOWN 0
#define DIRECT_NO    1
#define DIRECT_MAYBE 2
#define DIRECT_YES   3

#define REDIRECT_AV_FACTOR 1000

#define REDIRECT_NONE 0
#define REDIRECT_PENDING 1
#define REDIRECT_DONE 2

#define AUTHENTICATE_AV_FACTOR 1000
/* AUTHENTICATION */

#define NTLM_CHALLENGE_SZ 300

#define current_stacksize(stack) ((stack)->top - (stack)->base)

/* logfile status */
#define LOG_ENABLE  1
#define LOG_DISABLE 0

#define SM_PAGE_SIZE 4096
#define MAX_CLIENT_BUF_SZ 4096

#define EBIT_SET(flag, bit)     ((void)((flag) |= ((1L<<(bit)))))
#define EBIT_CLR(flag, bit)     ((void)((flag) &= ~((1L<<(bit)))))
#define EBIT_TEST(flag, bit)    ((flag) & ((1L<<(bit))))

/* bit opearations on a char[] mask of unlimited length */
#define CBIT_BIT(bit)           (1<<((bit)%8))
#define CBIT_BIN(mask, bit)     (mask)[(bit)>>3]
#define CBIT_SET(mask, bit)     ((void)(CBIT_BIN(mask, bit) |= CBIT_BIT(bit)))
#define CBIT_CLR(mask, bit)     ((void)(CBIT_BIN(mask, bit) &= ~CBIT_BIT(bit)))
#define CBIT_TEST(mask, bit)    (CBIT_BIN(mask, bit) & CBIT_BIT(bit))

#define MAX_FILES_PER_DIR (1<<20)

#define MAX_URL  8192
#define MAX_LOGIN_SZ  128

#define PEER_MAX_ADDRESSES 10
#define RTT_AV_FACTOR      50
#define RTT_BACKGROUND_AV_FACTOR      25    /* Background pings need a smaller factor since they are sent less frequently */

#define PEER_DEAD 0
#define PEER_ALIVE 1

#define AUTH_MSG_SZ 4096
#define HTTP_REPLY_BUF_SZ 4096
#define CLIENT_REQ_BUF_SZ 4096

#if !defined(ERROR_BUF_SZ) && defined(MAX_URL)
#define ERROR_BUF_SZ (MAX_URL << 2)
#endif

#if SQUID_SNMP
#define VIEWINCLUDED    1
#define VIEWEXCLUDED    2
#endif

#define STORE_META_OK     0x03
#define STORE_META_DIRTY  0x04
#define STORE_META_BAD    0x05

#define IPC_NONE 0
#define IPC_TCP_SOCKET 1
#define IPC_UDP_SOCKET 2
#define IPC_FIFO 3
#define IPC_UNIX_STREAM 4
#define IPC_UNIX_DGRAM 5

/* required for AF_UNIX below to be defined [on FreeBSD] */
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#if HAVE_SOCKETPAIR && defined (AF_UNIX)
#define IPC_STREAM IPC_UNIX_STREAM
#define IPC_DGRAM IPC_UNIX_DGRAM
#else
#define IPC_STREAM IPC_TCP_SOCKET
#define IPC_DGRAM IPC_UDP_SOCKET
#endif

#define STORE_META_KEY STORE_META_KEY_MD5

#define STORE_META_TLD_START sizeof(int)+sizeof(char)
#define STORE_META_TLD_SIZE STORE_META_TLD_START
#define SwapMetaType(x) (char)x[0]
#define SwapMetaSize(x) &x[sizeof(char)]
#define SwapMetaData(x) &x[STORE_META_TLD_START]
#define STORE_HDR_METASIZE (4*sizeof(time_t)+2*sizeof(uint16_t)+sizeof(uint64_t))
#define STORE_HDR_METASIZE_OLD (4*sizeof(time_t)+2*sizeof(uint16_t)+sizeof(size_t))

#define COUNT_INTERVAL 60
/*
 * keep 60 minutes' worth of per-minute readings (+ current reading)
 */
#define N_COUNT_HIST (3600 / COUNT_INTERVAL) + 1
/*
 * keep 3 days' (72 hours) worth of hourly readings
 */
#define N_COUNT_HOUR_HIST (86400 * 3) / (60 * COUNT_INTERVAL)

/* handy to determine the #elements in a static array */
#define countof(arr) (sizeof(arr)/sizeof(*arr))

/*
 * This many TCP connections must FAIL before we mark the
 * peer as DEAD
 */
#define PEER_TCP_MAGIC_COUNT 10

#define URI_WHITESPACE_STRIP 0
#define URI_WHITESPACE_ALLOW 1
#define URI_WHITESPACE_ENCODE 2
#define URI_WHITESPACE_CHOP 3
#define URI_WHITESPACE_DENY 4

#ifndef O_TEXT
#define O_TEXT 0
#endif
#ifndef O_BINARY
#define O_BINARY 0
#endif

/*
 * Macro to find file access mode
 */
#ifdef O_ACCMODE
#define FILE_MODE(x) ((x)&O_ACCMODE)
#else
#define FILE_MODE(x) ((x)&(O_RDONLY|O_WRONLY|O_RDWR))
#endif

#define HTTP_REQBUF_SZ  4096

/* CygWin & Windows NT Port */
#if _SQUID_WINDOWS_
#define _WIN_SQUID_SERVICE_CONTROL_STOP SERVICE_CONTROL_STOP
#define _WIN_SQUID_SERVICE_CONTROL_SHUTDOWN SERVICE_CONTROL_SHUTDOWN
#define _WIN_SQUID_SERVICE_CONTROL_INTERROGATE SERVICE_CONTROL_INTERROGATE
#define _WIN_SQUID_SERVICE_CONTROL_ROTATE   128
#define _WIN_SQUID_SERVICE_CONTROL_RECONFIGURE  129
#define _WIN_SQUID_SERVICE_CONTROL_DEBUG    130
#define _WIN_SQUID_SERVICE_CONTROL_INTERRUPT    131
#define _WIN_SQUID_SERVICE_OPTION       "--ntservice"
#define _WIN_SQUID_RUN_MODE_INTERACTIVE     0
#define _WIN_SQUID_RUN_MODE_SERVICE     1
#endif

#endif /* SQUID_DEFINES_H */

