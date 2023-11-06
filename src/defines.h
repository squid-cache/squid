/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

/* Select types. */
#define COMM_SELECT_READ   (0x1)
#define COMM_SELECT_WRITE  (0x2)

#define DISK_OK                   (0)
#define DISK_ERROR               (-1)
#define DISK_EOF                 (-2)
#define DISK_NO_SPACE_LEFT       (-6)

#define FD_DESC_SZ      64

#define FQDN_LOOKUP_IF_MISS 0x01
#define FQDN_MAX_NAMES 5

#define USER_IDENT_SZ 64

#define IP_LOOKUP_IF_MISS   0x01

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

/* AUTHENTICATION */

/* logfile status */
#define LOG_ENABLE  1
#define LOG_DISABLE 0

#define SM_PAGE_SIZE 4096

#define EBIT_SET(flag, bit)     ((void)((flag) |= ((1L<<(bit)))))
#define EBIT_CLR(flag, bit)     ((void)((flag) &= ~((1L<<(bit)))))
#define EBIT_TEST(flag, bit)    ((flag) & ((1L<<(bit))))

/* bit opearations on a char[] mask of unlimited length */
#define CBIT_BIT(bit)           (1<<((bit)%8))
#define CBIT_BIN(mask, bit)     (mask)[(bit)>>3]
#define CBIT_SET(mask, bit)     ((void)(CBIT_BIN(mask, bit) |= CBIT_BIT(bit)))
#define CBIT_CLR(mask, bit)     ((void)(CBIT_BIN(mask, bit) &= ~CBIT_BIT(bit)))
#define CBIT_TEST(mask, bit)    (CBIT_BIN(mask, bit) & CBIT_BIT(bit))

#define MAX_URL  8192
#define MAX_LOGIN_SZ  128

#define PEER_MAX_ADDRESSES 10
#define RTT_AV_FACTOR      50
#define RTT_BACKGROUND_AV_FACTOR      25    /* Background pings need a smaller factor since they are sent less frequently */

#define PEER_DEAD 0
#define PEER_ALIVE 1

#define CLIENT_REQ_BUF_SZ 4096

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

#define COUNT_INTERVAL 60
/*
 * keep 60 minutes' worth of per-minute readings (+ current reading)
 */
#define N_COUNT_HIST (3600 / COUNT_INTERVAL) + 1
/*
 * keep 3 days' (72 hours) worth of hourly readings
 */
#define N_COUNT_HOUR_HIST (86400 * 3) / (60 * COUNT_INTERVAL)

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

