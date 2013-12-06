/* UNIX RFCNB (RFC1001/RFC1002) NetBIOS implementation
 *
 * Version 1.0
 * RFCNB Defines
 *
 * Copyright (C) Richard Sharpe 1996
 *
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _RFCNB_RFCNB_PRIV_H
#define _RFCNB_RFCNB_PRIV_H

/* Defines we need */

typedef unsigned short uint16;

#define GLOBAL extern

#include "rfcnb/byteorder.h"
#include "rfcnb/rfcnb-common.h"
#include "rfcnb/rfcnb-error.h"

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef RFCNB_PORT
#define RFCNB_Default_Port RFCNB_PORT
#else
#define RFCNB_Default_Port 139
#endif

#define RFCNB_MAX_STATS 1

/* Protocol defines we need */

#define RFCNB_SESSION_MESSAGE 0
#define RFCNB_SESSION_REQUEST 0x81
#define RFCNB_SESSION_ACK 0x82
#define RFCNB_SESSION_REJ 0x83
#define RFCNB_SESSION_RETARGET 0x84
#define RFCNB_SESSION_KEEP_ALIVE 0x85

/* Structures      */

typedef struct redirect_addr *redirect_ptr;

struct redirect_addr {

    struct in_addr ip_addr;
    int port;
    redirect_ptr next;

};

typedef struct RFCNB_Con {

    int fd;                     /* File descripter for TCP/IP connection */
    int errn;                   /* last error                            */
    int timeout;                /* How many milli-secs before IO times out */
    int redirects;              /* How many times we were redirected     */
    struct redirect_addr *redirect_list;        /* First is first address */
    struct redirect_addr *last_addr;

} RFCNB_Con;

typedef char RFCNB_Hdr[4];      /* The header is 4 bytes long with  */
/* char[0] as the type, char[1] the */
/* flags, and char[2..3] the length */

/* Macros to extract things from the header. These are for portability
 * between architecture types where we are worried about byte order     */

#define RFCNB_Pkt_Hdr_Len        4
#define RFCNB_Pkt_Sess_Len       72
#define RFCNB_Pkt_Retarg_Len     10
#define RFCNB_Pkt_Nack_Len       5
#define RFCNB_Pkt_Type_Offset    0
#define RFCNB_Pkt_Flags_Offset   1
#define RFCNB_Pkt_Len_Offset     2      /* Length is 2 bytes plus a flag bit */
#define RFCNB_Pkt_N1Len_Offset   4
#define RFCNB_Pkt_Called_Offset  5
#define RFCNB_Pkt_N2Len_Offset   38
#define RFCNB_Pkt_Calling_Offset 39
#define RFCNB_Pkt_Error_Offset   4
#define RFCNB_Pkt_IP_Offset      4
#define RFCNB_Pkt_Port_Offset    8

/* The next macro isolates the length of a packet, including the bit in the
 * flags                                                                   */

#define RFCNB_Pkt_Len(p)  (PVAL((p), 3) | (PVAL((p), 2) << 8) |     \
                          ((PVAL((p), RFCNB_Pkt_Flags_Offset) & 0x01) << 16))

#define RFCNB_Put_Pkt_Len(p, v) ((p)[1] = (((v) >> 16) & 1)); \
                                ((p)[2] = (((v) >> 8) & 0xFF)); \
                                ((p)[3] = ((v) & 0xFF));

#define RFCNB_Pkt_Type(p) (CVAL((p), RFCNB_Pkt_Type_Offset))

#if UNUSED_CODE
typedef struct RFCNB_Hdr {
    unsigned char type;
    unsigned char flags;
    int16 len;
} RFCNB_Hdr;

typedef struct RFCNB_Sess_Pkt {
    unsigned char type;
    unsigned char flags;
    int16 length;
    unsigned char n1_len;
    char called_name[33];
    unsigned char n2_len;
    char calling_name[33];
} RFCNB_Sess_Pkt;

typedef struct RFCNB_Nack_Pkt {
    struct RFCNB_Hdr hdr;
    unsigned char error;
} RFCNB_Nack_Pkt;

typedef struct RFCNB_Retarget_Pkt {
    struct RFCNB_Hdr hdr;
    int dest_ip;
    unsigned char port;
} RFCNB_Redir_Pkt;
#endif /* UNUSED_CODE */

/* Static variables */

/* Only declare this if not defined */

#ifndef RFCNB_ERRNO
extern int RFCNB_errno;
extern int RFCNB_saved_errno;   /* Save this from point of error */
#endif

#endif /* _RFCNB_RFCNB_PRIV_H */
