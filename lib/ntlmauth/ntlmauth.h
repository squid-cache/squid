/*
 * * * * * * * * Legal stuff * * * * * * *
 *
 * (C) 2000 Francesco Chemolli <kinkie@kame.usr.dsi.unimi.it>,
 *   inspired by previous work by Andrew Doran <ad@interlude.eu.org>.
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
 *
 *
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
 * * * * * * * * Declaration of intents * * * * * * *
 *
 * This header contains definitions and defines allowing to decode and
 * understand NTLM packets, as sent by Internet Explorer.
 * It's put here as it is a common utility to all HTLM-enabled modules.
 */

#ifndef SQUID_NTLMAUTH_H
#define SQUID_NTLMAUTH_H

/* NP: All of this cruft is little endian */

#ifdef __cplusplus
extern "C" {
#endif

    /* Used internally. Microsoft seems to think this is right, I believe them.
     * Right. */
#define NTLM_MAX_FIELD_LENGTH 300	/* max length of an NTLMSSP field */

    /* max length of the BLOB data. (and helper input/output buffer) */
#define NTLM_BLOB_BUFFER_SIZE 10240

    /* Here start the NTLMSSP definitions */

    /* these are marked as "extra" fields */
#define NTLM_REQUEST_INIT_RESPONSE          0x100000
#define NTLM_REQUEST_ACCEPT_RESPONSE        0x200000
#define NTLM_REQUEST_NON_NT_SESSION_KEY     0x400000

    /* NTLM error codes */
#define NTLM_ERR_INTERNAL         -3
#define NTLM_ERR_BLOB             -2
#define NTLM_ERR_BAD_PROTOCOL     -1
#define NTLM_ERR_NONE              0    /* aka. SMBLM_ERR_NONE */
    /* codes used by smb_lm helper */
#define NTLM_ERR_SERVER            1    /* aka. SMBLM_ERR_SERVER   */
#define NTLM_ERR_PROTOCOL          2    /* aka. SMBLM_ERR_PROTOCOL */
#define NTLM_ERR_LOGON             3    /* aka. SMBLM_ERR_LOGON    */
#define NTLM_ERR_UNTRUSTED_DOMAIN  4
#define NTLM_ERR_NOT_CONNECTED     10
    /* codes used by mswin_ntlmsspi helper */
#define NTLM_SSPI_ERROR         1
#define NTLM_BAD_NTGROUP        2
#define NTLM_BAD_REQUEST        3
    /* TODO: reduce the above codes down to one set non-overlapping. */

    /** String header. String data resides at the end of the request */
    typedef struct _strhdr {
        int16_t len;		/**< Length in bytes */
        int16_t maxlen;		/**< Allocated space in bytes */
        int32_t offset;		/**< Offset from start of request */
    } strhdr;

    /** We use this to keep data/length couples. */
    typedef struct _lstring {
        int32_t l;			/**< length, -1 if empty */
        char *str;			/**< the string. NULL if not initialized */
    } lstring;

    /** Debug dump the given flags field to stderr */
    void ntlm_dump_ntlmssp_flags(const uint32_t flags);

    /* ************************************************************************* */
    /* Packet and Payload structures and handling functions */
    /* ************************************************************************* */

    /* NTLM request types that we know about */
#define NTLM_ANY			0
#define NTLM_NEGOTIATE			1
#define NTLM_CHALLENGE			2
#define NTLM_AUTHENTICATE		3

    /** This is an header common to all packets, it's used to discriminate
     * among the different packet signature types.
     */
    typedef struct _ntlmhdr {
        char signature[8];		/**< "NTLMSSP" */
        int32_t type;		/**< One of the NTLM_* types above. */
    } ntlmhdr;

    /** Validate the packet type matches one we want. */
    int ntlm_validate_packet(const ntlmhdr *packet, const int32_t type);

    /** Retrieve a string from the NTLM packet payload. */
    lstring ntlm_fetch_string(const ntlmhdr *packet,
                              const int32_t packet_length,
                              const strhdr *str,
                              const uint32_t flags);

    /** Append a string to the NTLM packet payload. */
    void ntlm_add_to_payload(const ntlmhdr *packet_hdr,
                             char *payload,
                             int *payload_length,
                             strhdr * hdr,
                             const char *toadd,
                             const int toadd_length);

    /* ************************************************************************* */
    /* Negotiate Packet structures and functions */
    /* ************************************************************************* */

    /* negotiate request flags */
#define NTLM_NEGOTIATE_UNICODE              0x0001
#define NTLM_NEGOTIATE_ASCII                0x0002
#define NTLM_NEGOTIATE_REQUEST_TARGET       0x0004
#define NTLM_NEGOTIATE_REQUEST_SIGN         0x0010
#define NTLM_NEGOTIATE_REQUEST_SEAL         0x0020
#define NTLM_NEGOTIATE_DATAGRAM_STYLE       0x0040
#define NTLM_NEGOTIATE_USE_LM               0x0080
#define NTLM_NEGOTIATE_USE_NETWARE          0x0100
#define NTLM_NEGOTIATE_USE_NTLM             0x0200
#define NTLM_NEGOTIATE_DOMAIN_SUPPLIED      0x1000
#define NTLM_NEGOTIATE_WORKSTATION_SUPPLIED 0x2000
#define NTLM_NEGOTIATE_THIS_IS_LOCAL_CALL   0x4000
#define NTLM_NEGOTIATE_ALWAYS_SIGN          0x8000

    /** Negotiation request sent by client */
    typedef struct _ntlm_negotiate {
        ntlmhdr hdr;		/**< "NTLMSSP" , LSWAP(0x1) */
        uint32_t flags;	/**< Request flags */
        strhdr domain;		/**< Domain we wish to authenticate in */
        strhdr workstation;	/**< Client workstation name */
        char payload[256];	/**< String data */
    } ntlm_negotiate;

    /* ************************************************************************* */
    /* Challenge Packet structures and functions */
    /* ************************************************************************* */

#define NTLM_NONCE_LEN 8

    /* challenge request flags */
#define NTLM_CHALLENGE_TARGET_IS_DOMAIN     0x10000
#define NTLM_CHALLENGE_TARGET_IS_SERVER     0x20000
#define NTLM_CHALLENGE_TARGET_IS_SHARE      0x40000

    /** Challenge request sent by server. */
    typedef struct _ntlm_challenge {
        ntlmhdr hdr;		/**< "NTLMSSP" , LSWAP(0x2) */
        strhdr target;		/**< Authentication target (domain/server ...) */
        uint32_t flags;		/**< Request flags */
        u_char challenge[NTLM_NONCE_LEN];	/**< Challenge string */
        uint32_t context_low;	/**< LS part of the server context handle */
        uint32_t context_high;	/**< MS part of the server context handle */
        char payload[256];		/**< String data */
    } ntlm_challenge;

    /* Size of the ntlm_challenge structures formatted fields (excluding payload) */
#define NTLM_CHALLENGE_HEADER_OFFSET	(sizeof(ntlm_challenge)-256)

    /** Generate a challenge request nonce. */
    void ntlm_make_nonce(char *nonce);

    /** Generate a challenge request Blob to be sent to the client. */
    void ntlm_make_challenge(ntlm_challenge *ch,
                             const char *domain,
                             const char *domain_controller,
                             const char *challenge_nonce,
                             const int challenge_nonce_len,
                             const uint32_t flags);

    /* ************************************************************************* */
    /* Authenticate Packet structures and functions */
    /* ************************************************************************* */

    /** Authentication request sent by client in response to challenge */
    typedef struct _ntlm_authenticate {
        ntlmhdr hdr;		/**< "NTLMSSP" , LSWAP(0x3) */
        strhdr lmresponse;		/**< LANMAN challenge response */
        strhdr ntresponse;		/**< NT challenge response */
        strhdr domain;		/**< Domain to authenticate against */
        strhdr user;		/**< Username */
        strhdr workstation;		/**< Workstation name */
        strhdr sessionkey;		/**< Session key for server's use */
        uint32_t flags;		/**< Request flags */
        char payload[256 * 6];	/**< String data */
    } ntlm_authenticate;

    /** Unpack username and domain out of a packet payload. */
    int ntlm_unpack_auth(const ntlm_authenticate *auth,
                         char *user,
                         char *domain,
                         const int32_t size);

#if __cplusplus
}
#endif

#endif /* SQUID_NTLMAUTH_H */
