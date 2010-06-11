/*
 * $Id$
 *
 * AUTHOR: Francesco Chemolli <kinkie@kame.usr.dsi.unimi.it>
 * AUTHOR: Guido Serassio: <guido.serassio@acmeconsulting.it>
 * AUTHOR: Amos Jeffries <squid3@treenet.co.nz>
 *
 * * * * * * * * Legal stuff * * * * * * *
 *
 * (C) 2000 Francesco Chemolli <kinkie@kame.usr.dsi.unimi.it>,
 *   inspired by previous work by Andrew Doran <ad@interlude.eu.org>.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "config.h"

#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif

#include "ntlmauth.h"
#include "util.h"		/* for base64-related stuff */

/* ************************************************************************* */
/* DEBUG functions */
/* ************************************************************************* */

/** Dumps NTLM flags to standard error for debugging purposes */
void
ntlm_dump_ntlmssp_flags(u_int32_t flags)
{
    fprintf(stderr, "flags: %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
            (flags & NEGOTIATE_UNICODE ? "Unicode " : ""),
            (flags & NEGOTIATE_ASCII ? "ASCII " : ""),
            (flags & NEGOTIATE_REQUEST_TARGET ? "ReqTgt " : ""),
            (flags & NEGOTIATE_REQUEST_SIGN ? "ReqSign " : ""),
            (flags & NEGOTIATE_REQUEST_SEAL ? "ReqSeal " : ""),
            (flags & NEGOTIATE_DATAGRAM_STYLE ? "Dgram " : ""),
            (flags & NEGOTIATE_USE_LM ? "UseLM " : ""),
            (flags & NEGOTIATE_USE_NETWARE ? "UseNW " : ""),
            (flags & NEGOTIATE_USE_NTLM ? "UseNTLM " : ""),
            (flags & NEGOTIATE_DOMAIN_SUPPLIED ? "HaveDomain " : ""),
            (flags & NEGOTIATE_WORKSTATION_SUPPLIED ? "HaveWKS " : ""),
            (flags & NEGOTIATE_THIS_IS_LOCAL_CALL ? "LocalCall " : ""),
            (flags & NEGOTIATE_ALWAYS_SIGN ? "AlwaysSign " : ""),
            (flags & CHALLENGE_TARGET_IS_DOMAIN ? "Tgt_is_domain" : ""),
            (flags & CHALLENGE_TARGET_IS_SERVER ? "Tgt_is_server " : ""),
            (flags & CHALLENGE_TARGET_IS_SHARE ? "Tgt_is_share " : ""),
            (flags & REQUEST_INIT_RESPONSE ? "Req_init_response " : ""),
            (flags & REQUEST_ACCEPT_RESPONSE ? "Req_accept_response " : ""),
            (flags & REQUEST_NON_NT_SESSION_KEY ? "Req_nonnt_sesskey " : "")
           );
}

/* ************************************************************************* */
/* Packet and Payload handling functions */
/* ************************************************************************* */

/**
 * Check the validity of a decoded NTLM packet. Return -1 on error.
 */
int
ntlm_validate_packet(const ntlmhdr * hdr, const int type)
{
    /*
     * Must be the correct security package and request type.
     * The 8 bytes compared includes the ASCII 'NUL'.
     */
    if (memcmp(hdr->signature, "NTLMSSP", 8) != 0) {
        fprintf(stderr, "ntlmCheckHeader: bad header signature\n");
        return (-1);
    }
    if (type == NTLM_ANY)
        return 0;

    if (le32toh(hdr->type) != type) {
        /* don't report this error - it's ok as we do a if() around this function */
//      fprintf(stderr, "ntlmCheckHeader: type is %d, wanted %d\n", le32toh(hdr->type), type);
        return (-1);
    }
    return (0);
}

#define lstring_zero(s) s.str=NULL; s.l=-1;

/**
 * Fetches a string from the authentication packet.
 * The lstring data-part may point to inside the packet itself or a temporary static buffer.
 * It's up to the user to memcpy() that if the value needs to
 * be used in any way that requires a tailing \0. (can check whether the
 * value is there though, in that case lstring.length == -1).
 *
 * String may be either ASCII or UNICODE depending on whether flags contains NEGOTIATE_ASCII
 */
lstring
ntlm_fetch_string(const ntlmhdr *packet, const int32_t packet_size, const strhdr * str, const u_int32_t flags)
{
    int16_t l;			/* length */
    int32_t o;			/* offset */
    static char buf[NTLM_MAX_FIELD_LENGTH];
    lstring rv;
    u_short *s, c;
    char *d, *sc;

    lstring_zero(rv);

    l = le16toh(str->len);
    o = le32toh(str->offset);
    /* debug("fetch_string(plength=%d,l=%d,o=%d)\n",packet_size,l,o); */

    if (l < 0 || l > NTLM_MAX_FIELD_LENGTH || o + l > packet_size || o == 0) {
        /* debug("ntlmssp: insane data (l: %d, o: %d)\n", l,o); */
        return rv;
    }
    rv.str = (char *)packet + o;
    if ((flags & NEGOTIATE_ASCII) == 0) {
        /* UNICODE string */
        s = (u_short *) ((char *) packet + o);
        rv.str = d = buf;

        for (l >>= 1; l; s++, l--) {
            c = le16toh(*s);
            if (c > 254 || c == '\0') {
                fprintf(stderr, "ntlmssp: bad unicode: %04x\n", c);
                return rv;
            }
            *d++ = c;
            rv.l++;
        }
    } else {
        /* ASCII/OEM string */
        sc = (char *) packet + o;

        for (; l; l--) {
            if (*sc == '\0' || !xisprint(*sc)) {
                fprintf(stderr, "ntlmssp: bad ascii: %04x\n", *sc);
                return rv;
            }
            rv.l++;
        }
    }

    return rv;
}

/**
 * Adds something to the payload. The caller must guarrantee that
 * there is enough space in the payload string to accommodate the
 * added value.
 * payload_length and hdr will be modified as a side-effect.
 */
void
ntlm_add_to_payload(const ntlmhdr *packet_hdr,
                    char *payload,
                    int *payload_length,
                    strhdr * hdr,
                    const char *toadd,
                    const int toadd_length)
{
    int l = (*payload_length);
    memcpy(payload + l, toadd, toadd_length);

    hdr->len = htole16(toadd_length);
    hdr->maxlen = htole16(toadd_length);
    hdr->offset = htole32(l + payload - (char*)packet_hdr);
    (*payload_length) += toadd_length;
}


/* ************************************************************************* */
/* Negotiate Packet functions */
/* ************************************************************************* */

// ??


/* ************************************************************************* */
/* Challenge Packet functions */
/* ************************************************************************* */

/* 
 * Generates a challenge request nonce. The randomness of the 8 byte
 * challenge strings can be guarenteed to be poor at best.
 */
void
ntlm_make_nonce(char *nonce)
{
    static unsigned hash;
    int i;
    int r = (int) rand();
    r = (hash ^ r) + r;

    for (i = 0; i < NTLM_NONCE_LEN; i++) {
        nonce[i] = r;
        r = (r >> 2) ^ r;
    }
    hash = r;
}

#if DEAD_API
/**
 * Prepares a base64-encode challenge packet to be sent to the client
 * \note domain should be upper_case
 * \note the storage type for the returned value depends on
 *    base64_encode_bin. Currently this means static storage.
 */
void
ntlm_make_challenge(const char *domain, const char *dc_UNUSED,
                    const char *cn, const int cnl)
{
    /* This function API has changes somewhat, and not all user helpers */
    ntlm_challenge chal;

    /*  ORIGINAL flags was HARD-CODED set to these:
        TODO: find all old callers (without flags field) and have them send these in manually now...
    */
    u_int32_t flags = REQUEST_NON_NT_SESSION_KEY |
                      CHALLENGE_TARGET_IS_DOMAIN |
                      NEGOTIATE_ALWAYS_SIGN |
                      NEGOTIATE_USE_NTLM |
                      NEGOTIATE_USE_LM |
                      NEGOTIATE_ASCII;

    ntlm_make_challenge(&chal, domain, dc_UNUSED, cn, cnl, flags);

/*  ORIGINAL handling of ntlm_challenge object was to encode it like this:
    TODO: find all old callers and have them do teh decode themselves now.
*/
    return base64_encode_bin((char *)&chal, NTLM_CHALLENGE_HEADER_OFFSET + pl);
}
#endif

/**
 * Prepares a challenge packet to be sent to the client
 * \note domain should be upper_case
 */
void
ntlm_make_challenge(ntlm_challenge *ch,
                    const char *domain, const char *domain_controller_UNUSED,
                    const char *challenge_nonce, const int challenge_nonce_len,
                    const u_int32_t flags)
{
    int pl = 0;
    memset(ch, 0, sizeof(ntlm_challenge));	/* reset */
    memcpy(ch->hdr.signature, "NTLMSSP", 8);		/* set the signature */
    ch->hdr.type = htole32(NTLM_CHALLENGE);	/* this is a challenge */
    if (domain != NULL) {
        ntlm_add_to_payload(&ch->hdr, ch->payload, &pl, &ch->target, domain, strlen(domain));
    }
    ch->flags = htole32(flags);
    ch->context_low = 0;		/* check this out */
    ch->context_high = 0;
    memcpy(ch->challenge, challenge_nonce, challenge_nonce_len);
}

/* ************************************************************************* */
/* Authenticate Packet functions */
/* ************************************************************************* */

/**
 * Unpack the strings in an NTLM authentication response from client.
 * The caller is responsible for initializing the user and domain buffers
 * this function will only insert data if the packet contains any. Otherwise
 * the buffers will be left untouched.
 *
 * \retval -1	packet type is not an authentication packet.
 * \retval  0	username present and maybe also domain.
 * \retval  1	no username.
 */
int
ntlm_unpack_auth(const ntlm_authenticate *auth, char *user, char *domain, const int32_t size)
{
    const char *p;
    unsigned int s;
    lstring rv;

    if (ntlm_validate_packet(&auth->hdr, NTLM_AUTHENTICATE)) {
        fprintf(stderr, "ntlmDecodeAuth: header check fails\n");
        return -1;
    }
    debug("ntlmDecodeAuth: size of %d\n", size);
    debug("ntlmDecodeAuth: flg %08x\n", auth->flags);
    debug("ntlmDecodeAuth: usr o(%d) l(%d)\n", auth->user.offset, auth->user.len);

    rv = ntlm_fetch_string(&auth->hdr, size, &auth->domain, auth->flags);
    if (rv.l > 0) {
        memcpy(rv.str, domain, rv.l);
        domain[rv.l] = '\0';
        debug("ntlm_unpack_auth: Domain '%s'.\n", domain);
    }
    if (rv.l >= size)
        return 1;

    rv = ntlm_fetch_string(&auth->hdr, size, &auth->user, auth->flags);
    if (rv.l > 0) {
        memcpy(rv.str, user, rv.l);
        user[rv.l] = '\0';
        debug("ntlm_unpack_auth: Username '%s'.\n", user);
    } else
        return 1;

    return 0;
}
