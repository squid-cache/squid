/*
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

#include "squid.h"

#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif

#include "ntlmauth/ntlmauth.h"
#include "util.h"		/* for base64-related stuff */

/* ************************************************************************* */
/* DEBUG functions */
/* ************************************************************************* */

/** Dumps NTLM flags to standard error for debugging purposes */
void
ntlm_dump_ntlmssp_flags(uint32_t flags)
{
    fprintf(stderr, "flags: %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
            (flags & NTLM_NEGOTIATE_UNICODE ? "Unicode " : ""),
            (flags & NTLM_NEGOTIATE_ASCII ? "ASCII " : ""),
            (flags & NTLM_NEGOTIATE_REQUEST_TARGET ? "ReqTgt " : ""),
            (flags & NTLM_NEGOTIATE_REQUEST_SIGN ? "ReqSign " : ""),
            (flags & NTLM_NEGOTIATE_REQUEST_SEAL ? "ReqSeal " : ""),
            (flags & NTLM_NEGOTIATE_DATAGRAM_STYLE ? "Dgram " : ""),
            (flags & NTLM_NEGOTIATE_USE_LM ? "UseLM " : ""),
            (flags & NTLM_NEGOTIATE_USE_NETWARE ? "UseNW " : ""),
            (flags & NTLM_NEGOTIATE_USE_NTLM ? "UseNTLM " : ""),
            (flags & NTLM_NEGOTIATE_DOMAIN_SUPPLIED ? "HaveDomain " : ""),
            (flags & NTLM_NEGOTIATE_WORKSTATION_SUPPLIED ? "HaveWKS " : ""),
            (flags & NTLM_NEGOTIATE_THIS_IS_LOCAL_CALL ? "LocalCall " : ""),
            (flags & NTLM_NEGOTIATE_ALWAYS_SIGN ? "AlwaysSign " : ""),
            (flags & NTLM_CHALLENGE_TARGET_IS_DOMAIN ? "Tgt_is_domain" : ""),
            (flags & NTLM_CHALLENGE_TARGET_IS_SERVER ? "Tgt_is_server " : ""),
            (flags & NTLM_CHALLENGE_TARGET_IS_SHARE ? "Tgt_is_share " : ""),
            (flags & NTLM_REQUEST_INIT_RESPONSE ? "Req_init_response " : ""),
            (flags & NTLM_REQUEST_ACCEPT_RESPONSE ? "Req_accept_response " : ""),
            (flags & NTLM_REQUEST_NON_NT_SESSION_KEY ? "Req_nonnt_sesskey " : "")
           );
}

/* ************************************************************************* */
/* Packet and Payload handling functions */
/* ************************************************************************* */

/**
 * Check the validity of a decoded NTLM packet.
 *
 * \retval NTLM_ERR_NONE      Packet is okay
 * \retval NTLM_ERR_BLOB      Packet is not even an NTLMSSP packet at all.
 * \retval NTLM_ERR_PROTOCOL  Packet is not the expected type.
 */
int
ntlm_validate_packet(const ntlmhdr * hdr, const int32_t type)
{
    /*
     * Must be the correct security package and request type.
     * The 8 bytes compared includes the ASCII 'NUL'.
     */
    if (memcmp(hdr->signature, "NTLMSSP", 8) != 0) {
        fprintf(stderr, "ntlmCheckHeader: bad header signature\n");
        return NTLM_ERR_BLOB;
    }
    if (type == NTLM_ANY)
        return NTLM_ERR_NONE;

    if ((int32_t)le32toh(hdr->type) != type) {
        /* don't report this error - it's ok as we do a if() around this function */
        debug("ntlm_validate_packet: type is %d, wanted %d\n", le32toh(hdr->type), type);
        return NTLM_ERR_PROTOCOL;
    }
    return NTLM_ERR_NONE;
}

/**
 * Fetches a string from the authentication packet.
 * The lstring data-part may point to inside the packet itself or a temporary static buffer.
 * It's up to the user to memcpy() that if the value needs to
 * be used in any way that requires a tailing \0. (can check whether the
 * value is there though, in that case lstring.length == -1).
 *
 * String may be either ASCII or UNICODE depending on whether flags contains NTLM_NEGOTIATE_ASCII
 */
lstring
ntlm_fetch_string(const ntlmhdr *packet, const int32_t packet_size, const strhdr * str, const uint32_t flags)
{
    int16_t l;			/* length */
    int32_t o;			/* offset */
    static char buf[NTLM_MAX_FIELD_LENGTH];
    lstring rv;
    char *d;

    rv.str = NULL;
    rv.l = -1;

    l = le16toh(str->len);
    o = le32toh(str->offset);
    // debug("ntlm_fetch_string(plength=%d,l=%d,o=%d)\n",packet_size,l,o);

    if (l < 0 || l > NTLM_MAX_FIELD_LENGTH || o + l > packet_size || o == 0) {
        debug("ntlm_fetch_string: insane data (pkt-sz: %d, fetch len: %d, offset: %d)\n", packet_size,l,o);
        return rv;
    }
    rv.str = (char *)packet + o;
    rv.l = 0;
    if ((flags & NTLM_NEGOTIATE_ASCII) == 0) {
        /* UNICODE string */
        unsigned short *s = (unsigned short *)rv.str;
        rv.str = d = buf;

        for (l >>= 1; l; ++s, --l) {
            unsigned short c = le16toh(*s);
            if (c > 254 || c == '\0') {
                fprintf(stderr, "ntlmssp: bad unicode: %04x\n", c);
                return rv;
            }
            *d = c;
            ++d;
            ++rv.l;
        }
    } else {
        /* ASCII/OEM string */
        char *sc = rv.str;

        for (; l>=0; ++sc, --l) {
            if (*sc == '\0' || !xisprint(*sc)) {
                fprintf(stderr, "ntlmssp: bad ascii: %04x\n", *sc);
                return rv;
            }
            ++rv.l;
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

// ?

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

    for (i = 0; i < NTLM_NONCE_LEN; ++i) {
        nonce[i] = r;
        r = (r >> 2) ^ r;
    }
    hash = r;
}

/**
 * Prepares a challenge packet to be sent to the client
 * \note domain should be upper_case
 */
void
ntlm_make_challenge(ntlm_challenge *ch,
                    const char *domain, const char *domain_controller_UNUSED,
                    const char *challenge_nonce, const int challenge_nonce_len,
                    const uint32_t flags)
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
 * \retval NTLM_ERR_NONE	username present, maybe also domain.
 * \retval NTLM_ERR_PROTOCOL	packet type is not an authentication packet.
 * \retval NTLM_ERR_LOGON	no username.
 * \retval NTLM_ERR_BLOB	domain field is apparently larger than the packet.
 */
int
ntlm_unpack_auth(const ntlm_authenticate *auth, char *user, char *domain, const int32_t size)
{
    lstring rv;

    if (ntlm_validate_packet(&auth->hdr, NTLM_AUTHENTICATE)) {
        fprintf(stderr, "ntlm_unpack_auth: header check fails\n");
        return NTLM_ERR_PROTOCOL;
    }
    debug("ntlm_unpack_auth: size of %d\n", size);
    debug("ntlm_unpack_auth: flg %08x\n", auth->flags);
    debug("ntlm_unpack_auth: lmr o(%d) l(%d)\n", le32toh(auth->lmresponse.offset), auth->lmresponse.len);
    debug("ntlm_unpack_auth: ntr o(%d) l(%d)\n", le32toh(auth->ntresponse.offset), auth->ntresponse.len);
    debug("ntlm_unpack_auth: dom o(%d) l(%d)\n", le32toh(auth->domain.offset), auth->domain.len);
    debug("ntlm_unpack_auth: usr o(%d) l(%d)\n", le32toh(auth->user.offset), auth->user.len);
    debug("ntlm_unpack_auth: wst o(%d) l(%d)\n", le32toh(auth->workstation.offset), auth->workstation.len);
    debug("ntlm_unpack_auth: key o(%d) l(%d)\n", le32toh(auth->sessionkey.offset), auth->sessionkey.len);

    rv = ntlm_fetch_string(&auth->hdr, size, &auth->domain, auth->flags);
    if (rv.l > 0) {
        memcpy(domain, rv.str, rv.l);
        domain[rv.l] = '\0';
        debug("ntlm_unpack_auth: Domain '%s' (len=%d).\n", domain, rv.l);
    }
    if (rv.l >= size) {
        debug("ntlm_unpack_auth: Domain length %d too big for %d byte packet.\n", rv.l , size);
        return NTLM_ERR_BLOB;
    }

    rv = ntlm_fetch_string(&auth->hdr, size, &auth->user, auth->flags);
    if (rv.l > 0) {
        memcpy(user, rv.str, rv.l);
        user[rv.l] = '\0';
        debug("ntlm_unpack_auth: Username '%s' (len=%d).\n", user, rv.l);
    } else
        return NTLM_ERR_LOGON;

    return NTLM_ERR_NONE;
}
