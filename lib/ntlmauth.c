/*
 * $Id: ntlmauth.c,v 1.9 2003/08/05 21:40:09 robertc Exp $
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

#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "ntlmauth.h"
#include "squid_endian.h"
#include "util.h"		/* for base64-related stuff */

#if UNUSED_CODE
/* Dumps NTLM flags to standard error for debugging purposes */
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

#endif

#define lstring_zero(s) s.str=NULL; s.l=-1;

/* fetches a string from the authentication packet.
 * The lstring data-part points to inside the packet itself.
 * It's up to the user to memcpy() that if the value needs to
 * be used in any way that requires a tailing \0. (he can check whether the
 * value is there though, in that case lstring.length==-1).
 */
lstring
ntlm_fetch_string(char *packet, int32_t length, strhdr * str)
{
    int16_t l;			/* length */
    int32_t o;			/* offset */
    lstring rv;

    lstring_zero(rv);

    l = le16toh(str->len);
    o = le32toh(str->offset);
    /* debug("fetch_string(plength=%d,l=%d,o=%d)\n",length,l,o); */

    if (l < 0 || l > MAX_FIELD_LENGTH || o + l > length || o == 0) {
	/* debug("ntlmssp: insane data (l: %d, o: %d)\n", l,o); */
	return rv;
    }
    rv.str = packet + o;
    rv.l = l;

    return rv;
}

/* Adds something to the payload. The caller must guarrantee that
 * there is enough space in the payload string to accommodate the
 * added value.
 * payload_length and hdr will be modified as a side-effect.
 * base_offset is the payload offset from the packet's beginning, and is
 */
void
ntlm_add_to_payload(char *payload, int *payload_length,
    strhdr * hdr, char *toadd,
    int toadd_length, int base_offset)
{

    int l = (*payload_length);
    memcpy(payload + l, toadd, toadd_length);

    hdr->len = htole16(toadd_length);
    hdr->maxlen = htole16(toadd_length);
    hdr->offset = htole32(l + base_offset);	/* 48 is the base offset of the payload */
    (*payload_length) += toadd_length;
}


/* prepares a base64-encode challenge packet to be sent to the client
 * note: domain should be upper_case
 * note: the storage type for the returned value depends on
 *    base64_encode_bin. Currently this means static storage.
 */
const char *
ntlm_make_challenge(char *domain, char *domain_controller,
    char *challenge_nonce, int challenge_nonce_len)
{
    ntlm_challenge ch;
    int pl = 0;
    const char *encoded;
    memset(&ch, 0, sizeof(ntlm_challenge));	/* reset */
    memcpy(ch.signature, "NTLMSSP", 8);		/* set the signature */
    ch.type = htole32(NTLM_CHALLENGE);	/* this is a challenge */
    ntlm_add_to_payload(ch.payload, &pl, &ch.target, domain, strlen(domain),
	NTLM_CHALLENGE_HEADER_OFFSET);
    ch.flags = htole32(
	REQUEST_NON_NT_SESSION_KEY |
	CHALLENGE_TARGET_IS_DOMAIN |
	NEGOTIATE_ALWAYS_SIGN |
	NEGOTIATE_USE_NTLM |
	NEGOTIATE_USE_LM |
	NEGOTIATE_ASCII |
	0
	);
    ch.context_low = 0;		/* check this out */
    ch.context_high = 0;
    memcpy(ch.challenge, challenge_nonce, challenge_nonce_len);
    encoded = base64_encode_bin((char *) &ch, NTLM_CHALLENGE_HEADER_OFFSET + pl);
    return encoded;
}
