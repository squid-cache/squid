
/*
 * $Id: store_swapmeta.cc,v 1.17 2001/10/24 08:52:37 hno Exp $
 *
 * DEBUG: section 20    Storage Manager Swapfile Metadata
 * AUTHOR: Kostas Anagnostakis
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
 */

#include "squid.h"

static tlv **
storeSwapTLVAdd(int type, const void *ptr, size_t len, tlv ** tail)
{
    tlv *t = memAllocate(MEM_TLV);
    t->type = (char) type;
    t->length = (int) len;
    t->value = xmalloc(len);
    xmemcpy(t->value, ptr, len);
    *tail = t;
    return &t->next;		/* return new tail pointer */
}

void
storeSwapTLVFree(tlv * n)
{
    tlv *t;
    while ((t = n) != NULL) {
	n = t->next;
	xfree(t->value);
	memFree(t, MEM_TLV);
    }
}

/*
 * Build a TLV list for a StoreEntry
 */
tlv *
storeSwapMetaBuild(StoreEntry * e)
{
    tlv *TLV = NULL;		/* we'll return this */
    tlv **T = &TLV;
    const char *url;
    const char *vary;
    assert(e->mem_obj != NULL);
    assert(e->swap_status == SWAPOUT_WRITING);
    url = storeUrl(e);
    debug(20, 3) ("storeSwapMetaBuild: %s\n", url);
    T = storeSwapTLVAdd(STORE_META_KEY, e->hash.key, MD5_DIGEST_CHARS, T);
    T = storeSwapTLVAdd(STORE_META_STD, &e->timestamp, STORE_HDR_METASIZE, T);
    T = storeSwapTLVAdd(STORE_META_URL, url, strlen(url) + 1, T);
    vary = e->mem_obj->vary_headers;
    if (vary)
	T = storeSwapTLVAdd(STORE_META_VARY_HEADERS, vary, strlen(vary) + 1, T);
    return TLV;
}

char *
storeSwapMetaPack(tlv * tlv_list, int *length)
{
    int buflen = 0;
    tlv *t;
    off_t j = 0;
    char *buf;
    assert(length != NULL);
    buflen++;			/* STORE_META_OK */
    buflen += sizeof(int);	/* size of header to follow */
    for (t = tlv_list; t; t = t->next)
	buflen += sizeof(char) + sizeof(int) + t->length;
    buflen++;			/* STORE_META_END */
    buf = xmalloc(buflen);
    buf[j++] = (char) STORE_META_OK;
    xmemcpy(&buf[j], &buflen, sizeof(int));
    j += sizeof(int);
    for (t = tlv_list; t; t = t->next) {
	buf[j++] = (char) t->type;
	xmemcpy(&buf[j], &t->length, sizeof(int));
	j += sizeof(int);
	xmemcpy(&buf[j], t->value, t->length);
	j += t->length;
    }
    buf[j++] = (char) STORE_META_END;
    assert((int) j == buflen);
    *length = buflen;
    return buf;
}

tlv *
storeSwapMetaUnpack(const char *buf, int *hdr_len)
{
    tlv *TLV;			/* we'll return this */
    tlv **T = &TLV;
    char type;
    int length;
    int buflen;
    off_t j = 0;
    assert(buf != NULL);
    assert(hdr_len != NULL);
    if (buf[j++] != (char) STORE_META_OK)
	return NULL;
    xmemcpy(&buflen, &buf[j], sizeof(int));
    j += sizeof(int);
    /*
     * sanity check on 'buflen' value.  It should be at least big
     * enough to hold one type and one length.
     */
    if (buflen <= (sizeof(char) + sizeof(int)))
	    return NULL;
    while (buflen - j > (sizeof(char) + sizeof(int))) {
	type = buf[j++];
	/* VOID is reserved, but allow some slack for new types.. */
	if (type <= STORE_META_VOID || type > STORE_META_END + 10) {
	    debug(20, 0) ("storeSwapMetaUnpack: bad type (%d)!\n", type);
	    break;
	}
	xmemcpy(&length, &buf[j], sizeof(int));
	if (length < 0 || length > (1 << 16)) {
	    debug(20, 0) ("storeSwapMetaUnpack: insane length (%d)!\n", length);
	    break;
	}
	j += sizeof(int);
	if (j + length > buflen) {
	    debug(20, 0) ("storeSwapMetaUnpack: overflow!\n");
	    debug(20, 0) ("\ttype=%d, length=%d, buflen=%d, offset=%d\n",
		type, length, buflen, (int) j);
	    break;
	}
	T = storeSwapTLVAdd(type, &buf[j], (size_t) length, T);
	j += length;
    }
    *hdr_len = buflen;
    return TLV;
}
