
/*
 * $Id: store_swapmeta.cc,v 1.7 1998/07/22 20:54:04 wessels Exp $
 *
 * DEBUG: section 20    Storage Manager Swapfile Metadata
 * AUTHOR: Kostas Anagnostakis
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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
    tlv *t = xcalloc(1, sizeof(tlv));
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
	xfree(t);
    }
}

/*
 * Build a TLV list for a StoreEntry
 */
tlv *
storeSwapMetaBuild(StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    tlv *TLV = NULL;		/* we'll return this */
    tlv **T = &TLV;
    const char *url;
    assert(mem != NULL);
    assert(e->swap_status == SWAPOUT_WRITING);
    url = storeUrl(e);
    debug(20, 3) ("storeSwapMetaBuild: %s\n", url);
    T = storeSwapTLVAdd(STORE_META_KEY, e->key, MD5_DIGEST_CHARS, T);
    T = storeSwapTLVAdd(STORE_META_STD, &e->timestamp, STORE_HDR_METASIZE, T);
    T = storeSwapTLVAdd(STORE_META_URL, url, strlen(url) + 1, T);
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
    assert(buflen > (sizeof(char) + sizeof(int)));
    while (buflen - j > (sizeof(char) + sizeof(int))) {
	type = buf[j++];
	xmemcpy(&length, &buf[j], sizeof(int));
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
