
/*
 * $Id: store_swapmeta.cc,v 1.23 2006/05/20 13:15:14 hno Exp $
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
#include "Store.h"
#include "MemObject.h"
#include "StoreMeta.h"
#include "StoreMetaUnpacker.h"

void
storeSwapTLVFree(tlv * n)
{
    tlv *t;

    while ((t = n) != NULL) {
        n = t->next;
        xfree(t->value);
        delete t;
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
    tlv *t = StoreMeta::Factory (STORE_META_KEY,MD5_DIGEST_CHARS, e->key);

    if (!t) {
        storeSwapTLVFree(TLV);
        return NULL;
    }

    T = StoreMeta::Add(T, t);
    t = StoreMeta::Factory(STORE_META_STD,STORE_HDR_METASIZE,&e->timestamp);

    if (!t) {
        storeSwapTLVFree(TLV);
        return NULL;
    }

    T = StoreMeta::Add(T, t);
    t = StoreMeta::Factory(STORE_META_URL, strlen(url) + 1, url);

    if (!t) {
        storeSwapTLVFree(TLV);
        return NULL;
    }

    T = StoreMeta::Add(T, t);
    vary = e->mem_obj->vary_headers;

    if (vary) {
        t =StoreMeta::Factory(STORE_META_VARY_HEADERS, strlen(vary) + 1, vary);

        if (!t) {
            storeSwapTLVFree(TLV);
            return NULL;
        }

        StoreMeta::Add (T, t);
    }

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

    buf = (char *)xmalloc(buflen);

    buf[j++] = (char) STORE_META_OK;

    xmemcpy(&buf[j], &buflen, sizeof(int));

    j += sizeof(int);

    for (t = tlv_list; t; t = t->next) {
        buf[j++] = t->getType();
        xmemcpy(&buf[j], &t->length, sizeof(int));
        j += sizeof(int);
        xmemcpy(&buf[j], t->value, t->length);
        j += t->length;
    }

    assert((int) j == buflen);
    *length = buflen;
    return buf;
}
