/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager Swapfile Metadata */

#include "squid.h"
#include "md5.h"
#include "MemObject.h"
#include "Store.h"
#include "StoreMeta.h"
#include "StoreMetaUnpacker.h"

#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

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
    tlv *TLV = NULL;        /* we'll return this */
    tlv **T = &TLV;
    assert(e->mem_obj != NULL);
    const int64_t objsize = e->mem_obj->expectedReplySize();

    // e->mem_obj->request may be nil in this context
    SBuf url;
    if (e->mem_obj->request)
        url = e->mem_obj->request->storeId();
    else
        url = e->url();

    debugs(20, 3, "storeSwapMetaBuild URL: " << url);

    tlv *t = StoreMeta::Factory (STORE_META_KEY,SQUID_MD5_DIGEST_LENGTH, e->key);

    if (!t) {
        storeSwapTLVFree(TLV);
        return NULL;
    }

    T = StoreMeta::Add(T, t);
    t = StoreMeta::Factory(STORE_META_STD_LFS,STORE_HDR_METASIZE,&e->timestamp);

    if (!t) {
        storeSwapTLVFree(TLV);
        return NULL;
    }

    // XXX: do TLV without the c_str() termination. check readers first though
    T = StoreMeta::Add(T, t);
    t = StoreMeta::Factory(STORE_META_URL, url.length()+1, url.c_str());

    if (!t) {
        storeSwapTLVFree(TLV);
        return NULL;
    }

    if (objsize >= 0) {
        T = StoreMeta::Add(T, t);
        t = StoreMeta::Factory(STORE_META_OBJSIZE, sizeof(objsize), &objsize);

        if (!t) {
            storeSwapTLVFree(TLV);
            return NULL;
        }
    }

    T = StoreMeta::Add(T, t);
    SBuf vary(e->mem_obj->vary_headers);

    if (!vary.isEmpty()) {
        t = StoreMeta::Factory(STORE_META_VARY_HEADERS, vary.length(), vary.c_str());

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
    int j = 0;
    char *buf;
    assert(length != NULL);
    ++buflen;           /* STORE_META_OK */
    buflen += sizeof(int);  /* size of header to follow */

    for (t = tlv_list; t; t = t->next)
        buflen += sizeof(char) + sizeof(int) + t->length;

    buf = (char *)xmalloc(buflen);

    buf[j] = (char) STORE_META_OK;
    ++j;

    memcpy(&buf[j], &buflen, sizeof(int));

    j += sizeof(int);

    for (t = tlv_list; t; t = t->next) {
        buf[j] = t->getType();
        ++j;
        memcpy(&buf[j], &t->length, sizeof(int));
        j += sizeof(int);
        memcpy(&buf[j], t->value, t->length);
        j += t->length;
    }

    assert((int) j == buflen);
    *length = buflen;
    return buf;
}

