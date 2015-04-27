/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 60    Generic Data Packer */

#include "squid.h"
#include "Packer.h"
#include "Store.h"

/*
 * We do have one potential problem here. Both append_f and vprintf_f types
 * cannot match real functions precisely (at least because of the difference in
 * the type of the first parameter). Thus, we have to use type cast. If somebody
 * changes the prototypes of real functions, Packer will not notice that because
 * of the type cast.
 *
 * Solution: we use the constants below to *hard code* current prototypes of
 * real functions. If real prototypes change, these constants will produce a
 * warning (e.g., "warning: assignment from incompatible pointer type").
 */

static void
storeEntryAppend(StoreEntry *e, const char *buf, int len)
{
    e->append(buf, len);
}

/* append()'s */
static void (*const store_append) (StoreEntry *, const char *, int) = &storeEntryAppend;

/* vprintf()'s */
static void (*const store_vprintf) (StoreEntry *, const char *, va_list ap) = &storeAppendVPrintf;

/* init/clean */

/* init with this to forward data to StoreEntry */
void
packerToStoreInit(Packer * p, StoreEntry * e)
{
    assert(p && e);
    p->append_ = (append_f) store_append;
    p->packer_vprintf = (vprintf_f) store_vprintf;
    p->real_handler = e;
    e->buffer();
}

Packer::~Packer()
{
    if (append_ == (append_f) store_append && real_handler)
        static_cast<StoreEntry*>(real_handler)->flush();

    /* it is not really necessary to do this, but, just in case... */
    append_ = NULL;
    packer_vprintf = NULL;
    real_handler = NULL;
}

void
Packer::append(const char *buf, int sz)
{
    assert(real_handler && append_);
    append_(real_handler, buf, sz);
}

void
Packer::vappendf(const char *fmt, va_list args)
{
    assert(real_handler && packer_vprintf);
    packer_vprintf(real_handler, fmt, args);
}

