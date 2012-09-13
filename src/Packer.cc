
/*
 * DEBUG: section 60    Packer: A uniform interface to store-like modules
 * AUTHOR: Alex Rousskov
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

/*
 * Rationale:
 * ----------
 *
 * OK, we have to major interfaces comm.c and store.c.
 *
 * Store.c has a nice storeAppend[Printf] capability which makes "storing"
 * things easy and painless.
 *
 * Comm.c lacks commAppend[Printf] because comm does not handle its own
 * buffers (no mem_obj equivalent for comm.c).
 *
 * Thus, if one wants to be able to store _and_ Comm::Write an object, s/he
 * has to implement two almost identical functions.
 *
 * Packer
 * ------
 *
 * Packer provides for a more uniform interface to store and comm modules.
 * Packer has its own append and printf routines that "know" where to send
 * incoming data. In case of store interface, Packer sends data to
 * storeAppend.  Otherwise, Packer uses a MemBuf that can be flushed later to
 * Comm::Write.
 *
 * Thus, one can write just one function that will either "pack" things for
 * Comm::Write or "append" things to store, depending on actual packer
 * supplied.
 *
 * It is amazing how much work a tiny object can save. :)
 *
 */

/*
 * To-Do:
 */

#include "squid.h"
#include "Store.h"
#include "MemBuf.h"

/* local types */

/* local routines */

/* local constants and vars */

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
memBufAppend(MemBuf *mb, const char *buf, mb_size_t len)
{
    mb->append(buf, len);
}

static void
memBufVPrintf(MemBuf * mb, const char *fmt, va_list vargs)
{
    mb->vPrintf(fmt, vargs);
}

static void
storeEntryAppend(StoreEntry *e, const char *buf, int len)
{
    e->append(buf, len);
}

/* append()'s */
static void (*const store_append) (StoreEntry *, const char *, int) = &storeEntryAppend;
static void (*const memBuf_append) (MemBuf *, const char *, mb_size_t) = &memBufAppend;

/* vprintf()'s */
static void (*const store_vprintf) (StoreEntry *, const char *, va_list ap) = &storeAppendVPrintf;
static void (*const memBuf_vprintf) (MemBuf *, const char *, va_list ap) = &memBufVPrintf;

/* init/clean */

/* init with this to forward data to StoreEntry */
void
packerToStoreInit(Packer * p, StoreEntry * e)
{
    assert(p && e);
    p->append = (append_f) store_append;
    p->packer_vprintf = (vprintf_f) store_vprintf;
    p->real_handler = e;
    e->buffer();
}

/* init with this to accumulate data in MemBuf */
void
packerToMemInit(Packer * p, MemBuf * mb)
{
    assert(p && mb);
    p->append = (append_f) memBuf_append;
    p->packer_vprintf = (vprintf_f) memBuf_vprintf;
    p->real_handler = mb;
}

/* call this when you are done */
void
packerClean(Packer * p)
{
    assert(p);

    if (p->append == (append_f) store_append && p->real_handler)
        static_cast<StoreEntry*>(p->real_handler)->flush();

    /* it is not really necessary to do this, but, just in case... */
    p->append = NULL;
    p->packer_vprintf = NULL;
    p->real_handler = NULL;
}

void
packerAppend(Packer * p, const char *buf, int sz)
{
    assert(p);
    assert(p->real_handler && p->append);
    p->append(p->real_handler, buf, sz);
}

void
packerPrintf(Packer * p, const char *fmt,...)
{
    va_list args;
    va_start(args, fmt);

    assert(p);
    assert(p->real_handler && p->packer_vprintf);
    p->packer_vprintf(p->real_handler, fmt, args);
    va_end(args);
}
