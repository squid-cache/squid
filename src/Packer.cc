/*
 * $Id: Packer.cc,v 1.2 1998/02/21 00:56:48 rousskov Exp $
 *
 * DEBUG: section ??                Packer: Uniform interface to "Storing" modules
 * AUTHOR: Alex Rousskov
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

/* see Packer.h for documentation */

/*
 * To-Do:
 */


#include "squid.h"

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

/* append()'s */
static void (*const store_append)(StoreEntry *, const char *, int) = &storeAppend;
static void (*const memBuf_append)(MemBuf *, const char *, mb_size_t) = &memBufAppend;

/* vprintf()'s */
static void (*const store_vprintf)(StoreEntry *, const char *, va_list ap) = &storeAppendVPrintf;
static void (*const memBuf_vprintf)(MemBuf *, const char *, va_list ap) = &memBufVPrintf;


void
packerToStoreInit(Packer *p, StoreEntry *e)
{
    assert(p && e);
    p->append = (append_f)store_append;
    p->vprintf = (vprintf_f)storeAppendVPrintf;
    p->real_handler = e;
}

void
packerToMemInit(Packer *p, MemBuf *mb)
{
    assert(p && mb);
    p->append = (append_f)memBuf_append;
    p->vprintf = (vprintf_f)memBuf_vprintf;
    p->real_handler = mb;
}

void
packerClean(Packer *p)
{
   assert(p);
   /* it is not really necessary to do this, but, just in case... */
   p->append = NULL;
   p->vprintf = NULL;
   p->real_handler = NULL;
}

void
packerAppend(Packer *p, const char *buf, int sz)
{
    assert(p);
    assert(p->real_handler && p->append);
    p->append(p->real_handler, buf, sz);
}

#ifdef __STDC__
void
packerPrintf(Packer *p, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
#else
void
packerPrintf(va_alist)
     va_dcl
{
    va_list args;
    Packer *p = NULL;
    const char *fmt = NULL;
    int sz = 0;
    va_start(args);
    p = va_arg(args, Packer *);
    fmt = va_arg(args, char *);
#endif
    assert(p);
    assert(p->real_handler && p->vprintf);
    tmp_debug(here) ("printf: fmt: '%s'\n", fmt);
    p->vprintf(p->real_handler, fmt, args);
    va_end(args);
}
