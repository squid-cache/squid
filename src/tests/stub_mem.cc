/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * stub file for mem.cc
 */

#include "squid.h"

#define STUB_API "stub_mem.cc"
#include "Mem.h"
#include "STUB.h"

void
memFreeString(size_t size, void *buf)
{
    xfree(buf);
}

void *
memAllocString(size_t net_size, size_t * gross_size)
{
    *gross_size=net_size;
    return xmalloc(net_size);
}

void
memFreeBuf(size_t size, void *buf)
{
    xfree(buf);
}

void *
memAllocBuf(size_t net_size, size_t * gross_size)
{
    *gross_size=net_size;
    return xcalloc(1, net_size);
}

/* net_size is the new size, *gross size is the old gross size, to be changed to
 * the new gross size as a side-effect.
 */
void *
memReallocBuf(void *oldbuf, size_t net_size, size_t * gross_size)
{
    void *rv=xrealloc(oldbuf,net_size);
//    if (net_size > *gross_size)
//        memset(rv+net_size,0,net_size-*gross_size);
    *gross_size=net_size;
    return rv;
}

static void
cxx_xfree(void * ptr)
{
    xfree(ptr);
}

FREE *
memFreeBufFunc(size_t size)
{
    return cxx_xfree;
}

void * memAllocate(mem_type type)
{
    // let's waste plenty of memory. This should cover any possible need
    return xmalloc(64*1024);
}
void memFree(void *p, int type)
{
    xfree(p);
}
void Mem::Init(void) STUB_NOP
void memDataInit(mem_type, const char *, size_t, int, bool) STUB_NOP
int memInUse(mem_type) STUB_RETVAL(0)
void memConfigure(void) STUB_NOP

