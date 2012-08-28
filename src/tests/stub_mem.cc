/*
 * stub file for mem.cc
 */

#include "squid.h"

#define STUB_API "stub_mem.cc"
#include "STUB.h"
#include "Mem.h"

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

void * memAllocate(mem_type type) STUB_RETVAL(NULL)
void memFree(void *p, int type) STUB
