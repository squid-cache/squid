/*
 * $Id: MemPool.c,v 1.2 1998/02/21 00:56:38 rousskov Exp $
 *
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

/*
 * MemPool handles allocation and accounting for fixed size objects or buffers.
 * It optimizes run-time allocation using a pre-allocated continuos pool of free
 * buffers.  MemPool does not know about the contents of a buffer.
 */

/*
 * Warning: Never use *alloc or *free on objects maintained by MemPool!
 */

/*
 * To-do:
 *    - src/stmem routines could use some of lib/MemPool stuff
 */


#if 0

Synopsis:

	/*
	 * creating a pool named "urls" for objects of size objSz with objCnt
	 * pre-allocated objects and 10% for dynamic stack.  Any of the first two
	 * parameters can be 0. If name is NULL "anonymous" will be used instead
	 */
	MemPool *mp1 = memPoolCreate(objCnt, objCnt/10, objSz, "urls");

	/*
	 * getting a new object from a pool; object buffer is initialized with 0s
	 */
	void *buf = memPoolGetObj(mp1);

	/*
	 * returning an object back
	 */
	memPoolPutObj(mp1, buf);

	/*
	 * accounting: generate report as an ASCII string
	 * warning: static buffer is used, strdup your copy!
	 */
	char *report = xstrdup(memPoolReport());

	/* destroy your pools when done playing! */
	memPoolDestroy(mp1);

#endif /* synopsis */

#include "config.h"
#if HAVE_ASSERT_H
#include <assert.h>
#endif
#include "util.h"
#include "snprintf.h"
#include "MemPool.h"


MemPool *
memPoolCreate(size_t preallocCnt, size_t dynStackCnt, size_t objSz, const char *poolName)
{
    MemPool *mp = xcalloc(1, sizeof(MemPool));
    mp->buf = xcalloc(preallocCnt, objSz);
    mp->obj_size = objSz;
    mp->name = xstrdup(poolName ? poolName : "anonymous");
    mp->_buf_end = mp->buf + objSz*preallocCnt; /* internal, never dereference this! */
    mp->static_stack = stackCreate(preallocCnt);
    mp->dynamic_stack = stackCreate(dynStackCnt);
    /* other members are initialized with 0 because of calloc() */
    /* push all pre-allocated memory on stack because it is currently free */
    while(preallocCnt-- > 0)
	stackPush(mp->static_stack, mp->buf + objSz*preallocCnt);
    return mp;
}

void
memPoolDestroy(MemPool *mp)
{
    assert(mp);
    /* could also warn if some objects are left */
    stackDestroy(mp->static_stack);
    stackDestroy(mp->dynamic_stack);
    xfree(mp->buf);
    xfree(mp->name);
    xfree(mp);
}

/*
 * find a free buffer:
 * if none on the pool stack, use alloc stack; 
 * if none there, use alloc
 * never fails
 */
void *
memPoolGetObj2(MemPool *mp)
{
    assert(mp);
    if (mp->static_stack->count)
	return stackPop(mp->static_stack);
    else
    if (mp->dynamic_stack->count)
	return stackPop(mp->dynamic_stack);
    /* have to alloc, monitor high whater mark */
    if (++mp->alloc_count - mp->free_count > mp->alloc_high_water)
	mp->alloc_high_water = mp->alloc_count - mp->free_count;
    return xcalloc(1, mp->obj_size);
}

void *
memPoolGetObj(MemPool *mp)
{
    void *obj = memPoolGetObj2(mp);
    /*printf("memPoolGetObj: %p :  %d -> %d , %d >= %d\n", obj, mp->static_stack->count, mp->dynamic_stack->count, mp->alloc_count, mp->free_count);*/
    return obj;
}

/*
 * return object to the pool; put on the corresponding stack or free if
 * corresponding stack is full
 */
void
memPoolPutObj(MemPool *mp, void *obj)
{
    assert(mp);
    /*printf("memPoolPutObj: %p :  %d >= %d\n", obj, mp->alloc_count, mp->free_count);*/
    /* static object? */
    if (mp->buf <= (char*)obj && mp->_buf_end > (char*)obj) {
	assert(!mp->static_stack->is_full); /* never full if we got here! */
	stackPush(mp->static_stack, obj);
    } else
    /* dynamic object, but stack may be full */
    if (!mp->dynamic_stack->is_full) {
	assert(mp->alloc_count);
	stackPush(mp->dynamic_stack, obj);
    } else {
        /* free-ing is the last option */
	mp->free_count++;
	assert(mp->free_count <= mp->alloc_count);
	xfree(obj); /* do this after assert */
    }
}

const char *
memPoolReport(MemPool *mp)
{
    static char buf[512]; /* we do not use LOCALL_ARRAY in squid/lib, do we? */

    assert(mp);
    snprintf(buf, sizeof(buf),
	"pool %s: obj_sz: %ud cap: %ud/%ud "
	"stat: +%uld-%uld dyn: +%uld-%uld alloc: +%uld/-%uld<%uld",
	mp->name,
	mp->obj_size,
	mp->static_stack->capacity,
	mp->dynamic_stack->capacity,
	mp->static_stack->push_count,
	mp->static_stack->pop_count,
	mp->dynamic_stack->push_count,
	mp->dynamic_stack->pop_count,
	mp->alloc_count,
	mp->free_count,
	mp->alloc_high_water);

    return buf;
}
