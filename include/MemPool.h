/*
 * $Id: MemPool.h,v 1.3 1998/02/25 07:43:02 rousskov Exp $
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

#ifndef _MEM_POOL_H_
#define _MEM_POOL_H_

#include "Stack.h"

/* see MemPool.c for documentation */

struct _MemPool {
    /* public, read only */
    char *name;      /* an optional label or name for this pool */
    size_t obj_size;

    /* protected, do not use these, use interface functions instead */
    char *buf;
    Stack *static_stack;
    Stack *dynamic_stack;

    size_t alloc_count;
    size_t free_count;
    size_t alloc_high_water;

    /* private, never touch this */
    char *_buf_end;
};

typedef struct _MemPool MemPool;

extern MemPool *memPoolCreate(size_t preallocCnt, size_t dynStackCnt, size_t objSz, const char *poolName);
extern void memPoolDestroy(MemPool *mp);
extern void *memPoolGetObj(MemPool *mp);
extern void memPoolPutObj(MemPool *mp, void *obj);
extern const char *memPoolReport(MemPool *mp);


#endif /* ndef _MEM_POOL_H_ */
