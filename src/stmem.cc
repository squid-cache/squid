
/*
 * $Id: stmem.cc,v 1.28 1996/09/26 19:54:47 wessels Exp $
 *
 * DEBUG: section 19    Memory Primitives
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
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
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

#include "squid.h"

stmem_stats sm_stats;
stmem_stats disk_stats;
stmem_stats request_pool;
stmem_stats mem_obj_pool;

#define min(x,y) ((x)<(y)? (x) : (y))

#ifndef USE_MEMALIGN
#define USE_MEMALIGN 0
#endif

static void *get_free_thing _PARAMS((stmem_stats * thing));
static void put_free_thing _PARAMS((stmem_stats * thing, void *p));
static void stmemFreeThingMemory _PARAMS((stmem_stats * thing));


void
memFree(mem_ptr mem)
{
    mem_node lastp, p = mem->head;

    if (p) {
	while (p && (p != mem->tail)) {
	    lastp = p;
	    p = p->next;
	    if (lastp) {
		put_free_4k_page(lastp->data);
		safe_free(lastp);
	    }
	}

	if (p) {
	    put_free_4k_page(p->data);
	    safe_free(p);
	}
    }
    memset(mem, '\0', sizeof(mem_ptr));		/* nuke in case ref'ed again */
    safe_free(mem);
}

void
memFreeData(mem_ptr mem)
{
    mem_node lastp, p = mem->head;

    while (p != mem->tail) {
	lastp = p;
	p = p->next;
	put_free_4k_page(lastp->data);
	safe_free(lastp);
    }

    if (p != NULL) {
	put_free_4k_page(p->data);
	safe_free(p);
	p = NULL;
    }
    mem->head = mem->tail = NULL;	/* detach in case ref'd */
    mem->origin_offset = 0;
}

int
memFreeDataUpto(mem_ptr mem, int target_offset)
{
    int current_offset = mem->origin_offset;
    mem_node lastp, p = mem->head;

    while (p && ((current_offset + p->len) <= target_offset)) {
	if (p == mem->tail) {
	    /* keep the last one to avoid change to other part of code */
	    mem->head = mem->tail;
	    mem->origin_offset = current_offset;
	    return current_offset;
	} else {
	    lastp = p;
	    p = p->next;
	    current_offset += lastp->len;
	    put_free_4k_page(lastp->data);
	    safe_free(lastp);
	}
    }

    mem->head = p;
    mem->origin_offset = current_offset;
    if (current_offset < target_offset) {
	/* there are still some data left. */
	return current_offset;
    }
    if (current_offset != target_offset) {
	debug(19, 1, "memFreeDataBehind: This shouldn't happen. Some odd condition.\n");
	debug(19, 1, "   Current offset: %d  Target offset: %d  p: %p\n",
	    current_offset, target_offset, p);
    }
    return current_offset;

}


/* Append incoming data. */
int
memAppend(mem_ptr mem, char *data, int len)
{
    mem_node p;
    int avail_len;
    int len_to_copy;

    debug(19, 6, "memAppend: len %d\n", len);

    /* Does the last block still contain empty space? 
     * If so, fill out the block before dropping into the
     * allocation loop */

    if (mem->head && mem->tail && (mem->tail->len < SM_PAGE_SIZE)) {
	avail_len = SM_PAGE_SIZE - (mem->tail->len);
	len_to_copy = min(avail_len, len);
	xmemcpy((mem->tail->data + mem->tail->len), data, len_to_copy);
	/* Adjust the ptr and len according to what was deposited in the page */
	data += len_to_copy;
	len -= len_to_copy;
	mem->tail->len += len_to_copy;
    }
    while (len > 0) {
	len_to_copy = min(len, SM_PAGE_SIZE);
	p = xcalloc(1, sizeof(Mem_Node));
	p->next = NULL;
	p->len = len_to_copy;
	p->data = get_free_4k_page();
	xmemcpy(p->data, data, len_to_copy);

	if (!mem->head) {
	    /* The chain is empty */
	    mem->head = mem->tail = p;
	} else {
	    /* Append it to existing chain */
	    mem->tail->next = p;
	    mem->tail = p;
	}
	len -= len_to_copy;
	data += len_to_copy;
    }
    return len;
}

int
memCopy(mem_ptr mem, int offset, char *buf, int size)
{
    mem_node p = mem->head;
    int t_off = mem->origin_offset;
    int bytes_to_go = size;
    char *ptr_to_buf = NULL;
    int bytes_from_this_packet = 0;
    int bytes_into_this_packet = 0;

    debug(19, 6, "memCopy: offset %d: size %d\n", offset, size);

    if (p == NULL)
	fatal_dump("memCopy: NULL mem_node");

    if (size <= 0)
	return size;

    /* Seek our way into store */
    while ((t_off + p->len) < offset) {
	t_off += p->len;
	if (p->next)
	    p = p->next;
	else {
	    debug(19, 1, "memCopy: Offset: %d is off limit of current object of %d\n", t_off, offset);
	    return 0;
	}
    }

    /* Start copying begining with this block until
     * we're satiated */

    bytes_into_this_packet = offset - t_off;
    bytes_from_this_packet = min(bytes_to_go,
	p->len - bytes_into_this_packet);

    xmemcpy(buf, p->data + bytes_into_this_packet, bytes_from_this_packet);
    bytes_to_go -= bytes_from_this_packet;
    ptr_to_buf = buf + bytes_from_this_packet;
    p = p->next;

    while (p && bytes_to_go > 0) {
	if (bytes_to_go > p->len) {
	    xmemcpy(ptr_to_buf, p->data, p->len);
	    ptr_to_buf += p->len;
	    bytes_to_go -= p->len;
	} else {
	    xmemcpy(ptr_to_buf, p->data, bytes_to_go);
	    bytes_to_go -= bytes_to_go;
	}
	p = p->next;
    }

    return size;
}


/* Do whatever is necessary to begin storage of new object */
mem_ptr
memInit(void)
{
    mem_ptr new = xcalloc(1, sizeof(Mem_Hdr));
    new->tail = new->head = NULL;
    new->mem_free = memFree;
    new->mem_free_data = memFreeData;
    new->mem_free_data_upto = memFreeDataUpto;
    new->mem_append = memAppend;
    new->mem_copy = memCopy;
    return new;
}

static void *
get_free_thing(stmem_stats * thing)
{
    void *p = NULL;
    if (!empty_stack(&thing->free_page_stack)) {
	p = pop(&thing->free_page_stack);
	if (p == NULL)
	    fatal_dump("get_free_thing: NULL pointer?");
    } else {
	p = xmalloc(thing->page_size);
	thing->total_pages_allocated++;
    }
    thing->n_pages_in_use++;
    memset(p, '\0', thing->page_size);
    return p;
}

void *
get_free_request_t(void)
{
    return get_free_thing(&request_pool);
}

void *
get_free_mem_obj(void)
{
    return get_free_thing(&mem_obj_pool);
}

char *
get_free_4k_page(void)
{
    return (char *) get_free_thing(&sm_stats);
}

char *
get_free_8k_page(void)
{
    return (char *) get_free_thing(&disk_stats);
}

static void
put_free_thing(stmem_stats * thing, void *p)
{
    if (p == NULL)
	fatal_dump("Somebody is putting a NULL pointer!");
    thing->n_pages_in_use--;
    if (thing->total_pages_allocated > thing->max_pages) {
	xfree(p);
	thing->total_pages_allocated--;
    } else if (full_stack(&thing->free_page_stack)) {
	xfree(p);
	thing->total_pages_allocated--;
    } else {
	push(&thing->free_page_stack, p);
    }
}

void
put_free_request_t(void *req)
{
    put_free_thing(&request_pool, req);
}

void
put_free_mem_obj(void *mem)
{
    put_free_thing(&mem_obj_pool, mem);
}

void
put_free_4k_page(void *page)
{
    put_free_thing(&sm_stats, page);
}

void
put_free_8k_page(void *page)
{
    put_free_thing(&disk_stats, page);
}

void
stmemInit(void)
{
    sm_stats.page_size = SM_PAGE_SIZE;
    sm_stats.total_pages_allocated = 0;
    sm_stats.n_pages_in_use = 0;
    sm_stats.max_pages = (Config.Mem.maxSize / SM_PAGE_SIZE) >> 1;

    disk_stats.page_size = DISK_PAGE_SIZE;
    disk_stats.total_pages_allocated = 0;
    disk_stats.n_pages_in_use = 0;
    disk_stats.max_pages = 200;

    request_pool.page_size = sizeof(request_t);
    request_pool.total_pages_allocated = 0;
    request_pool.n_pages_in_use = 0;
    request_pool.max_pages = FD_SETSIZE >> 3;

    mem_obj_pool.page_size = sizeof(MemObject);
    mem_obj_pool.total_pages_allocated = 0;
    mem_obj_pool.n_pages_in_use = 0;
    mem_obj_pool.max_pages = FD_SETSIZE >> 3;

#if PURIFY
    debug(19, 0, "Disabling stacks under purify\n");
    sm_stats.max_pages = 0;
    disk_stats.max_pages = 0;
    request_pool.max_pages = 0;
    mem_obj_pool.max_pages = 0;
#endif
    if (!opt_mem_pools) {
	sm_stats.max_pages = 0;
	disk_stats.max_pages = 0;
	request_pool.max_pages = 0;
	mem_obj_pool.max_pages = 0;
    }
    init_stack(&sm_stats.free_page_stack, sm_stats.max_pages);
    init_stack(&disk_stats.free_page_stack, disk_stats.max_pages);
    init_stack(&request_pool.free_page_stack, request_pool.max_pages);
    init_stack(&mem_obj_pool.free_page_stack, mem_obj_pool.max_pages);
}

static void
stmemFreeThingMemory(stmem_stats * thing)
{
    void *p;
    while (!empty_stack(&thing->free_page_stack)) {
	p = pop(&thing->free_page_stack);
	safe_free(p);
    }
    stackFreeMemory(&thing->free_page_stack);
}

void
stmemFreeMemory(void)
{
    stmemFreeThingMemory(&sm_stats);
    stmemFreeThingMemory(&disk_stats);
    stmemFreeThingMemory(&request_pool);
    stmemFreeThingMemory(&mem_obj_pool);
}
