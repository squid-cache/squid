
/*
 * $Id: stmem.cc,v 1.57 1998/02/02 21:16:33 wessels Exp $
 *
 * DEBUG: section 19    Memory Primitives
 * AUTHOR: Harvest Derived
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

void
stmemFree(mem_hdr * mem)
{
    mem_node *lastp;
    mem_node *p = mem->head;

    if (p) {
	while (p && (p != mem->tail)) {
	    lastp = p;
	    p = p->next;
	    if (lastp) {
		memFree(MEM_STMEM_BUF, lastp->data);
		store_mem_size -= SM_PAGE_SIZE;
		safe_free(lastp);
	    }
	}

	if (p) {
	    memFree(MEM_STMEM_BUF, p->data);
	    store_mem_size -= SM_PAGE_SIZE;
	    safe_free(p);
	}
    }
    memFree(MEM_MEM_HDR, mem);
}

int
stmemFreeDataUpto(mem_hdr * mem, int target_offset)
{
    int current_offset = mem->origin_offset;
    mem_node *lastp;
    mem_node *p = mem->head;
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
	    memFree(MEM_STMEM_BUF, lastp->data);
	    store_mem_size -= SM_PAGE_SIZE;
	    safe_free(lastp);
	}
    }
    mem->head = p;
    mem->origin_offset = current_offset;
    if (current_offset < target_offset) {
	/* there are still some data left. */
	return current_offset;
    }
    assert(current_offset == target_offset);
    return current_offset;
}

/* Append incoming data. */
void
stmemAppend(mem_hdr * mem, const char *data, int len)
{
    mem_node *p;
    int avail_len;
    int len_to_copy;
    debug(19, 6) ("memAppend: len %d\n", len);
    /* Does the last block still contain empty space? 
     * If so, fill out the block before dropping into the
     * allocation loop */
    if (mem->head && mem->tail && (mem->tail->len < SM_PAGE_SIZE)) {
	avail_len = SM_PAGE_SIZE - (mem->tail->len);
	len_to_copy = XMIN(avail_len, len);
	xmemcpy((mem->tail->data + mem->tail->len), data, len_to_copy);
	/* Adjust the ptr and len according to what was deposited in the page */
	data += len_to_copy;
	len -= len_to_copy;
	mem->tail->len += len_to_copy;
    }
    while (len > 0) {
	len_to_copy = XMIN(len, SM_PAGE_SIZE);
	p = xcalloc(1, sizeof(mem_node));
	p->next = NULL;
	p->len = len_to_copy;
	p->data = memAllocate(MEM_STMEM_BUF, 1);
	store_mem_size += SM_PAGE_SIZE;
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
}

ssize_t
stmemCopy(const mem_hdr * mem, off_t offset, char *buf, size_t size)
{
    mem_node *p = mem->head;
    off_t t_off = mem->origin_offset;
    size_t bytes_to_go = size;
    char *ptr_to_buf = NULL;
    int bytes_from_this_packet = 0;
    int bytes_into_this_packet = 0;
    debug(19, 6) ("memCopy: offset %d: size %d\n", offset, size);
    if (p == NULL)
	return 0;
    assert(size > 0);
    /* Seek our way into store */
    while ((t_off + p->len) < offset) {
	t_off += p->len;
	if (!p->next) {
	    debug(19, 1) ("memCopy: p->next == NULL\n");
	    return 0;
	}
	assert(p->next);
	p = p->next;
    }
    /* Start copying begining with this block until
     * we're satiated */
    bytes_into_this_packet = offset - t_off;
    bytes_from_this_packet = XMIN(bytes_to_go, p->len - bytes_into_this_packet);
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
    return size - bytes_to_go;
}
