/* $Id: stmem.cc,v 1.9 1996/04/12 21:41:40 wessels Exp $ */

/* 
 * DEBUG: Section 19          stmem:
 */

#include "squid.h"

stmem_stats sm_stats;
stmem_stats disk_stats;

#define min(x,y) ((x)<(y)? (x) : (y))

#ifndef USE_MEMALIGN
#define USE_MEMALIGN 0
#endif

void memFree(mem)
     mem_ptr mem;
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

void memFreeData(mem)
     mem_ptr mem;
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

int memFreeDataUpto(mem, target_offset)
     mem_ptr mem;
     int target_offset;
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
int memAppend(mem, data, len)
     mem_ptr mem;
     char *data;
     int len;
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
	memcpy((mem->tail->data + mem->tail->len), data, len_to_copy);
	/* Adjust the ptr and len according to what was deposited in the page */
	data += len_to_copy;
	len -= len_to_copy;
	mem->tail->len += len_to_copy;
    }
    while (len > 0) {
	len_to_copy = min(len, SM_PAGE_SIZE);
	p = (mem_node) xcalloc(1, sizeof(Mem_Node));
	p->next = NULL;
	p->len = len_to_copy;
	p->data = get_free_4k_page();
	memcpy(p->data, data, len_to_copy);

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

int memGrep(mem, string, nbytes)
     mem_ptr mem;
     char *string;
     int nbytes;
{
    mem_node p = mem->head;
    char *str_i, *mem_i;
    int i = 0, blk_idx = 0, state, goal;

    debug(19, 6, "memGrep: looking for %s in less than %d bytes.\n",
	string, nbytes);

    if (!p)
	return 0;

    if (mem->origin_offset != 0) {
	debug(19, 1, "memGrep: Some lower chunk of data has been erased. Can't do memGrep!\n");
	return 0;
    }
    str_i = string;
    mem_i = p->data;
    state = 1;
    goal = strlen(string);

    while (i < nbytes) {
	if (tolower(*mem_i++) == tolower(*str_i++))
	    state++;
	else {
	    state = 1;
	    str_i = string;
	}

	i++;
	blk_idx++;

	/* Return offset of byte beyond the matching string */
	if (state == goal)
	    return (i + 1);

	if (blk_idx >= p->len) {
	    if (p->next) {
		p = p->next;
		mem_i = p->data;
		blk_idx = 0;
	    } else
		break;
	}
    }
    return 0;
}

int memCopy(mem, offset, buf, size)
     mem_ptr mem;
     int offset;
     char *buf;
     int size;
{
    mem_node p = mem->head;
    int t_off = mem->origin_offset;
    int bytes_to_go = size;
    char *ptr_to_buf;
    int bytes_from_this_packet = 0;
    int bytes_into_this_packet = 0;

    debug(19, 6, "memCopy: offset %d: size %d\n", offset, size);

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

    memcpy(buf, p->data + bytes_into_this_packet, bytes_from_this_packet);
    bytes_to_go -= bytes_from_this_packet;
    ptr_to_buf = buf + bytes_from_this_packet;
    p = p->next;

    while (p && bytes_to_go > 0) {
	if (bytes_to_go > p->len) {
	    memcpy(ptr_to_buf, p->data, p->len);
	    ptr_to_buf += p->len;
	    bytes_to_go -= p->len;
	} else {
	    memcpy(ptr_to_buf, p->data, bytes_to_go);
	    bytes_to_go -= bytes_to_go;
	}
	p = p->next;
    }

    return size;
}


/* Do whatever is necessary to begin storage of new object */
mem_ptr memInit()
{
    mem_ptr new = (mem_ptr) xcalloc(1, sizeof(Mem_Hdr));

    new->tail = new->head = NULL;

    new->mem_free = memFree;
    new->mem_free_data = memFreeData;
    new->mem_free_data_upto = memFreeDataUpto;
    new->mem_append = memAppend;
    new->mem_copy = memCopy;
    new->mem_grep = memGrep;

    return new;
}


/* PBD 12/95: Memory allocator routines for saving and reallocating fixed 
 * size blocks rather than mallocing and freeing them */
char *get_free_4k_page()
{
    char *page = NULL;

    if (!empty_stack(&sm_stats.free_page_stack)) {
	page = pop(&sm_stats.free_page_stack);
    } else {
#if USE_MEMALIGN
	page = (char *) memalign(SM_PAGE_SIZE, SM_PAGE_SIZE);
	if (!page)
	    fatal_dump(NULL);
#else
	page = (char *) xmalloc(SM_PAGE_SIZE);
#endif
	sm_stats.total_pages_allocated++;
    }
    sm_stats.n_pages_in_use++;
    if (page == NULL)
	fatal_dump("get_free_4k_page: Null page pointer?");
    return (page);
}

void put_free_4k_page(page)
     char *page;
{
    static stack_overflow_warning_toggle;

#if USE_MEMALIGN
    if ((int) page % SM_PAGE_SIZE)
	fatal_dump("Someone tossed a string into the 4k page pool");
#endif
    if (full_stack(&sm_stats.free_page_stack)) {
	sm_stats.total_pages_allocated--;
	if (!stack_overflow_warning_toggle) {
	    debug(19, 0, "Stack of free stmem pages overflowed.  Resize it?");
	    stack_overflow_warning_toggle++;
	}
    }
    sm_stats.n_pages_in_use--;
    /* Call push regardless if it's full, cause it's just going to release the
     * page if stack is full */
    push(&sm_stats.free_page_stack, page);
}

char *get_free_8k_page()
{
    char *page = NULL;

    if (!empty_stack(&disk_stats.free_page_stack)) {
	page = pop(&disk_stats.free_page_stack);
    } else {
#if USE_MEMALIGN
	page = (char *) memalign(DISK_PAGE_SIZE, DISK_PAGE_SIZE);
	if (!page)
	    fatal_dump(NULL);
#else
	page = (char *) xmalloc(DISK_PAGE_SIZE);
#endif
	disk_stats.total_pages_allocated++;
    }
    disk_stats.n_pages_in_use++;
    if (page == NULL)
	fatal_dump("get_free_8k_page: Null page pointer?");
    return (page);
}

void put_free_8k_page(page)
     char *page;
{
    static stack_overflow_warning_toggle;

#if USE_MEMALIGN
    if ((int) page % DISK_PAGE_SIZE)
	fatal_dump("Someone tossed a string into the 8k page pool");
#endif

    if (full_stack(&disk_stats.free_page_stack)) {
	disk_stats.total_pages_allocated--;
	if (!stack_overflow_warning_toggle) {
	    debug(19, 0, "Stack of free disk pages overflowed.  Resize it?");
	    stack_overflow_warning_toggle++;
	}
    }
    disk_stats.n_pages_in_use--;
    /* Call push regardless if it's full, cause it's just going to release the
     * page if stack is full */
    push(&disk_stats.free_page_stack, page);
}

void stmemInit()
{
    sm_stats.page_size = SM_PAGE_SIZE;
    sm_stats.total_pages_allocated = 0;
    sm_stats.n_pages_free = 0;
    sm_stats.n_pages_in_use = 0;

    disk_stats.page_size = DISK_PAGE_SIZE;
    disk_stats.total_pages_allocated = 0;
    disk_stats.n_pages_free = 0;
    disk_stats.n_pages_in_use = 0;

/* use -DPURIFY=1 on the compile line to enable Purify checks */

#if !PURIFY
    /* 4096 * 10000 pages = 40MB + CacheMemMax in pages */
    init_stack(&sm_stats.free_page_stack, 10000 + (getCacheMemMax() / SM_PAGE_SIZE));
    /* 8096 * 1000 pages = 8MB */
    init_stack(&disk_stats.free_page_stack, 1000);
#else
    /* Declare a zero size page stack so that purify checks for 
     * FMRs/UMRs etc.
     */
    init_stack(&sm_stats.free_page_stack, 0);
    init_stack(&disk_stats.free_page_stack, 0);
#endif
}
