/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: none          Linked list functions (deprecated) */

#include "squid.h"
#include "Mem.h"
#include "SquidList.h"
#include "typedefs.h"

/* This should go away, in favour of the List template class */

void
linklistPush(link_list ** L, void *p)
{
    link_list *l = (link_list *)memAllocate(MEM_LINK_LIST);
    l->next = NULL;
    l->ptr = p;

    while (*L)
        L = &(*L)->next;

    *L = l;
}

void *
linklistShift(link_list ** L)
{
    void *p;
    link_list *l;

    if (NULL == *L)
        return NULL;

    l = *L;

    p = l->ptr;

    *L = (*L)->next;

    memFree(l, MEM_LINK_LIST);

    return p;
}

