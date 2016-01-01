/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "dlink.h"

/* dlink are Mem-pooled */
#include "MemPool.h"

dlink_list ClientActiveRequests;

MemAllocator *dlink_node_pool = NULL;

dlink_node *
dlinkNodeNew()
{
    if (dlink_node_pool == NULL)
        dlink_node_pool = memPoolCreate("Dlink list nodes", sizeof(dlink_node));

    /* where should we call delete dlink_node_pool;dlink_node_pool = NULL; */
    return (dlink_node *)dlink_node_pool->alloc();
}

/** The node needs to be unlinked FIRST */
void
dlinkNodeDelete(dlink_node * m)
{
    if (m == NULL)
        return;

    dlink_node_pool->freeOne(m);
}

void
dlinkAdd(void *data, dlink_node * m, dlink_list * list)
{
    m->data = data;
    m->prev = NULL;
    m->next = list->head;

    if (list->head)
        list->head->prev = m;

    list->head = m;

    if (list->tail == NULL)
        list->tail = m;
}

void
dlinkAddAfter(void *data, dlink_node * m, dlink_node * n, dlink_list * list)
{
    m->data = data;
    m->prev = n;
    m->next = n->next;

    if (n->next)
        n->next->prev = m;
    else {
        assert(list->tail == n);
        list->tail = m;
    }

    n->next = m;
}

void
dlinkAddTail(void *data, dlink_node * m, dlink_list * list)
{
    m->data = data;
    m->next = NULL;
    m->prev = list->tail;

    if (list->tail)
        list->tail->next = m;

    list->tail = m;

    if (list->head == NULL)
        list->head = m;
}

void
dlinkDelete(dlink_node * m, dlink_list * list)
{
    if (m->next)
        m->next->prev = m->prev;

    if (m->prev)
        m->prev->next = m->next;

    if (m == list->head)
        list->head = m->next;

    if (m == list->tail)
        list->tail = m->prev;

    m->next = m->prev = NULL;
}

