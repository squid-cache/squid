/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_DLINK_H
#define SQUID_DLINK_H

#include "mem/forward.h"

class dlink_node
{
    MEMPROXY_CLASS(dlink_node);
public:
    dlink_node() : data(nullptr), prev(nullptr), next(nullptr) {}

    void *data;
    dlink_node *prev;
    dlink_node *next;
};

class dlink_list
{
public:
    dlink_list() : head(NULL), tail(NULL) {}

    dlink_node *head;
    dlink_node *tail;
};

extern dlink_list ClientActiveRequests;

void dlinkAdd(void *data, dlink_node *, dlink_list *);
void dlinkAddAfter(void *, dlink_node *, dlink_node *, dlink_list *);
void dlinkAddTail(void *data, dlink_node *, dlink_list *);
void dlinkDelete(dlink_node * m, dlink_list * list);

#endif /* SQUID_DLINK_H */

