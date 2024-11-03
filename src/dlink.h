/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_DLINK_H
#define SQUID_SRC_DLINK_H

#include "mem/forward.h"

class dlink_node
{
    MEMPROXY_CLASS(dlink_node);
public:
    void *data = nullptr;
    dlink_node *prev = nullptr;
    dlink_node *next = nullptr;
};

class dlink_list
{
public:
    dlink_node *head = nullptr;
    dlink_node *tail = nullptr;
};

extern dlink_list ClientActiveRequests;

void dlinkAdd(void *data, dlink_node *, dlink_list *);
void dlinkAddAfter(void *, dlink_node *, dlink_node *, dlink_list *);
void dlinkAddTail(void *data, dlink_node *, dlink_list *);
void dlinkDelete(dlink_node * m, dlink_list * list);

#endif /* SQUID_SRC_DLINK_H */

