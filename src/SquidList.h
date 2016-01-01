/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: none          Linked list functions (deprecated) */

#ifndef SQUID_SQUIDLIST_H_
#define SQUID_SQUIDLIST_H_

class link_list
{
public:
    void *ptr;
    link_list *next;
};

void linklistPush(link_list **, void *);
void *linklistShift(link_list **);

#endif /* SQUID_SQUIDLIST_H_ */

