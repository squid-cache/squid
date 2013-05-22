/*
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */
#ifndef SQUID_DLINK_H
#define SQUID_DLINK_H

class dlink_node
{

public:
    dlink_node() : data(NULL), prev(NULL), next(NULL) {}

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
void dlinkNodeDelete(dlink_node * m);
dlink_node *dlinkNodeNew(void);

#endif /* SQUID_DLINK_H */
