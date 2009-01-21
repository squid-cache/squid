/*
 * $Id$
 *
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

#include "config.h"

class dlink_node
{

public:
    dlink_node() : data(NULL), prev(NULL), next(NULL) {}

    void *data;
    dlink_node *prev;
    dlink_node *next;
};

struct dlink_list {
    dlink_node *head;
    dlink_node *tail;
};

/* mported form globals.h */
extern dlink_list ClientActiveRequests;

/* imported directly from protos.h */

SQUIDCEXTERN void dlinkAdd(void *data, dlink_node *, dlink_list *);
SQUIDCEXTERN void dlinkAddAfter(void *, dlink_node *, dlink_node *, dlink_list *);
SQUIDCEXTERN void dlinkAddTail(void *data, dlink_node *, dlink_list *);
SQUIDCEXTERN void dlinkDelete(dlink_node * m, dlink_list * list);
SQUIDCEXTERN void dlinkNodeDelete(dlink_node * m);
SQUIDCEXTERN dlink_node *dlinkNodeNew(void);

#endif /* SQUID_DLINK_H */
