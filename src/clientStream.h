
/*
 * $Id: clientStream.h,v 1.1 2002/09/24 10:46:43 robertc Exp $
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

#ifndef SQUID_CLIENTSTREAM_H
#define SQUID_CLIENTSTREAM_H

#include "StoreIOBuffer.h"

typedef struct _clientStreamNode clientStreamNode;
/* client stream read callback */
typedef void CSCB(clientStreamNode *, clientHttpRequest *, HttpReply *, StoreIOBuffer);
/* client stream read */
typedef void CSR(clientStreamNode *, clientHttpRequest *);
/* client stream detach */
typedef void CSD(clientStreamNode *, clientHttpRequest *);
typedef clientStream_status_t CSS(clientStreamNode *, clientHttpRequest *);


struct _clientStreamNode {
    dlink_node node;
    dlink_list *head;		/* sucks I know, but hey, the interface is limited */
    CSR *readfunc;
    CSCB *callback;
    CSD *detach;		/* tell this node the next one downstream wants no more data */
    CSS *status;
    void *data;			/* Context for the node */
    StoreIOBuffer readBuffer;	/* what, where and how much this node wants */
};

/* clientStream.c */
extern void clientStreamInit(dlink_list *, CSR *, CSD *, CSS *, void *, CSCB *, CSD *, void *, StoreIOBuffer tailBuffer);
extern void clientStreamInsertHead(dlink_list *, CSR *, CSCB *, CSD *, CSS *, void *);
extern clientStreamNode *clientStreamNew(CSR *, CSCB *, CSD *, CSS *, void *);
extern void clientStreamCallback(clientStreamNode *, clientHttpRequest *, HttpReply *, StoreIOBuffer replyBuffer);
extern void clientStreamRead(clientStreamNode *, clientHttpRequest *, StoreIOBuffer readBuffer);
extern void clientStreamDetach(clientStreamNode *, clientHttpRequest *);
extern void clientStreamAbort(clientStreamNode *, clientHttpRequest *);
extern clientStream_status_t clientStreamStatus(clientStreamNode *, clientHttpRequest *);

#endif /* SQUID_CLIENTSTREAM_H */
