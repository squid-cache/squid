
/*
 * $Id: ACLStrategy.h,v 1.3 2005/05/08 06:36:45 hno Exp $
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef SQUID_ACLSTRATEGY_H
#define SQUID_ACLSTRATEGY_H
#include "ACL.h"
#include "ACLData.h"

/* Perhaps this should live in ACL? */

template<class M>

class ACLStrategy
{

public:
    typedef M MatchType;
    virtual int match (ACLData<M> * &, ACLChecklist *) = 0;
    virtual bool requiresRequest() const {return false;}

    virtual bool requiresReply() const {return false;}

    virtual bool valid() const {return true;}

    virtual ~ACLStrategy(){}}

;

#endif /* SQUID_ACLSTRATEGY_H */
