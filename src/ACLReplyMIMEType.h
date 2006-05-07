
/*
 * $Id: ACLReplyMIMEType.h,v 1.8 2006/05/06 22:13:18 wessels Exp $
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

#ifndef SQUID_ACLREPLYMIMETYPE_H
#define SQUID_ACLREPLYMIMETYPE_H
#include "ACL.h"
#include "ACLData.h"
#include "ACLReplyHeaderStrategy.h"
#include "ACLStrategised.h"
#include "ACLChecklist.h"
#include "HttpReply.h"

class ACLReplyMIMEType
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<char const *> RegistryEntry_;
};

/* partial specialisation */

template <>
int
ACLReplyHeaderStrategy<HDR_CONTENT_TYPE>::match (ACLData<char const *> * &data, ACLChecklist *checklist)
{
    char const *theHeader = checklist->reply->header.getStr(HDR_CONTENT_TYPE);

    if (NULL == theHeader)
        theHeader = "";

    return data->match(theHeader);
}

#endif /* SQUID_ACLREPLYMIMETYPE_H */
