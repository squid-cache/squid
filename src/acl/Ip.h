/*
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

#ifndef SQUID_ACLIP_H
#define SQUID_ACLIP_H

#include "acl/Acl.h"
#include "splay.h"
#include "ip/IpAddress.h"

/// \ingroup ACLAPI
class acl_ip_data
{

public:
    MEMPROXY_CLASS(acl_ip_data);
    static acl_ip_data *FactoryParse(char const *);
    static int NetworkCompare(acl_ip_data * const & a, acl_ip_data * const &b);

    acl_ip_data ();

    acl_ip_data (IpAddress const &, IpAddress const &, IpAddress const &, acl_ip_data *);
    void toStr(char *buf, int len) const;

    IpAddress addr1;

    IpAddress addr2;

    IpAddress mask; /**< \todo This should perhapse be stored as a CIDR range now instead of a full IP mask. */

    acl_ip_data *next;		/**< used for parsing, not for storing */

private:

    static bool DecodeMask(const char *asc, IpAddress &mask, int string_format_type);
};

MEMPROXY_CLASS_INLINE(acl_ip_data);

/// \ingroup ACLAPI
class ACLIP : public ACL
{

public:
    void *operator new(size_t);
    void operator delete(void *);

    ACLIP() : data(NULL) {}

    ~ACLIP();

    typedef SplayNode<acl_ip_data *> IPSplay;

    virtual char const *typeString() const = 0;
    virtual void parse();
    //    virtual bool isProxyAuth() const {return true;}
    virtual int match(ACLChecklist *checklist) = 0;
    virtual wordlist *dump() const;
    virtual bool empty () const;

protected:

    int match(IpAddress &);
    IPSplay *data;

private:
    static void DumpIpListWalkee(acl_ip_data * const & ip, void *state);
};

#endif /* SQUID_ACLIP_H */
