
/*
 * $Id: ACLChecklist.h,v 1.1 2003/01/28 01:29:32 robertc Exp $
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

#ifndef SQUID_ACLCHECKLIST_H
#define SQUID_ACLCHECKLIST_H

#include "typedefs.h"

class ACLChecklist {
  public:
    void *operator new(size_t);
    void operator delete(void *);
    void deleteSelf() const;

    ACLChecklist();
    ~ACLChecklist();

    void checkCallback(allow_t answer);
    
    const acl_access *accessList;
    struct in_addr src_addr;
    struct in_addr dst_addr;
    struct in_addr my_addr;
    unsigned short my_port;
    request_t *request;
    /* for acls that look at reply data */
    HttpReply *reply;
    ConnStateData *conn;	/* hack for ident and NTLM */
    char rfc931[USER_IDENT_SZ];
    auth_user_request_t *auth_user_request;
    acl_lookup_state state[ACL_ENUM_MAX];
#if SQUID_SNMP
    char *snmp_community;
#endif
    PF *callback;
    void *callback_data;
    external_acl_entry *extacl_entry;
private:
    CBDATA_CLASS(ACLChecklist);
};

#endif /* SQUID_ACLCHECKLIST_H */
