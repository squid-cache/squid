/*
 * $Id: acl_noncore.cc,v 1.5 2007/04/28 22:26:37 hno Exp $
 *
 * DEBUG: section 28    Access Control
 * AUTHOR: Duane Wessels
 *
 * This file contains ACL routines that are not part of the 
 * ACL class, nor any other class yet, and that need to be
 * factored into appropriate places. They are here to reduce 
 * unneeded dependencies between the ACL class and the rest
 * of squid.
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

#include "squid.h"
#include "ACL.h"
#include "ACLChecklist.h"
#include "ConfigParser.h"
#include "errorpage.h"
#include "HttpRequest.h"


/* does name lookup, returns page_id */
err_type
aclGetDenyInfoPage(acl_deny_info_list ** head, const char *name, int redirect_allowed)
{
    acl_deny_info_list *A = NULL;

    debugs(28, 9, "aclGetDenyInfoPage: got called for " << name);


    for (A = *head; A; A = A->next) {
        acl_name_list *L = NULL;

        if (!redirect_allowed && strchr(A->err_page_name, ':')) {
            debugs(28, 3, "aclGetDenyInfoPage: WARNING, unexpected codepath taken");
            continue;
        }

        for (L = A->acl_list; L; L = L->next) {
            if (!strcmp(name, L->name)) {
                debugs(28, 8, "aclGetDenyInfoPage: match on " << name);
                return A->err_page_id;
            }

        }
    }

    debugs(28, 8, "aclGetDenyInfoPage: no match");
    return ERR_NONE;
}

/* does name lookup, returns if it is a proxy_auth acl */
int
aclIsProxyAuth(const char *name)
{
    debugs(28, 5, "aclIsProxyAuth: called for " << name);

    if (NULL == name)
        return false;

    ACL *a;

    if ((a = ACL::FindByName(name))) {
        debugs(28, 5, "aclIsProxyAuth: returning " << a->isProxyAuth());
        return a->isProxyAuth();
    }

    debugs(28, 3, "aclIsProxyAuth: WARNING, called for nonexistent ACL");
    return false;
}


/* maex@space.net (05.09.96)
 *    get the info for redirecting "access denied" to info pages
 *      TODO (probably ;-)
 *      currently there is no optimization for
 *      - more than one deny_info line with the same url
 *      - a check, whether the given acl really is defined
 *      - a check, whether an acl is added more than once for the same url
 */

void
aclParseDenyInfoLine(acl_deny_info_list ** head)
{
    char *t = NULL;
    acl_deny_info_list *A = NULL;
    acl_deny_info_list *B = NULL;
    acl_deny_info_list **T = NULL;
    acl_name_list *L = NULL;
    acl_name_list **Tail = NULL;

    /* first expect a page name */

    if ((t = strtok(NULL, w_space)) == NULL) {
        debugs(28, 0, "aclParseDenyInfoLine: " << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, 0, "aclParseDenyInfoLine: missing 'error page' parameter.");
        return;
    }

    A = (acl_deny_info_list *)memAllocate(MEM_ACL_DENY_INFO_LIST);
    A->err_page_id = errorReservePageId(t);
    A->err_page_name = xstrdup(t);
    A->next = (acl_deny_info_list *) NULL;
    /* next expect a list of ACL names */
    Tail = &A->acl_list;

    while ((t = strtok(NULL, w_space))) {
        L = (acl_name_list *)memAllocate(MEM_ACL_NAME_LIST);
        xstrncpy(L->name, t, ACL_NAME_SZ);
        *Tail = L;
        Tail = &L->next;
    }

    if (A->acl_list == NULL) {
        debugs(28, 0, "aclParseDenyInfoLine: " << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, 0, "aclParseDenyInfoLine: deny_info line contains no ACL's, skipping");
        memFree(A, MEM_ACL_DENY_INFO_LIST);
        return;
    }

    for (B = *head, T = head; B; T = &B->next, B = B->next)

        ;	/* find the tail */
    *T = A;
}

void
aclParseAccessLine(ConfigParser &parser, acl_access ** head)
{
    char *t = NULL;
    acl_access *A = NULL;
    acl_access *B = NULL;
    acl_access **T = NULL;

    /* first expect either 'allow' or 'deny' */

    if ((t = strtok(NULL, w_space)) == NULL) {
        debugs(28, 0, "aclParseAccessLine: " << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, 0, "aclParseAccessLine: missing 'allow' or 'deny'.");
        return;
    }

    A = new acl_access;

    if (!strcmp(t, "allow"))
        A->allow = ACCESS_ALLOWED;
    else if (!strcmp(t, "deny"))
        A->allow = ACCESS_DENIED;
    else {
        debugs(28, 0, "aclParseAccessLine: " << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, 0, "aclParseAccessLine: expecting 'allow' or 'deny', got '" << t << "'.");
        delete A;
        return;
    }

    aclParseAclList(parser, &A->aclList);

    if (A->aclList == NULL) {
        debugs(28, 0, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, 0, "aclParseAccessLine: Access line contains no ACL's, skipping");
        delete A;
        return;
    }

    A->cfgline = xstrdup(config_input_line);
    /* Append to the end of this list */

    for (B = *head, T = head; B; T = &B->next, B = B->next)

        ;
    *T = A;

    /* We lock _acl_access structures in ACLChecklist::check() */
}

void
aclParseAclList(ConfigParser &parser, acl_list ** head)
{
    acl_list **Tail = head;	/* sane name in the use below */
    ACL *a = NULL;
    char *t;

    /* next expect a list of ACL names, possibly preceeded
     * by '!' for negation */

    while ((t = strtok(NULL, w_space))) {
        acl_list *L = new ACLList;

        if (*t == '!') {
            L->negated (true);
            t++;
        }

        debugs(28, 3, "aclParseAccessLine: looking for ACL name '" << t << "'");
        a = ACL::FindByName(t);

        if (a == NULL) {
            debugs(28, 0, "aclParseAccessLine: ACL name '" << t << "' not found.");
            delete L;
            parser.destruct();
            continue;
        }

        L->_acl = a;
        *Tail = L;
        Tail = &L->next;
    }
}



/*********************/
/* Destroy functions */
/*********************/

void
aclDestroyAcls(ACL ** head)
{
    ACL *next = NULL;

    debugs(28, 8, "aclDestroyACLs: invoked");

    for (ACL *a = *head; a; a = next) {
        next = a->next;
        delete a;
    }

    *head = NULL;
}

void
aclDestroyAclList(acl_list ** head)
{
    acl_list *l;
    debugs(28, 8, "aclDestroyAclList: invoked");

    for (l = *head; l; l = *head) {
        *head = l->next;
        delete l;
    }
}

void
aclDestroyAccessList(acl_access ** list)
{
    acl_access *l = NULL;
    acl_access *next = NULL;

    for (l = *list; l; l = next) {
        debugs(28, 3, "aclDestroyAccessList: '" << l->cfgline << "'");
        next = l->next;
        aclDestroyAclList(&l->aclList);
        safe_free(l->cfgline);
        cbdataFree(l);
    }

    *list = NULL;
}

/* maex@space.net (06.09.1996)
 *    destroy an _acl_deny_info_list */

void
aclDestroyDenyInfoList(acl_deny_info_list ** list)
{
    acl_deny_info_list *a = NULL;
    acl_deny_info_list *a_next = NULL;
    acl_name_list *l = NULL;
    acl_name_list *l_next = NULL;

    debugs(28, 8, "aclDestroyDenyInfoList: invoked");

    for (a = *list; a; a = a_next) {
        for (l = a->acl_list; l; l = l_next) {
            l_next = l->next;
            safe_free(l);
        }

        a_next = a->next;
        xfree(a->err_page_name);
        memFree(a, MEM_ACL_DENY_INFO_LIST);
    }

    *list = NULL;
}

/*
 * This function traverses all ACL elements referenced
 * by an access list (presumably 'http_access').   If 
 * it finds a PURGE method ACL, then it returns TRUE,
 * otherwise FALSE.
 */
/* XXX: refactor this more sensibly. perhaps have the parser detect it ? */
int
aclPurgeMethodInUse(acl_access * a)
{
    return a->containsPURGE();
}
