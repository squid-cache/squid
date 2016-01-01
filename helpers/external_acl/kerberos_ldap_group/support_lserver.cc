/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * -----------------------------------------------------------------------------
 *
 * Author: Markus Moeller (markus_moeller at compuserve.com)
 *
 * Copyright (C) 2007 Markus Moeller. All rights reserved.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * -----------------------------------------------------------------------------
 */

#include "squid.h"
#include "util.h"

#if HAVE_LDAP

#include "support.h"
struct lsstruct *init_ls(void);
void free_ls(struct lsstruct *lssp);

struct lsstruct *
init_ls(void) {
    struct lsstruct *lssp;
    lssp = (struct lsstruct *) xmalloc(sizeof(struct lsstruct));
    lssp->lserver = NULL;
    lssp->domain = NULL;
    lssp->next = NULL;
    return lssp;
}

void
free_ls(struct lsstruct *lssp)
{
    while (lssp) {
        struct lsstruct *lsspn = lssp->next;
        xfree(lssp->lserver);
        xfree(lssp->domain);
        xfree(lssp);
        lssp = lsspn;
    }
}

int
create_ls(struct main_args *margs)
{
    char *np, *dp;
    char *p;
    struct lsstruct *lssp = NULL, *lsspn = NULL;
    /*
     *  netbios list format:
     *
     *     nlist=Pattern1[:Pattern2]
     *
     *     Pattern=ldap-server@Domain    ldap server Name for a specific Kerberos domain
     *                             lsstruct.domain=Domain, lsstruct.lserver=ldap server
     *
     *
     */
    p = margs->llist;
    np = margs->llist;
    debug((char *) "%s| %s: DEBUG: ldap server list %s\n", LogTime(), PROGRAM, margs->llist ? margs->llist : "NULL");
    dp = NULL;

    if (!p) {
        debug((char *) "%s| %s: DEBUG: No ldap servers defined.\n", LogTime(), PROGRAM);
        return (0);
    }
    while (*p) {        /* loop over group list */
        if (*p == '\n' || *p == '\r') {     /* Ignore CR and LF if exist */
            ++p;
            continue;
        }
        if (*p == '@') {    /* end of group name - start of domain name */
            if (p == np) {  /* empty group name not allowed */
                debug((char *) "%s| %s: DEBUG: No ldap servers defined for domain %s\n", LogTime(), PROGRAM, p);
                free_ls(lssp);
                return (1);
            }
            if (dp) {  /* end of domain name - twice */
                debug((char *) "%s| %s: @ is not allowed in server name %s@%s\n",LogTime(), PROGRAM,np,dp);
                free_ls(lssp);
                return(1);
            }
            *p = '\0';
            ++p;
            lssp = init_ls();
            lssp->lserver = xstrdup(np);
            lssp->next = lsspn;
            dp = p;     /* after @ starts new domain name */
        } else if (*p == ':') { /* end of group name or end of domain name */
            if (p == np) {  /* empty group name not allowed */
                debug((char *) "%s| %s: DEBUG: No ldap servers defined for domain %s\n", LogTime(), PROGRAM, p);
                free_ls(lssp);
                return (1);
            }
            *p = '\0';
            ++p;
            if (dp) {       /* end of domain name */
                lssp->domain = xstrdup(dp);
                dp = NULL;
            } else {        /* end of group name and no domain name */
                lssp = init_ls();
                lssp->lserver = xstrdup(np);
                lssp->next = lsspn;
            }
            lsspn = lssp;
            np = p;     /* after : starts new group name */
            debug((char *) "%s| %s: DEBUG: ldap server %s Domain %s\n", LogTime(), PROGRAM, lssp->lserver, lssp->domain?lssp->domain:"NULL");
        } else
            ++p;
    }
    if (p == np) {      /* empty group name not allowed */
        debug((char *) "%s| %s: DEBUG: No ldap servers defined for domain %s\n", LogTime(), PROGRAM, p);
        free_ls(lssp);
        return (1);
    }
    if (dp) {           /* end of domain name */
        lssp->domain = xstrdup(dp);
    } else {            /* end of group name and no domain name */
        lssp = init_ls();
        lssp->lserver = xstrdup(np);
        if (lsspn)      /* Have already an existing structure */
            lssp->next = lsspn;
    }
    debug((char *) "%s| %s: DEBUG: ldap server %s Domain %s\n", LogTime(), PROGRAM, lssp->lserver, lssp->domain?lssp->domain:"NULL");

    margs->lservs = lssp;
    return (0);
}
#endif

