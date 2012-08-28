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

#define KERBEROS_LDAP_GROUP_VERSION "1.3.0sq"

#if HAVE_STRING_H
#include <string.h>
#endif

#if HAVE_KRB5_H
#if HAVE_BROKEN_SOLARIS_KRB5_H
#warn "Warning! You have a broken Solaris <krb5.h> system header"
#warn "http://bugs.opensolaris.org/bugdatabase/view_bug.do?bug_id=6837512"
#if defined(__cplusplus)
#define KRB5INT_BEGIN_DECLS     extern "C" {
#define KRB5INT_END_DECLS
KRB5INT_BEGIN_DECLS
#endif
#endif /* HAVE_BROKEN_SOLARIS_KRB5_H */
#if HAVE_BROKEN_HEIMDAL_KRB5_H
extern "C" {
#include <krb5.h>
}
#else
#include <krb5.h>
#endif
#endif /* HAVE_KRB5_H */

#if HAVE_COM_ERR_H
#include <com_err.h>
#elif HAVE_HEIMDAL_KERBEROS
#define error_message(code) krb5_get_err_text(kparam.context,code)
#endif /* HAVE_COM_ERR_H */

#define LDAP_DEPRECATED 1
#ifdef HAVE_LDAP_REBIND_FUNCTION
#define LDAP_REFERRALS
#endif
#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
#ifdef HAVE_MOZLDAP_LDAP_H
#include <mozldap/ldap.h>
#endif

struct gdstruct {
    char *group;
    char *domain;
    struct gdstruct *next;
};
struct ndstruct {
    char *netbios;
    char *domain;
    struct ndstruct *next;
};
struct lsstruct {
    char *lserver;
    char *domain;
    struct lsstruct *next;
};

struct main_args {
    char *glist;
    char *ulist;
    char *tlist;
    char *nlist;
    char *llist;
    char *luser;
    char *lpass;
    char *lbind;
    char *lurl;
    char *ssl;
    int rc_allow;
    int AD;
    int mdepth;
    char *ddomain;
    struct gdstruct *groups;
    struct ndstruct *ndoms;
    struct lsstruct *lservs;
};

SQUIDCEXTERN int log_enabled;

/* the macro overload style is really a gcc-ism */
#ifdef __GNUC__

#define log(X...) \
                     if (log_enabled) { \
                         fprintf(stderr, "%s(%d): pid=%ld :", __FILE__, __LINE__, (long)getpid() ); \
                         fprintf(stderr,X); \
                     } else (void)0

#define error(X...) \
                     fprintf(stderr, "%s(%d): pid=%ld :", __FILE__, __LINE__, (long)getpid() ); \
                     fprintf(stderr,X); \
 
#define warn(X...) \
                     fprintf(stderr, "%s(%d): pid=%ld :", __FILE__, __LINE__, (long)getpid() ); \
                     fprintf(stderr,X); \
 
#else /* __GNUC__ */

/* non-GCC compilers can't do the above macro define yet. */
void log(char *format,...);
void error(char *format,...);
void warn(char *format,...);
#endif

struct hstruct {
    char *host;
    int port;
    int priority;
    int weight;
};

struct ldap_creds {
    char *dn;
    char *pw;
};

void init_args(struct main_args *margs);
void clean_args(struct main_args *margs);
const char *LogTime(void);

int check_memberof(struct main_args *margs, char *user, char *domain);
int get_memberof(struct main_args *margs, char *user, char *domain, char *group);

char *get_netbios_name(struct main_args *margs, char *netbios);

int create_gd(struct main_args *margs);
int create_nd(struct main_args *margs);
int create_ls(struct main_args *margs);

#ifdef HAVE_KRB5
int krb5_create_cache(struct main_args *margs, char *domain);
void krb5_cleanup(void);
#endif

int get_ldap_hostname_list(struct main_args *margs, struct hstruct **hlist, int nhosts, char *domain);
int get_hostname_list(struct main_args *margs, struct hstruct **hlist, int nhosts, char *name);
int free_hostname_list(struct hstruct **hlist, int nhosts);

#if defined(HAVE_SASL_H) || defined(HAVE_SASL_SASL_H) || defined(HAVE_SASL_DARWIN)
int tool_sasl_bind(LDAP * ld, char *binddn, char *ssl);
#endif

#define PROGRAM "kerberos_ldap_group"
