/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/***********************************************************
    Copyright 1988, 1989 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/

#include "squid.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_GNUMALLOC_H
#include <gnumalloc.h>
#elif HAVE_MALLOC_H
#include <malloc.h>
#endif
#if HAVE_MEMORY_H
#include <memory.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#if HAVE_BSTRING_H
#include <bstring.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif

#include "asn1.h"
#include "snmp.h"

#include "parse.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp_pdu.h"
#include "snmp_session.h"
#include "snmp_vars.h"

#include "util.h"

static struct snmp_mib_tree *get_symbol(oid *objid, int objidlen, struct snmp_mib_tree *subtree, char *buf);

oid RFC1066_MIB[] = {1, 3, 6, 1, 2, 1};
unsigned char RFC1066_MIB_text[] = ".iso.org.dod.internet.mgmt.mib";
struct snmp_mib_tree *Mib;

void
init_mib(char *file)
{
    if (Mib != NULL)
        return;

    if (file != NULL)
        Mib = read_mib(file);
}

static struct snmp_mib_tree *
find_rfc1066_mib(struct snmp_mib_tree *root) {
    oid *op = RFC1066_MIB;
    struct snmp_mib_tree *tp;
    int len;

    for (len = sizeof(RFC1066_MIB) / sizeof(oid); len; len--, op++) {
        for (tp = root; tp; tp = tp->next_peer) {
            if (tp->subid == *op) {
                root = tp->child_list;
                break;
            }
        }
        if (tp == NULL)
            return NULL;
    }
    return root;
}

static int
lc_cmp(const char *s1, const char *s2)
{
    char c1, c2;

    while (*s1 && *s2) {
        if (xisupper(*s1))
            c1 = xtolower(*s1);
        else
            c1 = *s1;
        if (xisupper(*s2))
            c2 = xtolower(*s2);
        else
            c2 = *s2;
        if (c1 != c2)
            return ((c1 - c2) > 0 ? 1 : -1);
        s1++;
        s2++;
    }

    if (*s1)
        return -1;
    if (*s2)
        return 1;
    return 0;
}

static int
parse_subtree(struct snmp_mib_tree *subtree, char *input, oid *output, int *out_len)
{
    char buf[128], *to = buf;
    u_int subid = 0;
    struct snmp_mib_tree *tp;

    /*
     * No empty strings.  Can happen if there is a trailing '.' or two '.'s
     * in a row, i.e. "..".
     */
    if ((*input == '\0') ||
            (*input == '.'))
        return (0);

    if (xisdigit(*input)) {
        /*
         * Read the number, then try to find it in the subtree.
         */
        while (xisdigit(*input)) {
            subid *= 10;
            subid += *input++ - '0';
        }
        for (tp = subtree; tp; tp = tp->next_peer) {
            if (tp->subid == subid)
                goto found;
        }
        tp = NULL;
    } else {
        /*
         * Read the name into a buffer.
         */
        while ((*input != '\0') &&
                (*input != '.')) {
            *to++ = *input++;
        }
        *to = '\0';

        /*
         * Find the name in the subtree;
         */
        for (tp = subtree; tp; tp = tp->next_peer) {
            if (lc_cmp(tp->label, buf) == 0) {
                subid = tp->subid;
                goto found;
            }
        }

        /*
         * If we didn't find the entry, punt...
         */
        if (tp == NULL) {
            snmplib_debug(0, "sub-identifier not found: %s\n", buf);
            return (0);
        }
    }

found:
    if (subid > (u_int) MAX_SUBID) {
        snmplib_debug(0, "sub-identifier too large: %s\n", buf);
        return (0);
    }
    if ((*out_len)-- <= 0) {
        snmplib_debug(0, "object identifier too long\n");
        return (0);
    }
    *output++ = subid;

    if (*input != '.')
        return (1);
    if ((*out_len =
                parse_subtree(tp ? tp->child_list : NULL, ++input, output, out_len)) == 0)
        return (0);
    return (++*out_len);
}

int
read_objid(input, output, out_len)
char *input;
oid *output;
int *out_len;       /* number of subid's in "output" */
{
    struct snmp_mib_tree *root = Mib;
    oid *op = output;
    int i;

    if (*input == '.')
        input++;
    else {
        root = find_rfc1066_mib(root);
        for (i = 0; i < sizeof(RFC1066_MIB) / sizeof(oid); i++) {
            if ((*out_len)-- > 0)
                *output++ = RFC1066_MIB[i];
            else {
                snmplib_debug(0, "object identifier too long\n");
                return (0);
            }
        }
    }

    if (root == NULL) {
        snmplib_debug(0, "Mib not initialized.\n");
        return 0;
    }
    if ((*out_len = parse_subtree(root, input, output, out_len)) == 0)
        return (0);
    *out_len += output - op;

    return (1);
}

void
print_objid(objid, objidlen)
oid *objid;
int objidlen;       /* number of subidentifiers */
{
    char buf[256];
    struct snmp_mib_tree *subtree = Mib;

    *buf = '.';         /* this is a fully qualified name */
    get_symbol(objid, objidlen, subtree, buf + 1);
    snmplib_debug(7, "%s\n", buf);

}

void
sprint_objid(buf, objid, objidlen)
char *buf;
oid *objid;
int objidlen;       /* number of subidentifiers */
{
    struct snmp_mib_tree *subtree = Mib;

    *buf = '.';         /* this is a fully qualified name */
    get_symbol(objid, objidlen, subtree, buf + 1);
}

static struct snmp_mib_tree *
get_symbol(objid, objidlen, subtree, buf)
oid *objid;
int objidlen;
struct snmp_mib_tree *subtree;
char *buf;
{
    struct snmp_mib_tree *return_tree = NULL;

    for (; subtree; subtree = subtree->next_peer) {
        if (*objid == subtree->subid) {
            strcpy(buf, subtree->label);
            goto found;
        }
    }

    /* subtree not found */
    while (objidlen--) {    /* output rest of name, uninterpreted */
        sprintf(buf, "%u.", *objid++);
        while (*buf)
            buf++;
    }
    *(buf - 1) = '\0';      /* remove trailing dot */
    return NULL;

found:
    if (objidlen > 1) {
        while (*buf)
            buf++;
        *buf++ = '.';
        *buf = '\0';
        return_tree = get_symbol(objid + 1, objidlen - 1, subtree->child_list, buf);
    }
    if (return_tree != NULL)
        return return_tree;
    else
        return subtree;
}

void
print_oid_nums(oid * O, int len)
{
    int x;

    for (x = 0; x < len; x++)
        printf(".%u", O[x]);
}

