/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PARSE_H
#define SQUID_PARSE_H

/***********************************************************
    Copyright 1989 by Carnegie Mellon University

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

/* NP: we only need struct variable_list and typedef oid from SNMP library     */
/*     we use as ptrs. If this was true C++ we could pre-define their classes. */
#include "snmp_vars.h"

/**
 * A linked list of tag-value pairs for enumerated integers.
 */
struct enum_list {
    struct enum_list *next;
    int value;
    char *label;
};

/**
 * A tree in the format of the tree structure of the MIB.
 */
struct snmp_mib_tree {
    struct snmp_mib_tree *child_list;   /* list of children of this node */
    struct snmp_mib_tree *next_peer;    /* Next node in list of peers */
    struct snmp_mib_tree *parent;
    char label[64];     /* This node's textual name */
    u_int subid;        /* This node's integer subidentifier */
    int type;           /* This node's object type */
    struct enum_list *enums;    /* (optional) list of enumerated integers (otherwise NULL) */
    void (*printer) (char *buf, variable_list *var, void *foo, int quiet);      /* Value printing function */
};

/* non-aggregate types for tree end nodes */
#define TYPE_OTHER      0
#define TYPE_OBJID      1
#define TYPE_OCTETSTR       2
#define TYPE_INTEGER        3
#define TYPE_NETADDR        4
#define TYPE_IPADDR     5
#define TYPE_COUNTER        6
#define TYPE_GAUGE      7
#define TYPE_TIMETICKS      8
#define TYPE_OPAQUE     9
#define TYPE_NULL       10

#ifdef __cplusplus
extern "C" {
#endif

void init_mib(char *);
int read_objid(char *, oid *, int *);
void print_objid(oid *, int);
void sprint_objid(char *, oid *, int);
void print_variable(oid *, int, struct variable_list *);
void sprint_variable(char *, oid *, int, struct variable_list *);
void sprint_value(char *, oid *, int, struct variable_list *);
void print_value(oid *, int, struct variable_list *);

/*void print_variable_list(struct variable_list *); */
/*void print_variable_list_value(struct variable_list *); */
/*void print_type(struct variable_list *); */
void print_oid_nums(oid *, int);

struct snmp_mib_tree *read_mib(char *);

#ifdef __cplusplus
}

#endif

#endif              /* SQUID_PARSE_H */

