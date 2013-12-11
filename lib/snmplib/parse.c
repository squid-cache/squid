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

/*
 * parse.c
 */
#include "squid.h"
#include "asn1.h"
#include "cache_snmp.h"
#include "parse.h"
#include "snmp_debug.h"
#include "snmp_pdu.h"
#include "snmp_vars.h"
#include "util.h"

#include <stdio.h>

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
#if HAVE_ASSERT_H
#include <assert.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif

/*
 * This is one element of an object identifier with either an integer subidentifier,
 * or a textual string label, or both.
 * The subid is -1 if not present, and label is NULL if not present.
 */
struct subid {
    int subid;
    char *label;
};

/*
 * A linked list of nodes.
 */
struct node {
    struct node *next;
    char label[64];		/* This node's (unique) textual name */
    u_int subid;		/* This node's integer subidentifier */
    char parent[64];		/* The parent's textual name */
    int type;			/* The type of object this represents */
    struct enum_list *enums;	/* (optional) list of enumerated integers (otherwise NULL) */
};

int Line = 1;

/* types of tokens */
#define	CONTINUE    -1
#define ENDOFFILE   0
#define LABEL	    1
#define SUBTREE	    2
#define SYNTAX	    3
#undef OBJID
#define OBJID	    4
#define OCTETSTR    5
#undef INTEGER
#define INTEGER	    6
#define NETADDR	    7
#define	IPADDR	    8
#define COUNTER	    9
#define GAUGE	    10
#define TIMETICKS   11
#define SNMP_OPAQUE	    12
#define NUL	    13
#define SEQUENCE    14
#define OF	    15		/* SEQUENCE OF */
#define OBJTYPE	    16
#define ACCESS	    17
#define READONLY    18
#define READWRITE   19
#define	WRITEONLY   20
#undef NOACCESS
#define NOACCESS    21
#define SNMP_STATUS 22
#define MANDATORY   23
#define SNMP_OPTIONAL    24
#define OBSOLETE    25
#define RECOMMENDED 26
#define PUNCT	    27
#define EQUALS	    28
#define NUMBER	    29
#define LEFTBRACKET 30
#define RIGHTBRACKET 31
#define	LEFTPAREN   32
#define RIGHTPAREN  33
#define COMMA	    34
/* For SNMPv2 SMI pseudo-compliance */
#define DESCRIPTION 35
#define INDEX       36
#define QUOTE       37

struct tok {
    const char *name;			/* token name */
    int len;			/* length not counting nul */
    int token;			/* value */
    int hash;			/* hash of name */
    struct tok *next;		/* pointer to next in hash table */
};

struct tok tokens[] = {
    {"obsolete", sizeof("obsolete") - 1, OBSOLETE},
    {"Opaque", sizeof("Opaque") - 1, SNMP_OPAQUE},
    {"recommended", sizeof("recommended") - 1, RECOMMENDED},
    {"optional", sizeof("optional") - 1, SNMP_OPTIONAL},
    {"mandatory", sizeof("mandatory") - 1, MANDATORY},
    {"current", sizeof("current") - 1, MANDATORY},
    {"not-accessible", sizeof("not-accessible") - 1, NOACCESS},
    {"write-only", sizeof("write-only") - 1, WRITEONLY},
    {"read-write", sizeof("read-write") - 1, READWRITE},
    {"TimeTicks", sizeof("TimeTicks") - 1, TIMETICKS},
    {"OBJECTIDENTIFIER", sizeof("OBJECTIDENTIFIER") - 1, OBJID},
    /*
     * This CONTINUE appends the next word onto OBJECT,
     * hopefully matching OBJECTIDENTIFIER above.
     */
    {"OBJECT", sizeof("OBJECT") - 1, CONTINUE},
    {"NetworkAddress", sizeof("NetworkAddress") - 1, NETADDR},
    {"Gauge", sizeof("Gauge") - 1, GAUGE},
    {"OCTETSTRING", sizeof("OCTETSTRING") - 1, OCTETSTR},
    {"OCTET", sizeof("OCTET") - 1, -1},
    {"OF", sizeof("OF") - 1, OF},
    {"SEQUENCE", sizeof("SEQUENCE") - 1, SEQUENCE},
    {"NULL", sizeof("NULL") - 1, NUL},
    {"IpAddress", sizeof("IpAddress") - 1, IPADDR},
    {"INTEGER", sizeof("INTEGER") - 1, INTEGER},
    {"Counter", sizeof("Counter") - 1, COUNTER},
    {"read-only", sizeof("read-only") - 1, READONLY},
    {"ACCESS", sizeof("ACCESS") - 1, ACCESS},
    {"MAX-ACCESS", sizeof("MAX-ACCESS") - 1, ACCESS},
    {"STATUS", sizeof("STATUS") - 1, SNMP_STATUS},
    {"SYNTAX", sizeof("SYNTAX") - 1, SYNTAX},
    {"OBJECT-TYPE", sizeof("OBJECT-TYPE") - 1, OBJTYPE},
    {"{", sizeof("{") - 1, LEFTBRACKET},
    {"}", sizeof("}") - 1, RIGHTBRACKET},
    {"::=", sizeof("::=") - 1, EQUALS},
    {"(", sizeof("(") - 1, LEFTPAREN},
    {")", sizeof(")") - 1, RIGHTPAREN},
    {",", sizeof(",") - 1, COMMA},
    {"DESCRIPTION", sizeof("DESCRIPTION") - 1, DESCRIPTION},
    {"INDEX", sizeof("INDEX") - 1, INDEX},
    {"\"", sizeof("\"") - 1, QUOTE},
    {"END", sizeof("END") - 1, ENDOFFILE},
    /* Hacks for easier MIBFILE coercing */
    {"read-create", sizeof("read-create") - 1, READWRITE},
    {NULL}
};

#define	HASHSIZE	32
#define	BUCKET(x)	(x & 0x01F)

static struct tok *buckets[HASHSIZE];

static void
hash_init(void)
{
    register struct tok *tp;
    register const char *cp;
    register int h;
    register int b;

    memset((char *) buckets, '\0', sizeof(buckets));
    for (tp = tokens; tp->name; tp++) {
        for (h = 0, cp = tp->name; *cp; cp++)
            h += *cp;
        tp->hash = h;
        b = BUCKET(h);
        if (buckets[b])
            tp->next = buckets[b];	/* BUG ??? */
        buckets[b] = tp;
    }
}

#define NHASHSIZE    128
#define NBUCKET(x)   (x & 0x7F)
struct node *nbuckets[NHASHSIZE];

static void
init_node_hash(struct node *nodes)
{
    register struct node *np, *nextp;
    register char *cp;
    register int hash;

    memset((char *) nbuckets, '\0', sizeof(nbuckets));
    for (np = nodes; np;) {
        nextp = np->next;
        hash = 0;
        for (cp = np->parent; *cp; cp++)
            hash += *cp;
        np->next = nbuckets[NBUCKET(hash)];
        nbuckets[NBUCKET(hash)] = np;
        np = nextp;
    }
}

static void
print_error(const char *string, const char *token, int type)
{
    assert(string != NULL);
    if (type == ENDOFFILE)
        snmplib_debug(0, "%s(EOF): On or around line %d\n", string, Line);
    else if (token)
        snmplib_debug(0, "%s(%s): On or around line %d\n", string, token, Line);
    else
        snmplib_debug(0, "%s: On or around line %d\n", string, Line);
}

#if TEST
print_subtree(tree, count)
struct snmp_mib_tree *tree;
int count;
{
    struct snmp_mib_tree *tp;
    int i;

    for (i = 0; i < count; i++)
        printf("  ");
    printf("Children of %s:\n", tree->label);
    count++;
    for (tp = tree->child_list; tp; tp = tp->next_peer) {
        for (i = 0; i < count; i++)
            printf("  ");
        printf("%s\n", tp->label);
    }
    for (tp = tree->child_list; tp; tp = tp->next_peer) {
        print_subtree(tp, count);
    }
}
#endif /* TEST */

int translation_table[40];

static void
build_translation_table(void)
{
    int count;

    for (count = 0; count < 40; count++) {
        switch (count) {
        case OBJID:
            translation_table[count] = TYPE_OBJID;
            break;
        case OCTETSTR:
            translation_table[count] = TYPE_OCTETSTR;
            break;
        case INTEGER:
            translation_table[count] = TYPE_INTEGER;
            break;
        case NETADDR:
            translation_table[count] = TYPE_IPADDR;
            break;
        case IPADDR:
            translation_table[count] = TYPE_IPADDR;
            break;
        case COUNTER:
            translation_table[count] = TYPE_COUNTER;
            break;
        case GAUGE:
            translation_table[count] = TYPE_GAUGE;
            break;
        case TIMETICKS:
            translation_table[count] = TYPE_TIMETICKS;
            break;
        case SNMP_OPAQUE:
            translation_table[count] = TYPE_OPAQUE;
            break;
        case NUL:
            translation_table[count] = TYPE_NULL;
            break;
        default:
            translation_table[count] = TYPE_OTHER;
            break;
        }
    }
}

/*
 * Find all the children of root in the list of nodes.  Link them into the
 * tree and out of the nodes list.
 */
static void
do_subtree(struct snmp_mib_tree *root, struct node **nodes)
{
    register struct snmp_mib_tree *tp;
    struct snmp_mib_tree *peer = NULL;
    register struct node *np = NULL, **headp = NULL;
    struct node *oldnp = NULL, *child_list = NULL, *childp = NULL;
    char *cp;
    int hash;

    tp = root;
    hash = 0;
    for (cp = tp->label; *cp; cp++)
        hash += *cp;
    headp = &nbuckets[NBUCKET(hash)];
    /*
     * Search each of the nodes for one whose parent is root, and
     * move each into a separate list.
     */
    for (np = *headp; np; np = np->next) {
        if ((*tp->label != *np->parent) || strcmp(tp->label, np->parent)) {
            if ((*tp->label == *np->label) && !strcmp(tp->label, np->label)) {
                /* if there is another node with the same label, assume that
                 * any children after this point in the list belong to the other node.
                 * This adds some scoping to the table and allows vendors to
                 * reuse names such as "ip".
                 */
                break;
            }
            oldnp = np;
        } else {
            if (child_list == NULL) {
                child_list = childp = np;	/* first entry in child list */
            } else {
                childp->next = np;
                childp = np;
            }
            /* take this node out of the node list */
            if (oldnp == NULL) {
                *headp = np->next;	/* fix root of node list */
            } else {
                oldnp->next = np->next;		/* link around this node */
            }
        }
    }
    if (childp)
        childp->next = 0;	/* re-terminate list */
    /*
     * Take each element in the child list and place it into the tree.
     */
    for (np = child_list; np; np = np->next) {
        tp = (struct snmp_mib_tree *) xmalloc(sizeof(struct snmp_mib_tree));
        tp->parent = root;
        tp->next_peer = NULL;
        tp->child_list = NULL;
        strcpy(tp->label, np->label);
        tp->subid = np->subid;
        tp->type = translation_table[np->type];
        tp->enums = np->enums;
        np->enums = NULL;	/* so we don't free them later */
        if (root->child_list == NULL) {
            root->child_list = tp;
        } else if (peer) {
            peer->next_peer = tp;
        }
        peer = tp;
        /*      if (tp->type == TYPE_OTHER) */
        do_subtree(tp, nodes);	/* recurse on this child if it isn't an end node */
    }
    /* free all nodes that were copied into tree */
    oldnp = NULL;
    for (np = child_list; np; np = np->next) {
        if (oldnp)
            xfree(oldnp);
        oldnp = np;
    }
    if (oldnp)
        xfree(oldnp);
}

#if !TEST
static
#endif
struct snmp_mib_tree *
build_tree(struct node *nodes) {
    struct node *np;
    struct snmp_mib_tree *tp;
    int bucket, nodes_left = 0;

    /* build root node */
    tp = (struct snmp_mib_tree *) xmalloc(sizeof(struct snmp_mib_tree));
    tp->parent = NULL;
    tp->next_peer = NULL;
    tp->child_list = NULL;
    tp->enums = NULL;
    strcpy(tp->label, "iso");
    tp->subid = 1;
    tp->type = 0;
    build_translation_table();
    /* grow tree from this root node */
    init_node_hash(nodes);
    /* XXX nodes isn't needed in do_subtree() ??? */
    do_subtree(tp, &nodes);
#if TEST
    print_subtree(tp, 0);
#endif /* TEST */
    /* If any nodes are left, the tree is probably inconsistent */
    for (bucket = 0; bucket < NHASHSIZE; bucket++) {
        if (nbuckets[bucket]) {
            nodes_left = 1;
            break;
        }
    }
    if (nodes_left) {
        snmplib_debug(0, "The mib description doesn't seem to be consistent.\n");
        snmplib_debug(0, "Some nodes couldn't be linked under the \"iso\" tree.\n");
        snmplib_debug(0, "these nodes are left:\n");
        for (bucket = 0; bucket < NHASHSIZE; bucket++) {
            for (np = nbuckets[bucket]; np; np = np->next)
                snmplib_debug(5, "%s ::= { %s %d } (%d)\n", np->label, np->parent, np->subid,
                              np->type);
        }
    }
    return tp;
}

/*
 * Parses a token from the file.  The type of the token parsed is returned,
 * and the text is placed in the string pointed to by token.
 */
static char last = ' ';

static int
get_token(register FILE *fp, register char *token)
{
    register int ch;
    register char *cp = token;
    register int hash = 0;
    register struct tok *tp;

    *cp = 0;
    ch = (unsigned char)last;
    /* skip all white space */
    while (xisspace(ch) && ch != -1) {
        ch = getc(fp);
        if (ch == '\n')
            Line++;
    }
    if (ch == -1)
        return ENDOFFILE;

    /*
     * Accumulate characters until end of token is found.  Then attempt to match this
     * token as a reserved word.  If a match is found, return the type.  Else it is
     * a label.
     */
    do {
        if (ch == '\n')
            Line++;
        if (xisspace(ch) || ch == '(' || ch == ')' ||
                ch == '{' || ch == '}' || ch == ',' ||
                ch == '"') {
            if (!xisspace(ch) && *token == 0) {
                hash += ch;
                *cp++ = ch;
                last = ' ';
            } else {
                last = ch;
            }
            *cp = '\0';

            for (tp = buckets[BUCKET(hash)]; tp; tp = tp->next) {
                if ((tp->hash == hash) && (strcmp(tp->name, token) == 0))
                    break;
            }
            if (tp) {
                if (tp->token == CONTINUE)
                    continue;
                return (tp->token);
            }
            if (token[0] == '-' && token[1] == '-') {
                /* strip comment */
                while ((ch = getc(fp)) != -1)
                    if (ch == '\n') {
                        Line++;
                        break;
                    }
                if (ch == -1)
                    return ENDOFFILE;
                last = ch;
                return get_token(fp, token);
            }
            for (cp = token; *cp; cp++)
                if (!xisdigit(*cp))
                    return LABEL;
            return NUMBER;
        } else {
            hash += ch;
            *cp++ = ch;
            if (ch == '\n')
                Line++;
        }

    } while ((ch = getc(fp)) != -1);
    return ENDOFFILE;
}

/*
 * Takes a list of the form:
 * { iso org(3) dod(6) 1 }
 * and creates several nodes, one for each parent-child pair.
 * Returns NULL on error.
 *   register struct subid *SubOid;	an array of subids
 *   int length;			the length of the array
 */
static int
getoid(register FILE *fp, register struct subid *SubOid, int length)
{
    register int count;
    int type;
    char token[128];
    register char *cp;

    if ((type = get_token(fp, token)) != LEFTBRACKET) {
        print_error("Expected \"{\"", token, type);
        return 0;
    }
    type = get_token(fp, token);
    for (count = 0; count < length; count++, SubOid++) {
        SubOid->label = 0;
        SubOid->subid = -1;
        if (type == RIGHTBRACKET) {
            return count;
        } else if (type != LABEL && type != NUMBER) {
            print_error("Not valid for object identifier", token, type);
            return 0;
        }
        if (type == LABEL) {
            /* this entry has a label */
            cp = (char *) xmalloc((unsigned) strlen(token) + 1);
            strcpy(cp, token);
            SubOid->label = cp;
            type = get_token(fp, token);
            if (type == LEFTPAREN) {
                type = get_token(fp, token);
                if (type == NUMBER) {
                    SubOid->subid = atoi(token);
                    if ((type = get_token(fp, token)) != RIGHTPAREN) {
                        print_error("Unexpected a closing parenthesis", token, type);
                        return 0;
                    }
                } else {
                    print_error("Expected a number", token, type);
                    return 0;
                }
            } else {
                continue;
            }
        } else {
            /* this entry  has just an integer sub-identifier */
            SubOid->subid = atoi(token);
        }
        type = get_token(fp, token);
    }
    return count;

}

static void
free_node(struct node *np)
{
    struct enum_list *ep, *tep;

    ep = np->enums;
    while (ep) {
        tep = ep;
        ep = ep->next;
        xfree((char *) tep);
    }
    xfree((char *) np);
}

static void
free_node_list(struct node *nl)
{
    while (nl) {
        struct node *t = nl->next;
        free_node(nl);
        nl = t;
    }
}

/*
 * Parse an entry of the form:
 * label OBJECT IDENTIFIER ::= { parent 2 }
 * The "label OBJECT IDENTIFIER" portion has already been parsed.
 * Returns 0 on error.
 */
static struct node *
parse_objectid(FILE *fp, char *name) {
    int type;
    char token[64];
    register int count;
    register struct subid *op, *nop;
    int length;
    struct subid SubOid[32];
    struct node *np, *root, *oldnp = NULL;

    type = get_token(fp, token);
    if (type != EQUALS) {
        print_error("Bad format", token, type);
        return 0;
    }
    if ((length = getoid(fp, SubOid, 32)) != 0) {
        np = root = (struct node *) xmalloc(sizeof(struct node));
        memset((char *) np, '\0', sizeof(struct node));
        /*
         * For each parent-child subid pair in the subid array,
         * create a node and link it into the node list.
         */
        for (count = 0, op = SubOid, nop = SubOid + 1; count < (length - 2); count++,
                op++, nop++) {
            /* every node must have parent's name and child's name or number */
            if (op->label && (nop->label || (nop->subid != -1))) {
                strncpy(np->parent, op->label, sizeof(np->parent) - 1);
                if (nop->label)
                    strncpy(np->label, nop->label, sizeof(np->label) - 1);
                if (nop->subid != -1)
                    np->subid = nop->subid;
                np->type = 0;
                np->enums = 0;
                /* set up next entry */
                np->next = (struct node *) xmalloc(sizeof(*np->next));
                memset((char *) np->next, '\0', sizeof(struct node));
                oldnp = np;
                np = np->next;
            }
        }
        np->next = (struct node *) NULL;
        /*
         * The above loop took care of all but the last pair.  This pair is taken
         * care of here.  The name for this node is taken from the label for this
         * entry.
         * np still points to an unused entry.
         */
        if (count == (length - 2)) {
            if (op->label) {
                strncpy(np->parent, op->label, sizeof(np->parent)-1);
                strncpy(np->label, name, sizeof(np->label)-1);
                if (nop->subid != -1)
                    np->subid = nop->subid;
                else
                    print_error("Warning: This entry is pretty silly", np->label, type);
            } else {
                free_node(np);
                if (oldnp)
                    oldnp->next = NULL;
                else {
                    free_node_list(root); // we need to clear the newly allocated list
                    return NULL;
                }
            }
        } else {
            print_error("Missing end of oid", (char *) NULL, type);
            free_node_list(root); // we need to clear the newly allocated list
            if (oldnp)
                oldnp->next = NULL;
            return NULL;
        }
        /* free the oid array */
        for (count = 0, op = SubOid; count < length; count++, op++) {
            if (op->label)
                xfree(op->label);
            op->label = 0;
        }
        return root;
    } else {
        print_error("Bad object identifier", (char *) NULL, type);
        return 0;
    }
}

/*
 * Parses an asn type.  This structure is ignored by this parser.
 * Returns NULL on error.
 */
static int
parse_asntype(FILE *fp)
{
    int type;
    char token[64];

    type = get_token(fp, token);
    if (type != SEQUENCE) {
        print_error("Not a sequence", token, type);	/* should we handle this */
        return ENDOFFILE;
    }
    while ((type = get_token(fp, token)) != ENDOFFILE) {
        if (type == RIGHTBRACKET)
            return type;
    }
    print_error("Expected \"}\"", token, type);
    return ENDOFFILE;
}

/*
 * Parses an OBJECT TYPE macro.
 * Returns 0 on error.
 */
static struct node *
parse_objecttype(register FILE *fp, char *name) {
    register int type;
    char token[64];
    int count, length;
    struct subid SubOid[32];
    char syntax[64];
    int nexttype;
    char nexttoken[64];
    register struct node *np = NULL;
    register struct enum_list *ep = NULL;

    type = get_token(fp, token);
    if (type != SYNTAX) {
        print_error("Bad format for OBJECT TYPE", token, type);
        return 0;
    }
    np = (struct node *) xmalloc(sizeof(struct node));
    np->next = 0;
    np->enums = 0;
    type = get_token(fp, token);
    nexttype = get_token(fp, nexttoken);
    np->type = type;
    switch (type) {
    case SEQUENCE:
        strcpy(syntax, token);
        if (nexttype == OF) {
            strcat(syntax, " ");
            strcat(syntax, nexttoken);
            nexttype = get_token(fp, nexttoken);
            strcat(syntax, " ");
            strcat(syntax, nexttoken);
            nexttype = get_token(fp, nexttoken);
        }
        break;
    case INTEGER:
        strcpy(syntax, token);
        if (nexttype == LEFTBRACKET) {
            /* if there is an enumeration list, parse it */
            while ((type = get_token(fp, token)) != ENDOFFILE) {
                if (type == RIGHTBRACKET)
                    break;
                if (type == LABEL) {
                    /* this is an enumerated label */
                    if (np->enums == 0) {
                        ep = np->enums = (struct enum_list *)
                                         xmalloc(sizeof(struct enum_list));
                    } else {
                        ep->next = (struct enum_list *)
                                   xmalloc(sizeof(struct enum_list));
                        ep = ep->next;
                    }
                    ep->next = 0;
                    /* a reasonable approximation for the length */
                    ep->label = (char *) xmalloc((unsigned) strlen(token) + 1);
                    strcpy(ep->label, token);
                    type = get_token(fp, token);
                    if (type != LEFTPAREN) {
                        print_error("Expected \"(\"", token, type);
                        free_node(np);
                        return 0;
                    }
                    type = get_token(fp, token);
                    if (type != NUMBER) {
                        print_error("Expected integer", token, type);
                        free_node(np);
                        return 0;
                    }
                    ep->value = atoi(token);
                    type = get_token(fp, token);
                    if (type != RIGHTPAREN) {
                        print_error("Expected \")\"", token, type);
                        free_node(np);
                        return 0;
                    }
                }
            }
            if (type == ENDOFFILE) {
                print_error("Expected \"}\"", token, type);
                free_node(np);
                return 0;
            }
            nexttype = get_token(fp, nexttoken);
        } else if (nexttype == LEFTPAREN) {
            /* ignore the "constrained integer" for now */
            nexttype = get_token(fp, nexttoken);
            nexttype = get_token(fp, nexttoken);
            nexttype = get_token(fp, nexttoken);
        }
        break;
    case OBJID:
    case OCTETSTR:
    case NETADDR:
    case IPADDR:
    case COUNTER:
    case GAUGE:
    case TIMETICKS:
    case SNMP_OPAQUE:
    case NUL:
    case LABEL:
        strcpy(syntax, token);
        break;
    default:
        print_error("Bad syntax", token, type);
        free_node(np);
        return 0;
    }
    if (nexttype != ACCESS) {
        print_error("Should be ACCESS", nexttoken, nexttype);
        free_node(np);
        return 0;
    }
    type = get_token(fp, token);
    if (type != READONLY && type != READWRITE && type != WRITEONLY
            && type != NOACCESS) {
        print_error("Bad access type", nexttoken, nexttype);
        free_node(np);
        return 0;
    }
    type = get_token(fp, token);
    if (type != SNMP_STATUS) {
        print_error("Should be STATUS", token, nexttype);
        free_node(np);
        return 0;
    }
    type = get_token(fp, token);
    if (type != MANDATORY && type != SNMP_OPTIONAL && type != OBSOLETE && type != RECOMMENDED) {
        print_error("Bad status", token, type);
        free_node(np);
        return 0;
    }
    /* Fetch next token.  Either:
     *
     * -> EQUALS (Old MIB format)
     * -> DESCRIPTION, INDEX (New MIB format)
     */
    type = get_token(fp, token);
    if ((type != DESCRIPTION) && (type != INDEX) && (type != EQUALS)) {
        print_error("Should be DESCRIPTION, INDEX, or EQUALS", token, nexttype);
        free_node(np);
        return 0;
    }
    if (type == DESCRIPTION) {

        type = get_token(fp, token);
        if (type != QUOTE) {
            print_error("Should be Description open quote", token, nexttype);
            free_node(np);
            return 0;
        }
        /* Fetch description string */
        {
            int ReadChar;

            ReadChar = last;
            /* skip everything until closing quote */
            while ((ReadChar != '"') && (ReadChar != -1)) {
                ReadChar = getc(fp);
                if (ReadChar == '\n')
                    Line++;
            }
            last = ' ';
        }
        /* ASSERT:  Done with description. */
        type = get_token(fp, token);
    }
    if ((type != INDEX) && (type != EQUALS)) {
        print_error("Should be INDEX, or EQUALS", token, nexttype);
        free_node(np);
        return 0;
    }
    if (type == INDEX) {

        /* Scarf INDEX */

        type = get_token(fp, token);
        if (type != LEFTBRACKET) {
            print_error("Should be INDEX left brace", token, type);
            free_node(np);
            return 0;
        }
        /* Fetch description string */
        {
            int ReadChar;

            ReadChar = last;
            /* skip everything until closing quote */
            while ((ReadChar != '}') && (ReadChar != -1)) {
                ReadChar = getc(fp);
                if (ReadChar == '\n')
                    Line++;
            }
            last = ' ';
        }
        /* ASSERT:  Done with INDEX. */
        type = get_token(fp, token);
    }
    if (type != EQUALS) {
        print_error("Bad format", token, type);
        free_node(np);
        return 0;
    }
    length = getoid(fp, SubOid, 32);
    if (length > 1 && length <= 32) {
        /* just take the last pair in the oid list */
        if (SubOid[length - 2].label) {
            strncpy(np->parent, SubOid[length - 2].label, 64);
            np->parent[63] = '\0';
        }
        strncpy(np->label, name, sizeof(np->label));
        np->label[sizeof(np->label) - 1] = '\0';
        if (SubOid[length - 1].subid != -1)
            np->subid = SubOid[length - 1].subid;
        else
            print_error("Warning: This entry is pretty silly", np->label, type);
    } else {
        print_error("No end to oid", (char *) NULL, type);
        free_node(np);
        np = 0;
    }
    /* free oid array */
    for (count = 0; count < length; count++) {
        if (SubOid[count].label)
            xfree(SubOid[count].label);
        SubOid[count].label = 0;
    }
    return np;
}

/*
 * Parses a mib file and returns a linked list of nodes found in the file.
 * Returns NULL on error.
 */
#if !TEST
static
#endif
struct node *
parse(FILE *fp) {
    char token[64];
    char name[64];
    int type = 1;
    struct node *np = NULL, *root = NULL;

    hash_init();

    while (type != ENDOFFILE) {
        type = get_token(fp, token);
        if (type != LABEL) {
            if (type == ENDOFFILE) {
                return root;
            }
            print_error(token, "is a reserved word", type);
            free_node_list(root);
            return NULL;
        }
        strncpy(name, token, 64);
        name[63] = '\0';
        type = get_token(fp, token);
        if (type == OBJTYPE) {
            if (root == NULL) {
                /* first link in chain */
                np = root = parse_objecttype(fp, name);
                if (np == NULL) {
                    print_error("Bad parse of object type", (char *) NULL, type);
                    return NULL;
                }
            } else {
                np->next = parse_objecttype(fp, name);
                if (np->next == NULL) {
                    print_error("Bad parse of objecttype", (char *) NULL, type);
                    free_node_list(root);
                    return NULL;
                }
            }
            /* now find end of chain */
            while (np->next)
                np = np->next;
        } else if (type == OBJID) {
            if (root == NULL) {
                /* first link in chain */
                np = root = parse_objectid(fp, name);
                if (np == NULL) {
                    print_error("Bad parse of object id", (char *) NULL, type);
                    return NULL;
                }
            } else {
                np->next = parse_objectid(fp, name);
                if (np->next == NULL) {
                    print_error("Bad parse of object type", (char *) NULL, type);
                    free_node_list(root);
                    return NULL;
                }
            }
            /* now find end of chain */
            while (np->next)
                np = np->next;
        } else if (type == EQUALS) {
            type = parse_asntype(fp);
        } else if (type == ENDOFFILE) {
            break;
        } else {
            print_error("Bad operator", (char *) NULL, type);
            free_node_list(root);
            return NULL;
        }
    }
#if TEST
    {
        struct enum_list *ep;

        for (np = root; np; np = np->next) {
            printf("%s ::= { %s %d } (%d)\n", np->label, np->parent, np->subid,
                   np->type);
            if (np->enums) {
                printf("Enums: \n");
                for (ep = np->enums; ep; ep = ep->next) {
                    printf("%s(%d)\n", ep->label, ep->value);
                }
            }
        }
    }
#endif /* TEST */
    return root;
}

struct snmp_mib_tree *
read_mib(char *filename) {
    FILE *fp;
    struct node *nodes;
    struct snmp_mib_tree *tree;
    char mbuf[256];
    char *p;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        snmplib_debug(1, "init_mib: %s: %s\n", filename, xstrerror());
        return (NULL);
    }
    mbuf[0] = '\0';
    while ((p = fgets(mbuf, 256, fp)) && strncmp(mbuf, "DUMMY",
            strlen("DUMMY")));
    if (!p) {
        snmplib_debug(0, "Bad MIB version or tag missing, install original!\n");
        fclose(fp);
        return NULL;
    }
    if (!strcmp(mbuf, "DUMMY")) {
        snmplib_debug(0, "You need to update your MIB!\n");
        fclose(fp);
        return NULL;
    }
    nodes = parse(fp);
    fclose(fp);
    if (!nodes) {
        snmplib_debug(0, "Mib table is bad.  Exiting\n");
        return NULL;
    }
    tree = build_tree(nodes);
    return (tree);
}
