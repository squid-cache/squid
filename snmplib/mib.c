
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

#include "config.h"

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
#elif HAVE_MALLOC_H && !defined(_SQUID_FREEBSD_) && !defined(_SQUID_NEXT_)
#include <malloc.h>
#endif
#if HAVE_MEMORY_H
#include <memory.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STRINGS_H
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

#include "snmp_pdu.h"
#include "snmp_vars.h"
#include "snmp_session.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "parse.h"

#include "util.h"
#include "snprintf.h"
#if 0
static void sprint_by_type();
#endif

#if 0
static char *
uptimeString(timeticks, buf)
     int timeticks;
     char *buf;
{
    int seconds, minutes, hours, days;

    timeticks /= 100;
    days = timeticks / (60 * 60 * 24);
    timeticks %= (60 * 60 * 24);

    hours = timeticks / (60 * 60);
    timeticks %= (60 * 60);

    minutes = timeticks / 60;
    seconds = timeticks % 60;

    if (days == 0) {
	snprintf(buf, 32, "%d:%02d:%02d", hours, minutes, seconds);
    } else if (days == 1) {
	snprintf(buf, 32, "%d day, %d:%02d:%02d", days, hours, minutes, seconds);
    } else {
	snprintf(buf, 32, "%d days, %d:%02d:%02d", days, hours, minutes, seconds);
    }
    return buf;
}

static void 
sprint_hexstring(buf, cp, len)
     char *buf;
     u_char *cp;
     int len;
{

    for (; len >= 16; len -= 16) {
	snprintf(buf, 26, "%02X %02X %02X %02X %02X %02X %02X %02X ", cp[0], cp[1], cp[2], cp[3], cp[4], cp[5], cp[6], cp[7]);
	buf += strlen(buf);
	cp += 8;
	snprintf(buf, 26, "%02X %02X %02X %02X %02X %02X %02X %02X\n", cp[0], cp[1], cp[2], cp[3], cp[4], cp[5], cp[6], cp[7]);
	buf += strlen(buf);
	cp += 8;
    }
    for (; len > 0; len--) {
	snprintf(buf, 4, "%02X ", *cp++);
	buf += strlen(buf);
    }
    *buf = '\0';
}

static void 
sprint_asciistring(buf, cp, len)
     char *buf;
     u_char *cp;
     int len;
{
    int x;

    for (x = 0; x < len; x++) {
	if (isprint(*cp)) {
	    *buf++ = *cp++;
	} else {
	    *buf++ = '.';
	    cp++;
	}
	if ((x % 48) == 47)
	    *buf++ = '\n';
    }
    *buf = '\0';
}

static void
sprint_octet_string(buf, var, foo, quiet)
     char *buf;
     variable_list *var;
     void *foo;
     int quiet;
{
    int hex, x;
    u_char *cp;

    if (var->type != ASN_OCTET_STR) {
	sprintf(buf, "Wrong Type (should be OCTET STRING): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *) NULL, quiet);
	return;
    }
    hex = 0;
    for (cp = var->val.string, x = 0; x < var->val_len; x++, cp++) {
	if (!(isprint(*cp) || isspace(*cp)))
	    hex = 1;
    }
    if (var->val_len <= 4)
	hex = 1;		/* not likely to be ascii */
    if (hex) {
	if (!quiet) {
	    sprintf(buf, "OCTET STRING-   (hex):\t");
	    buf += strlen(buf);
	}
	sprint_hexstring(buf, var->val.string, var->val_len);
    } else {
	if (!quiet) {
	    sprintf(buf, "OCTET STRING- (ascii):\t");
	    buf += strlen(buf);
	}
	sprint_asciistring(buf, var->val.string, var->val_len);
    }
}

static void
sprint_opaque(buf, var, foo, quiet)
     char *buf;
     variable_list *var;
     void *foo;
     int quiet;
{

    if (var->type != SMI_OPAQUE) {
	sprintf(buf, "Wrong Type (should be Opaque): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *) NULL, quiet);
	return;
    }
    if (!quiet) {
	sprintf(buf, "OPAQUE -   (hex):\t");
	buf += strlen(buf);
    }
    sprint_hexstring(buf, var->val.string, var->val_len);
}

static void
sprint_object_identifier(buf, var, foo, quiet)
     char *buf;
     variable_list *var;
     void *foo;
     int quiet;
{
    if (var->type != SMI_OBJID) {
	sprintf(buf, "Wrong Type (should be OBJECT IDENTIFIER): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *) NULL, quiet);
	return;
    }
    if (!quiet) {
	sprintf(buf, "OBJECT IDENTIFIER:\t");
	buf += strlen(buf);
    }
    sprint_objid(buf, (oid *) (var->val.objid), var->val_len / sizeof(oid));
}

static void
sprint_timeticks(buf, var, foo, quiet)
     char *buf;
     variable_list *var;
     void *foo;
     int quiet;
{
    char timebuf[32];

    if (var->type != SMI_TIMETICKS) {
	sprintf(buf, "Wrong Type (should be Timeticks): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *) NULL, quiet);
	return;
    }
    if (!quiet) {
	sprintf(buf, "Timeticks: ");
	buf += strlen(buf);
    }
    sprintf(buf, "(%u) %s",
	*(var->val.integer),
	uptimeString(*(var->val.integer), timebuf));
}

static void
sprint_integer(buf, var, enums, quiet)
     char *buf;
     variable_list *var;
     struct enum_list *enums;
     int quiet;
{
    char *enum_string = NULL;

    if (var->type != SMI_INTEGER) {
	sprintf(buf, "Wrong Type (should be INTEGER): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *) NULL, quiet);
	return;
    }
    for (; enums; enums = enums->next)
	if (enums->value == *var->val.integer) {
	    enum_string = enums->label;
	    break;
	}
    if (!quiet) {
	sprintf(buf, "INTEGER: ");
	buf += strlen(buf);
    }
    if (enum_string == NULL)
	sprintf(buf, "%u", *var->val.integer);
    else
	sprintf(buf, "%s(%u)", enum_string, *var->val.integer);
}

static void
sprint_gauge(buf, var, foo, quiet)
     char *buf;
     variable_list *var;
     void *foo;
     int quiet;
{
    if (var->type != SMI_GAUGE32) {
	sprintf(buf, "Wrong Type (should be Gauge): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *) NULL, quiet);
	return;
    }
    if (!quiet) {
	sprintf(buf, "Gauge: ");
	buf += strlen(buf);
    }
    sprintf(buf, "%u", *var->val.integer);
}

static void
sprint_counter(buf, var, foo, quiet)
     char *buf;
     variable_list *var;
     void *foo;
     int quiet;
{
    if (var->type != SMI_COUNTER32) {
	sprintf(buf, "Wrong Type (should be Counter): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *) NULL, quiet);
	return;
    }
    if (!quiet) {
	sprintf(buf, "Counter: ");
	buf += strlen(buf);
    }
    sprintf(buf, "%u", *var->val.integer);
}

static void
sprint_networkaddress(buf, var, foo, quiet)
     char *buf;
     variable_list *var;
     void *foo;
     int quiet;
{
    int x, len;
    u_char *cp;

    if (!quiet) {
	sprintf(buf, "Network Address:\t");
	buf += strlen(buf);
    }
    cp = var->val.string;
    len = var->val_len;
    for (x = 0; x < len; x++) {
	sprintf(buf, "%02X", *cp++);
	buf += strlen(buf);
	if (x < (len - 1))
	    *buf++ = ':';
    }
}

static void
sprint_ipaddress(buf, var, foo, quiet)
     char *buf;
     variable_list *var;
     void *foo;
     int quiet;
{
    u_char *ip;

    if (var->type != SMI_IPADDRESS) {
	sprintf(buf, "Wrong Type (should be Ipaddress): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *) NULL, quiet);
	return;
    }
    ip = var->val.string;
    if (!quiet) {
	sprintf(buf, "IPAddress:\t");
	buf += strlen(buf);
    }
    sprintf(buf, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}
#endif

#if 0
static void
sprint_unsigned_short(buf, var, foo, quiet)
     char *buf;
     variable_list *var;
     void *foo;
     int quiet;
{
    if (var->type != SMI_INTEGER) {
	sprintf(buf, "Wrong Type (should be INTEGER): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *) NULL, quiet);
	return;
    }
    if (!quiet) {
	sprintf(buf, "INTEGER (0..65535): ");
	buf += strlen(buf);
    }
    sprintf(buf, "%u", *var->val.integer);
}
#endif

#if 0
static void
sprint_null(buf, var, foo, quiet)
     char *buf;
     variable_list *var;
     void *foo;
     int quiet;
{
    if (var->type != SMI_NULLOBJ) {
	sprintf(buf, "Wrong Type (should be NULL): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *) NULL, quiet);
	return;
    }
    sprintf(buf, "NULL");
}

static void
sprint_unknowntype(buf, var, foo, quiet)
     char *buf;
     variable_list *var;
     void *foo;
     int quiet;
{
/*    sprintf(buf, "Variable has bad type"); */
    sprint_by_type(buf, var, foo, quiet);
}

static void
sprint_badtype(buf)
     char *buf;
{
    sprintf(buf, "Variable has bad type");
}

static void
sprint_by_type(buf, var, enums, quiet)
     char *buf;
     variable_list *var;
     struct enum_list *enums;
     int quiet;
{
    switch (var->type) {
    case SMI_INTEGER:
	sprint_integer(buf, var, enums, quiet);
	break;
    case SMI_STRING:
	sprint_octet_string(buf, var, enums, quiet);
	break;
    case SMI_OPAQUE:
	sprint_opaque(buf, var, enums, quiet);
	break;
    case SMI_OBJID:
	sprint_object_identifier(buf, var, enums, quiet);
	break;
    case SMI_TIMETICKS:
	sprint_timeticks(buf, var, enums, quiet);
	break;
    case SMI_GAUGE32:
	sprint_gauge(buf, var, enums, quiet);
	break;
    case SMI_COUNTER32:
	sprint_counter(buf, var, enums, quiet);
	break;
    case SMI_IPADDRESS:
	sprint_ipaddress(buf, var, enums, quiet);
	break;
    case SMI_NULLOBJ:
	sprint_null(buf, var, enums, quiet);
	break;
    default:
	sprint_badtype(buf, enums, quiet);
	break;
    }
}
#endif

static struct snmp_mib_tree *get_symbol();

oid RFC1066_MIB[] =
{1, 3, 6, 1, 2, 1};
unsigned char RFC1066_MIB_text[] = ".iso.org.dod.internet.mgmt.mib";
struct snmp_mib_tree *Mib;

#if 0
static void
set_functions(subtree)
     struct snmp_mib_tree *subtree;
{
    for (; subtree; subtree = subtree->next_peer) {
	switch (subtree->type) {
	case TYPE_OBJID:
	    subtree->printer = sprint_object_identifier;
	    break;
	case TYPE_OCTETSTR:
	    subtree->printer = sprint_octet_string;
	    break;
	case TYPE_INTEGER:
	    subtree->printer = sprint_integer;
	    break;
	case TYPE_NETADDR:
	    subtree->printer = sprint_networkaddress;
	    break;
	case TYPE_IPADDR:
	    subtree->printer = sprint_ipaddress;
	    break;
	case TYPE_COUNTER:
	    subtree->printer = sprint_counter;
	    break;
	case TYPE_GAUGE:
	    subtree->printer = sprint_gauge;
	    break;
	case TYPE_TIMETICKS:
	    subtree->printer = sprint_timeticks;
	    break;
	case TYPE_OPAQUE:
	    subtree->printer = sprint_opaque;
	    break;
	case TYPE_NULL:
	    subtree->printer = sprint_null;
	    break;
	case TYPE_OTHER:
	default:
	    subtree->printer = sprint_unknowntype;
	    break;
	}
	set_functions(subtree->child_list);
    }
}
#endif

void 
init_mib(char *file)
{
    if (Mib != NULL)
	return;

    if (file != NULL)
	Mib = read_mib(file);
#if 0
    set_functions(Mib);
#endif
}


static struct snmp_mib_tree *
find_rfc1066_mib(root)
     struct snmp_mib_tree *root;
{
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
lc_cmp(s1, s2)
     char *s1, *s2;
{
    char c1, c2;

    while (*s1 && *s2) {
	if (isupper(*s1))
	    c1 = tolower(*s1);
	else
	    c1 = *s1;
	if (isupper(*s2))
	    c2 = tolower(*s2);
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
parse_subtree(subtree, input, output, out_len)
     struct snmp_mib_tree *subtree;
     char *input;
     oid *output;
     int *out_len;		/* number of subid's */
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

    if (isdigit(*input)) {
	/*
	 * Read the number, then try to find it in the subtree.
	 */
	while (isdigit(*input)) {
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
     int *out_len;		/* number of subid's in "output" */
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
     int objidlen;		/* number of subidentifiers */
{
    char buf[256];
    struct snmp_mib_tree *subtree = Mib;

    *buf = '.';			/* this is a fully qualified name */
    get_symbol(objid, objidlen, subtree, buf + 1);
    snmplib_debug(7, "%s\n", buf);

}

void 
sprint_objid(buf, objid, objidlen)
     char *buf;
     oid *objid;
     int objidlen;		/* number of subidentifiers */
{
    struct snmp_mib_tree *subtree = Mib;

    *buf = '.';			/* this is a fully qualified name */
    get_symbol(objid, objidlen, subtree, buf + 1);
}

#if 0
void 
print_variable(objid, objidlen, pvariable)
     oid *objid;
     int objidlen;
     struct variable_list *pvariable;
{
    char buf[1024], *cp;
    struct snmp_mib_tree *subtree = Mib;

    *buf = '.';			/* this is a fully qualified name */
    subtree = get_symbol(objid, objidlen, subtree, buf + 1);
    cp = buf;
    if ((strlen(buf) >= strlen((char *) RFC1066_MIB_text)) && !memcmp(buf, (char *) RFC1066_MIB_text,
	    strlen((char *) RFC1066_MIB_text))) {
	cp += sizeof(RFC1066_MIB_text);
    }
    printf("Name: %s -> ", cp);
    *buf = '\0';
    if (subtree->printer)
	(*subtree->printer) (buf, pvariable, subtree->enums, 0);
    else {
	sprint_by_type(buf, pvariable, subtree->enums, 0);
    }
    printf("%s\n", buf);
}


void 
sprint_variable(buf, objid, objidlen, pvariable)
     char *buf;
     oid *objid;
     int objidlen;
     struct variable_list *pvariable;
{
    char tempbuf[512], *cp;
    struct snmp_mib_tree *subtree = Mib;

    *tempbuf = '.';		/* this is a fully qualified name */
    subtree = get_symbol(objid, objidlen, subtree, tempbuf + 1);
    cp = tempbuf;
    if ((strlen(buf) >= strlen((char *) RFC1066_MIB_text)) && !memcmp(buf, (char *) RFC1066_MIB_text,
	    strlen((char *) RFC1066_MIB_text))) {
	cp += sizeof(RFC1066_MIB_text);
    }
    sprintf(buf, "Name: %s -> ", cp);
    buf += strlen(buf);
    if (subtree->printer)
	(*subtree->printer) (buf, pvariable, subtree->enums, 0);
    else {
	sprint_by_type(buf, pvariable, subtree->enums, 0);
    }
    strcat(buf, "\n");
}

void 
sprint_value(buf, objid, objidlen, pvariable)
     char *buf;
     oid *objid;
     int objidlen;
     struct variable_list *pvariable;
{
    char tempbuf[512];
    struct snmp_mib_tree *subtree = Mib;

    subtree = get_symbol(objid, objidlen, subtree, tempbuf);
    if (subtree->printer)
	(*subtree->printer) (buf, pvariable, subtree->enums, 0);
    else {
	sprint_by_type(buf, pvariable, subtree->enums, 0);
    }
}

void 
print_value(objid, objidlen, pvariable)
     oid *objid;
     int objidlen;
     struct variable_list *pvariable;
{
    char tempbuf[512];
    struct snmp_mib_tree *subtree = Mib;

    subtree = get_symbol(objid, objidlen, subtree, tempbuf);
    if (subtree->printer)
	(*subtree->printer) (tempbuf, pvariable, subtree->enums, 0);
    else {
	sprint_by_type(tempbuf, pvariable, subtree->enums, 0);
    }
    printf("%s\n", tempbuf);
}
#endif

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
    while (objidlen--) {	/* output rest of name, uninterpreted */
	sprintf(buf, "%u.", *objid++);
	while (*buf)
	    buf++;
    }
    *(buf - 1) = '\0';		/* remove trailing dot */
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




#if 0
void 
print_variable_list(variable_list * V)
{
    print_variable(V->name, V->name_length, V);
}

void 
print_variable_list_value(variable_list * pvariable)
{
    char buf[512];
    struct snmp_mib_tree *subtree = Mib;

    *buf = '.';			/* this is a fully qualified name */
    subtree = get_symbol(pvariable->name, pvariable->name_length, subtree, buf + 1);
    *buf = '\0';

    if (subtree->printer)
	(*subtree->printer) (buf, pvariable, subtree->enums, 1);
    else {
	sprint_by_type(buf, pvariable, subtree->enums, 1);
    }
    printf("%s", buf);
}
#endif

void 
print_type(variable_list * var)
{
    switch (var->type) {
    case SMI_INTEGER:
	printf("Integer");
	break;
    case SMI_STRING:
	printf("Octet String");
	break;
    case SMI_OPAQUE:
	printf("Opaque");
	break;
    case SMI_OBJID:
	printf("Object Identifier");
	break;
    case SMI_TIMETICKS:
	printf("Timeticks");
	break;
    case SMI_GAUGE32:
	printf("Gauge");
	break;
    case SMI_COUNTER32:
	printf("Counter");
	break;
    case SMI_IPADDRESS:
	printf("IP Address");
	break;
    case SMI_NULLOBJ:
	printf("NULL");
	break;
    default:
	printf("Unknown type %d\n", var->type);
	break;
    }
}

void 
print_oid_nums(oid * O, int len)
{
    int x;

    for (x = 0; x < len; x++)
	printf(".%u", O[x]);
}
