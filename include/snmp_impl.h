/*
 * Definitions for SNMP (RFC 1067) implementation.
 *
 *
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

#ifndef SNMP_IMPL_H
#define SNMP_IMPL_H


#undef _ANSI_ARGS_
#if (defined(__STDC__) && ! defined(NO_PROTOTYPE)) || defined(USE_PROTOTYPE)
# define _ANSI_ARGS_(x) x
#else
# define _ANSI_ARGS_(x) ()
#endif


#if (defined vax) || (defined (mips))
/*
 * This is a fairly bogus thing to do, but there seems to be no better way for
 * compilers that don't understand void pointers.
 */
#define void char
#endif

/*
 * Error codes:
 */
/*
 * These must not clash with SNMP error codes (all positive).
 */
#define PARSE_ERROR	-1
#define BUILD_ERROR	-2

#define SID_MAX_LEN	200
#define MAX_NAME_LEN	64  /* number of subid's in a objid */

#ifndef NULL
#define NULL 0
#endif

#ifndef TRUE
#define TRUE	1
#endif
#ifndef FALSE
#define FALSE	0
#endif

#define READ	    1
#define WRITE	    0

#define RESERVE1    0
#define RESERVE2    1
#define COMMIT      2
#define ACTION      3
#define FREE        4

#define RONLY	0xAAAA	/* read access for everyone */
#define RWRITE	0xAABA	/* add write access for community private */
#define NOACCESS 0x0000	/* no access for anybody */

#define INTEGER	    ASN_INTEGER
#define STRING	    ASN_OCTET_STR
#define OBJID	    ASN_OBJECT_ID
#define NULLOBJ	    ASN_NULL

/* defined types (from the SMI, RFC 1065) */
#define IPADDRESS   (ASN_APPLICATION | 0)
#define COUNTER	    (ASN_APPLICATION | 1)
#define GAUGE	    (ASN_APPLICATION | 2)
#define TIMETICKS   (ASN_APPLICATION | 3)
#define OPAQUE	    (ASN_APPLICATION | 4)

#define NSAP        (ASN_APPLICATION | 5)
#define COUNTER64   (ASN_APPLICATION | 6)
#define UINTEGER    (ASN_APPLICATION | 7)
#define DEBUG
#ifdef DEBUG
#define ERROR(string)	fprintf(stderr,"%s(%d): %s\n",__FILE__, __LINE__, string);
#else
#define ERROR(string)
#endif

/* from snmp.c*/
extern u_char	sid[];	/* size SID_MAX_LEN */

extern u_char *snmp_parse_var_op _ANSI_ARGS_((u_char *data,
					      oid *var_name,
					      int *var_name_len,
					      u_char *var_val_type,
					      int *var_val_len,
					      u_char **var_val, 
					      int *listlength));

extern u_char *snmp_build_var_op _ANSI_ARGS_((u_char *data,
					      oid *var_name,
					      int *var_name_len,
					      u_char var_val_type,
					      int var_val_len,
					      u_char *var_val,
					      int *listlength));

extern u_char *snmp_auth_parse _ANSI_ARGS_((u_char *data,
					    int *length,
					    u_char *sid,
					    int *slen,
					    long *version));

extern u_char *snmp_auth_build _ANSI_ARGS_((u_char *data,
					    int *length,
					    struct snmp_session *session,
					    int is_agent,
					    int messagelen));

#endif
