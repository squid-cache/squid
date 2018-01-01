/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * SNMP Variable Binding.  Complies with:
 *
 * RFC 1905: Protocol Operations for SNMPv2
 *
 */

/**********************************************************************
 *
 *           Copyright 1997 by Carnegie Mellon University
 *
 *                       All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 *
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 * Author: Ryan Troll <ryan+@andrew.cmu.edu>
 *
 **********************************************************************/

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
#include "snmp_vars.h"
#if 0
#include "mibii.h"
#endif
#include "snmp_api_error.h"
#include "snmp_msg.h"
#include "snmp_pdu.h"

#include "util.h"

/* #define DEBUG_VARS 1 */
/* #define DEBUG_VARS_MALLOC 1 */
/* #define DEBUG_VARS_DECODE 1 */
/* #define DEBUG_VARS_ENCODE 1 */

/* Create a new variable_list structure representing oid Name of length Len.
 *
 * Returns NULL upon error.
 */

struct variable_list *
snmp_var_new(oid * Name, int Len) {
    struct variable_list *New;

#if DEBUG_VARS
    printf("VARS: Creating.\n");
#endif

    New = xmalloc(sizeof(*New));
    /* XXX xmalloc never returns NULL */
    if (New == NULL) {
        snmp_set_api_error(SNMPERR_OS_ERR);
        return (NULL);
    }
    memset(New, '\0', sizeof(struct variable_list));
    /*  New->next_variable = NULL; */

    New->type = ASN_NULL;
    New->name_length = Len;

    if (New->name_length == 0) {
        New->name = NULL;
        return (New);
    }
    New->name = (oid *) xmalloc(Len * sizeof(oid));
    /* XXX xmalloc never returns NULL */
    if (New->name == NULL) {
        xfree(New);
        snmp_set_api_error(SNMPERR_OS_ERR);
        return (NULL);
    }
#if DEBUG_VARS
    printf("VARS: Copying name, size (%d)\n", Len);
#endif

    /* Only copy a name if it was specified. */
    if (Name)
        memcpy((char *) New->name, (char *) Name, Len * sizeof(oid));

    return (New);
}

struct variable_list *
snmp_var_new_integer(oid * Name, int Len, int ival, unsigned char type) {
    variable_list *v = snmp_var_new(Name, Len);
    v->val_len = sizeof(int);
    v->val.integer = xmalloc(sizeof(int));
    v->type = type;
    *(v->val.integer) = ival;
    return v;
}

/* Clone a variable list.
 *
 * Returns NULL upon error.
 */

struct variable_list *
snmp_var_clone(struct variable_list *Src) {
    struct variable_list *Dest;

#if DEBUG_VARS
    printf("VARS: Cloning.\n");
#endif

    Dest = (struct variable_list *) xmalloc(sizeof(struct variable_list));
    if (Dest == NULL) {
        snmp_set_api_error(SNMPERR_OS_ERR);
        return (NULL);
    }
#if DEBUG_VARS
    printf("VARS: Copying entire variable list.  (Size %d)\n",
           sizeof(struct variable_list));
#endif

    memcpy((char *) Dest, (char *) Src, sizeof(struct variable_list));

    if (Src->name != NULL) {
        Dest->name = (oid *) xmalloc(Src->name_length * sizeof(oid));
        if (Dest->name == NULL) {
            snmp_set_api_error(SNMPERR_OS_ERR);
            xfree(Dest);
            return (NULL);
        }
#if DEBUG_VARS
        printf("VARS: Copying name OID. (Size %d)\n", Src->name_length);
#endif
        memcpy((char *) Dest->name, (char *) Src->name,
               Src->name_length * sizeof(oid));
    }
    /* CISCO Catalyst 2900 returns NULL strings as data of length 0. */
    if ((Src->val.string != NULL) &&
            (Src->val_len)) {
        Dest->val.string = (u_char *) xmalloc(Src->val_len);
        if (Dest->val.string == NULL) {
            snmp_set_api_error(SNMPERR_OS_ERR);
            xfree(Dest->name);
            xfree(Dest);
            return (NULL);
        }
#if DEBUG_VARS
        printf("VARS: Copying value (Size %d)\n", Src->val_len);
#endif
        memcpy((char *) Dest->val.string, (char *) Src->val.string, Src->val_len);
    }
#if DEBUG_VARS
    printf("VARS: Cloned %x.\n", (unsigned int) Dest);
#endif
#if DEBUG_VARS_MALLOC
    printf("VARS: Cloned  (%x)\n", (unsigned int) Dest);
    printf("VARS: Name is (%x)\n", (unsigned int) Dest->name);
#endif

    return (Dest);
}

/* Free a variable_list.
 */
void
snmp_var_free(struct variable_list *Ptr)
{
    if (Ptr->name)
        xfree((char *) Ptr->name);

    if (Ptr->val.string)
        xfree((char *) Ptr->val.string);
    else if (Ptr->val.integer)
        xfree((char *) Ptr->val.integer);

    xfree(Ptr);
}

/**********************************************************************/

/* Build a variable binding.
 *
 * RFC 1905: Protocol Operations for SNMPv2
 *
 * VarBind ::=
 *   SEQUENCE {
 *     name ObjectName
 *     CHOICE {
 *       value ObjectSyntax
 *       unSpecified NULL
 *       noSuchObject[0] NULL
 *       noSuchInstance[1] NULL
 *       endOfMibView[2] NULL
 *     }
 *   }
 */
u_char *
snmp_var_EncodeVarBind(u_char * Buffer, int *BufLenP,
                       variable_list * VarList,
                       int Version)
{
    struct variable_list *Vars;
    u_char *bufp;
    u_char *HeaderStart;
    u_char *HeaderEnd;
    int FakeArg = *BufLenP;

    bufp = Buffer;

    for (Vars = VarList; Vars; Vars = Vars->next_variable) {

        /* Build the header for this variable
         *
         * Use Maximum size.
         */
        HeaderStart = bufp;
        HeaderEnd = asn_build_header(HeaderStart, BufLenP,
                                     (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                                     FakeArg);
        if (HeaderEnd == NULL)
            return (NULL);

        /* Now, let's put the Object Identifier into the buffer */
        bufp = asn_build_objid(HeaderEnd, BufLenP,
                               (u_char) (ASN_UNIVERSAL |
                                         ASN_PRIMITIVE |
                                         ASN_OBJECT_ID),
                               Vars->name, Vars->name_length);
        if (bufp == NULL)
            return (NULL);

        /* Now put the data in */
        switch (Vars->type) {

        case ASN_INTEGER:
            bufp = asn_build_int(bufp,
                                 BufLenP, Vars->type,
                                 (int *) Vars->val.integer, Vars->val_len);
            break;

        case SMI_COUNTER32:
        case SMI_GAUGE32:
        /*  case SMI_UNSIGNED32: */
        case SMI_TIMETICKS:
            bufp = asn_build_unsigned_int(bufp, BufLenP,
                                          Vars->type,
                                          (u_int *) Vars->val.integer, Vars->val_len);
            break;

        case ASN_OCTET_STR:
        case SMI_IPADDRESS:
        case SMI_OPAQUE:
            bufp = asn_build_string(bufp, BufLenP, Vars->type,
                                    Vars->val.string, Vars->val_len);
            break;

        case ASN_OBJECT_ID:
            bufp = asn_build_objid(bufp, BufLenP, Vars->type,
                                   (oid *) Vars->val.objid, Vars->val_len / sizeof(oid));
            break;

        case SMI_NOSUCHINSTANCE:
        case SMI_NOSUCHOBJECT:
        case SMI_ENDOFMIBVIEW:
            if (Version == SNMP_VERSION_1) {
                /* SNMP Version 1 does not support these error codes. */
                bufp = asn_build_null(bufp, BufLenP, SMI_NOSUCHOBJECT);
            } else {
                bufp = asn_build_exception(bufp, BufLenP, Vars->type);
            }
            break;

        case ASN_NULL:
            bufp = asn_build_null(bufp, BufLenP, Vars->type);
            break;

        case SMI_COUNTER64:
            snmplib_debug(2, "Unable to encode type SMI_COUNTER64!\n");
        /* Fall through */

        default:
            snmp_set_api_error(SNMPERR_UNSUPPORTED_TYPE);
            return (NULL);
        }

        /* ASSERT:  bufp should now point to the next valid byte. */
        if (bufp == NULL)
            return (NULL);

        /* Rebuild the header with the appropriate length */
        HeaderEnd = asn_build_header(HeaderStart, &FakeArg,
                                     (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                                     (bufp - HeaderEnd));

        /* Returns NULL */
        if (HeaderEnd == NULL)
            return (NULL);

    }

    /* or the end of the entire thing */
    return (bufp);
}

/* Parse all Vars from the buffer */
u_char *
snmp_var_DecodeVarBind(u_char * Buffer, int *BufLen,
                       struct variable_list ** VarP,
                       int Version)
{
    struct variable_list *Var = NULL, **VarLastP;
    u_char *bufp, *tmp;
    u_char VarBindType;
    u_char *DataPtr;
    int DataLen;
    oid TmpBuf[MAX_NAME_LEN];
    memset(TmpBuf, 0, MAX_NAME_LEN * sizeof(*TmpBuf));

    int AllVarLen = *BufLen;
    int ThisVarLen = 0;

    VarLastP = VarP;
#if DEBUG_VARS_DECODE
    printf("VARS: Decoding buffer of length %d\n", *BufLen);
#endif

    /* Now parse the variables */
    bufp = asn_parse_header(Buffer, &AllVarLen, &VarBindType);
    if (bufp == NULL)
        return (NULL);

    if (VarBindType != (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
        snmp_set_api_error(SNMPERR_PDU_PARSE);
        return (NULL);
    }
#if DEBUG_VARS_DECODE
    printf("VARS: All Variable length %d\n", AllVarLen);
#endif

#define PARSE_ERROR { snmp_var_free(Var); return(NULL); }

    /* We know how long the variable list is.  Parse it. */
    while ((int) AllVarLen > 0) {

        /* Create a new variable */
        Var = snmp_var_new(NULL, MAX_NAME_LEN);
        if (Var == NULL)
            return (NULL);

        /* Parse the header to find out the length of this variable. */
        ThisVarLen = AllVarLen;
        tmp = asn_parse_header(bufp, &ThisVarLen, &VarBindType);
        if (tmp == NULL)
            PARSE_ERROR;

        /* Now that we know the length , figure out how it relates to
         * the entire variable list
         */
        AllVarLen = AllVarLen - (ThisVarLen + (tmp - bufp));
        bufp = tmp;

        /* Is it valid? */
        if (VarBindType != (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
            snmp_set_api_error(SNMPERR_PDU_PARSE);
            PARSE_ERROR;
        }
#if DEBUG_VARS_DECODE
        printf("VARS: Header type 0x%x (%d bytes left)\n", VarBindType, ThisVarLen);
#endif

        /* Parse the OBJID */
        bufp = asn_parse_objid(bufp, &ThisVarLen, &VarBindType,
                               Var->name, &(Var->name_length));
        if (bufp == NULL)
            PARSE_ERROR;

        if (VarBindType != (u_char) (ASN_UNIVERSAL |
                                     ASN_PRIMITIVE |
                                     ASN_OBJECT_ID)) {
            snmp_set_api_error(SNMPERR_PDU_PARSE);
            PARSE_ERROR;
        }
#if DEBUG_VARS_DECODE
        printf("VARS: Decoded OBJID (%d bytes). (%d bytes left)\n",
               Var->name_length, ThisVarLen);
#endif

        /* Keep a pointer to this object */
        DataPtr = bufp;
        DataLen = ThisVarLen;

        /* find out type of object */
        bufp = asn_parse_header(bufp, &ThisVarLen, &(Var->type));
        if (bufp == NULL)
            PARSE_ERROR;
        ThisVarLen = DataLen;

#if DEBUG_VARS_DECODE
        printf("VARS: Data type %d\n", Var->type);
#endif

        /* Parse the type */

        switch ((short) Var->type) {

        case ASN_INTEGER:
            Var->val.integer = (int *) xmalloc(sizeof(int));
            if (Var->val.integer == NULL) {
                snmp_set_api_error(SNMPERR_OS_ERR);
                PARSE_ERROR;
            }
            Var->val_len = sizeof(int);
            bufp = asn_parse_int(DataPtr, &ThisVarLen,
                                 &Var->type, (int *) Var->val.integer,
                                 Var->val_len);
#if DEBUG_VARS_DECODE
            printf("VARS: Decoded integer '%d' (%d bytes left)\n",
                   *(Var->val.integer), ThisVarLen);
#endif
            break;

        case SMI_COUNTER32:
        case SMI_GAUGE32:
        /*  case SMI_UNSIGNED32: */
        case SMI_TIMETICKS:
            Var->val.integer = (int *) xmalloc(sizeof(u_int));
            if (Var->val.integer == NULL) {
                snmp_set_api_error(SNMPERR_OS_ERR);
                PARSE_ERROR;
            }
            Var->val_len = sizeof(u_int);
            bufp = asn_parse_unsigned_int(DataPtr, &ThisVarLen,
                                          &Var->type, (u_int *) Var->val.integer,
                                          Var->val_len);
#if DEBUG_VARS_DECODE
            printf("VARS: Decoded timeticks '%d' (%d bytes left)\n",
                   *(Var->val.integer), ThisVarLen);
#endif
            break;

        case ASN_OCTET_STR:
        case SMI_IPADDRESS:
        case SMI_OPAQUE:
            Var->val_len = *&ThisVarLen;    /* String is this at most */
            Var->val.string = (u_char *) xmalloc((unsigned) Var->val_len);
            if (Var->val.string == NULL) {
                snmp_set_api_error(SNMPERR_OS_ERR);
                PARSE_ERROR;
            }
            bufp = asn_parse_string(DataPtr, &ThisVarLen,
                                    &Var->type, Var->val.string,
                                    &Var->val_len);
#if DEBUG_VARS_DECODE
            printf("VARS: Decoded string '%s' (length %d) (%d bytes left)\n",
                   (Var->val.string), Var->val_len, ThisVarLen);
#endif
            break;

        case ASN_OBJECT_ID:
            Var->val_len = MAX_NAME_LEN;
            bufp = asn_parse_objid(DataPtr, &ThisVarLen,
                                   &Var->type, TmpBuf, &Var->val_len);
            Var->val_len *= sizeof(oid);
            Var->val.objid = (oid *) xmalloc((unsigned) Var->val_len);
            if (Var->val.integer == NULL) {
                snmp_set_api_error(SNMPERR_OS_ERR);
                PARSE_ERROR;
            }
            /* Only copy if we successfully decoded something */
            if (bufp) {
                memcpy((char *) Var->val.objid, (char *) TmpBuf, Var->val_len);
            }
#if DEBUG_VARS_DECODE
            printf("VARS: Decoded OBJID (length %d) (%d bytes left)\n",
                   Var->val_len, ThisVarLen);
#endif
            break;

        case ASN_NULL:
        case SMI_NOSUCHINSTANCE:
        case SMI_NOSUCHOBJECT:
        case SMI_ENDOFMIBVIEW:
            break;

        case SMI_COUNTER64:
            snmplib_debug(2, "Unable to parse type SMI_COUNTER64!\n");
            snmp_set_api_error(SNMPERR_UNSUPPORTED_TYPE);
            PARSE_ERROR;

        default:
            snmplib_debug(2, "bad type returned (%x)\n", Var->type);
            snmp_set_api_error(SNMPERR_PDU_PARSE);
            PARSE_ERROR;
        }           /* End of var type switch */

        if (bufp == NULL)
            PARSE_ERROR;

#if DEBUG_VARS_DECODE
        printf("VARS:  Adding to list.\n");
#endif
        /* Add variable to the list */
        *VarLastP = Var;
        VarLastP = &(Var->next_variable);
    }
#undef PARSE_ERROR

    return (bufp);
}

