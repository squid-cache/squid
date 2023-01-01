/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * Abstract Syntax Notation One, ASN.1
 * As defined in ISO/IS 8824 and ISO/IS 8825
 * This implements a subset of the above International Standards that
 * is sufficient to implement SNMP.
 *
 * Encodes abstract data types into a machine independent stream of bytes.
 *
 */
/***************************************************************************
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
 ***************************************************************************/

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
#include "snmp_api_error.h"

u_char *
asn_build_header(u_char * data, /* IN - ptr to start of object */
                 int *datalength,       /* IN/OUT - # of valid bytes */
                 /*          left in buffer */
                 u_char type,       /* IN - ASN type of object */
                 int length)
{   /* IN - length of object */
    /* Truth is 0 'cause we don't know yet */
    return (asn_build_header_with_truth(data, datalength, type, length, 0));
}

/*
 * asn_parse_int - pulls an int out of an ASN int type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_int(u_char * data, int *datalength,
              u_char * type, int *intp, int intsize)
/*    u_char *data;        IN     - pointer to start of object */
/*    int    *datalength;  IN/OUT - # of valid bytes left in buffer */
/*    u_char *type;        OUT    - asn type of object */
/*    int   *intp;         IN/OUT - pointer to start of output buffer */
/*    int     intsize;     IN     - size of output buffer */
{
    /*
     * ASN.1 integer ::= 0x02 asnlength byte {byte}*
     */
    u_char *bufp = data;
    u_int asn_length;
    int value = 0;

    /* Room to store int? */
    if (intsize != sizeof(int)) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    /* Type */
    *type = *bufp++;

    /* Extract length */
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == NULL)
        return (NULL);

    /* Make sure the entire int is in the buffer */
    if (asn_length + (bufp - data) > *datalength) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    /* Can we store this int? */
    if (asn_length > intsize) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    /* Remaining data */
    *datalength -= (int) asn_length + (bufp - data);

    /* Is the int negative? */
    if (*bufp & 0x80)
        value = -1;     /* integer is negative */

    /* Extract the bytes */
    while (asn_length--)
        value = (value << 8) | *bufp++;

    /* That's it! */
    *intp = value;
    return (bufp);
}

/*
 * asn_parse_unsigned_int - pulls an unsigned int out of an ASN int type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_unsigned_int(u_char * data, int *datalength,
                       u_char * type, u_int * intp, int intsize)
/*    u_char *data;          IN     - pointer to start of object */
/*    int    *datalength;    IN/OUT - # of valid bytes left in buffer */
/*    u_char *type;          OUT    - asn type of object */
/*    u_int *intp;           IN/OUT - pointer to start of output buffer */
/*    int     intsize;       IN     - size of output buffer */
{
    /*
     * ASN.1 integer ::= 0x02 asnlength byte {byte}*
     */
    u_char *bufp = data;
    u_int asn_length;
    int value = 0;

    /* Room to store int? */
    if (intsize != sizeof(int)) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    /* Type */
    *type = *bufp++;

    /* Extract length */
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == NULL)
        return (NULL);

    /* Make sure the entire int is in the buffer */
    if (asn_length + (bufp - data) > *datalength) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    /* Can we store this int? */
    if ((asn_length > (intsize + 1)) ||
            ((asn_length == intsize + 1) && *bufp != 0x00)) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    /* Remaining data */
    *datalength -= (int) asn_length + (bufp - data);

    /* Is the int negative? */
    if (*bufp & 0x80)
        value = -1;     /* integer is negative */

    /* Extract the bytes */
    while (asn_length--)
        value = (value << 8) | *bufp++;

    /* That's it! */
    *intp = value;
    return (bufp);
}

/*
 * asn_build_int - builds an ASN object containing an integer.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_int(u_char * data, int *datalength,
              u_char type, int *intp, int intsize)
/*     u_char *data;         IN - pointer to start of output buffer */
/*     int    *datalength;   IN/OUT - # of valid bytes left in buffer */
/*     u_char  type;         IN - asn type of object */
/*     int   *intp;          IN - pointer to start of integer */
/*     int    intsize;       IN - size of *intp */
{
    /*
     * ASN.1 integer ::= 0x02 asnlength byte {byte}*
     */
    int integer;
    u_int mask;

    if (intsize != sizeof(int)) {
        snmp_set_api_error(SNMPERR_ASN_ENCODE);
        return (NULL);
    }
    integer = *intp;

    /*
     * Truncate "unnecessary" bytes off of the most significant end of this
     * 2's complement integer.  There should be no sequence of 9
     * consecutive 1's or 0's at the most significant end of the
     * integer.
     */
    mask = (u_int) 0x1FF << ((8 * (sizeof(int) - 1)) - 1);
    /* mask is 0xFF800000 on a big-endian machine */

    while ((((integer & mask) == 0) || ((integer & mask) == mask))
            && intsize > 1) {
        intsize--;
        integer <<= 8;
    }

    data = asn_build_header_with_truth(data, datalength, type, intsize, 1);
    if (data == NULL)
        return (NULL);

    /* Enough room for what we just encoded? */
    if (*datalength < intsize) {
        snmp_set_api_error(SNMPERR_ASN_ENCODE);
        return (NULL);
    }
    /* Insert it */
    *datalength -= intsize;
    mask = (u_int) 0xFF << (8 * (sizeof(int) - 1));
    /* mask is 0xFF000000 on a big-endian machine */
    while (intsize--) {
        *data++ = (u_char) ((integer & mask) >> (8 * (sizeof(int) - 1)));
        integer <<= 8;
    }
    return (data);
}

/*
 * asn_build_unsigned_int - builds an ASN object containing an integer.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_unsigned_int(u_char * data, int *datalength,
                       u_char type, u_int * intp, int intsize)
/*     u_char *data;         IN     - pointer to start of output buffer */
/*     int    *datalength;   IN/OUT - # of valid bytes left in buffer */
/*     u_char  type;         IN     - asn type of object */
/*     u_int  *intp;         IN     - pointer to start of integer */
/*     int     intsize;      IN     - size of *intp */
{
    /*
     * ASN.1 integer ::= 0x02 asnlength byte {byte}*
     */
    u_int integer;
    u_int mask;
    int add_null_byte = 0;

    if (intsize != sizeof(int)) {
        snmp_set_api_error(SNMPERR_ASN_ENCODE);
        return (NULL);
    }
    integer = *intp;
    mask = (u_int) 0x80 << (8 * (sizeof(int) - 1));
    /* mask is 0x80000000 on a big-endian machine */
    if ((integer & mask) != 0) {
        /* add a null byte if MSB is set, to prevent sign extension */
        add_null_byte = 1;
        intsize++;
    }
    /*
     * Truncate "unnecessary" bytes off of the most significant end of
     * this 2's complement integer.
     * There should be no sequence of 9 consecutive 1's or 0's at the
     * most significant end of the integer.
     * The 1's case is taken care of above by adding a null byte.
     */
    mask = (u_int) 0x1FF << ((8 * (sizeof(int) - 1)) - 1);
    /* mask is 0xFF800000 on a big-endian machine */
    while (((integer & mask) == 0) && intsize > 1) {
        intsize--;
        integer <<= 8;
    }

    data = asn_build_header_with_truth(data, datalength, type, intsize, 1);
    if (data == NULL)
        return (NULL);

    if (*datalength < intsize) {
        snmp_set_api_error(SNMPERR_ASN_ENCODE);
        return (NULL);
    }
    *datalength -= intsize;
    if (add_null_byte == 1) {
        *data++ = '\0';
        intsize--;
    }
    mask = (u_int) 0xFF << (8 * (sizeof(int) - 1));
    /* mask is 0xFF000000 on a big-endian machine */
    while (intsize--) {
        *data++ = (u_char) ((integer & mask) >> (8 * (sizeof(int) - 1)));
        integer <<= 8;
    }
    return (data);
}

/*
 * asn_parse_string - pulls an octet string out of an ASN octet string type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  "string" is filled with the octet string.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_string(u_char * data, int *datalength,
                 u_char * type, u_char * string, int *strlength)
/*    u_char *data;       IN - pointer to start of object */
/*    int    *datalength; IN/OUT - # of valid bytes left in buffer */
/*    u_char *type;       OUT - asn type of object */
/*    u_char *string;     IN/OUT - pointer to start of output buffer */
/*    int    *strlength;  IN/OUT - size of output buffer */
{
    /*
     * ASN.1 octet string ::= primstring | cmpdstring
     * primstring ::= 0x04 asnlength byte {byte}*
     * cmpdstring ::= 0x24 asnlength string {string}*
     */
    u_char *bufp = data;
    u_int asn_length;

    *type = *bufp++;
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == NULL)
        return (NULL);

    if (asn_length + (bufp - data) > *datalength) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    if (asn_length > *strlength) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    memcpy((char *) string, (char *) bufp, (int) asn_length);
    *strlength = (int) asn_length;
    *datalength -= (int) asn_length + (bufp - data);
    return (bufp + asn_length);
}

/*
 * asn_build_string - Builds an ASN octet string object containing the input
 *   string.  On entry, datalength is input as the number of valid bytes
 *   following "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_string(u_char * data, int *datalength,
                 u_char type, u_char * string, int strlength)
/*    u_char *data;       IN - pointer to start of object */
/*    int    *datalength; IN/OUT - # of valid bytes left in buf */
/*    u_char  type;       IN - ASN type of string */
/*    u_char *string;     IN - pointer to start of input buffer */
/*    int     strlength;  IN - size of input buffer */
{
    /*
     * ASN.1 octet string ::= primstring | cmpdstring
     * primstring ::= 0x04 asnlength byte {byte}*
     * cmpdstring ::= 0x24 asnlength string {string}*
     * This code will never send a compound string.
     */
    data = asn_build_header_with_truth(data, datalength, type, strlength, 1);
    if (data == NULL)
        return (NULL);

    if (*datalength < strlength) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    memcpy((char *) data, (char *) string, strlength);
    *datalength -= strlength;
    return (data + strlength);
}

/*
 * asn_parse_header - interprets the ID and length of the current object.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   in this object following the id and length.
 *
 *  Returns a pointer to the first byte of the contents of this object.
 *  Returns NULL on any error.
 */
u_char *
asn_parse_header(u_char * data, int *datalength, u_char * type)
/*    u_char  *data;       IN - pointer to start of object */
/*    int     *datalength; IN/OUT - # of valid bytes left in buffer */
/*    u_char  *type;       OUT - ASN type of object */
{
    u_char *bufp = data;
    int header_len;
    u_int asn_length;

    /* this only works on data types < 30, i.e. no extension octets */
    if (IS_EXTENSION_ID(*bufp)) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    *type = *bufp;
    bufp = asn_parse_length(bufp + 1, &asn_length);
    if (bufp == NULL)
        return (NULL);

    header_len = bufp - data;
    if (header_len + asn_length > *datalength || asn_length > (u_int)(2 << 18) ) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    *datalength = (int) asn_length;
    return (bufp);
}

/*
 * asn_build_header - builds an ASN header for an object with the ID and
 * length specified.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   in this object following the id and length.
 *
 *  This only works on data types < 30, i.e. no extension octets.
 *  The maximum length is 0xFFFF;
 *
 *  Returns a pointer to the first byte of the contents of this object.
 *  Returns NULL on any error.
 */

u_char *
asn_build_header_with_truth(u_char * data, int *datalength,
                            u_char type, int length, int truth)
/*    u_char *data;       IN - pointer to start of object */
/*    int    *datalength; IN/OUT - # of valid bytes left in buffer */
/*    u_char  type;       IN - ASN type of object */
/*    int     length;     IN - length of object */
/*    int     truth;      IN - Whether length is truth */
{
    if (*datalength < 1) {
        snmp_set_api_error(SNMPERR_ASN_ENCODE);
        return (NULL);
    }
    *data++ = type;
    (*datalength)--;
    return (asn_build_length(data, datalength, length, truth));
}

#if 0
/*
 * asn_build_sequence - builds an ASN header for a sequence with the ID and
 * length specified.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   in this object following the id and length.
 *
 *  This only works on data types < 30, i.e. no extension octets.
 *  The maximum length is 0xFFFF;
 *
 *  Returns a pointer to the first byte of the contents of this object.
 *  Returns NULL on any error.
 */
u_char *
asn_build_sequence(u_char * data, int *datalength,
                   u_char type, int length)
/*    u_char *data;       IN - pointer to start of object */
/*    int    *datalength; IN/OUT - # of valid bytes left in buffer */
/*    u_char  type;       IN - ASN type of object */
/*    int     length;     IN - length of object */
{
    *datalength -= 4;
    if (*datalength < 0) {
        *datalength += 4;   /* fix up before punting */
        snmp_set_api_error(SNMPERR_ASN_ENCODE);
        return (NULL);
    }
    *data++ = type;
    *data++ = (u_char) (0x02 | ASN_LONG_LEN);
    *data++ = (u_char) ((length >> 8) & 0xFF);
    *data++ = (u_char) (length & 0xFF);
    return (data);
}
#endif

/*
 * asn_parse_length - interprets the length of the current object.
 *  On exit, length contains the value of this length field.
 *
 *  Returns a pointer to the first byte after this length
 *  field (aka: the start of the data field).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_length(u_char * data, u_int * length)
/*    u_char  *data;   IN - pointer to start of length field */
/*    u_int  *length; OUT - value of length field */
{
    u_char lengthbyte = *data;

    if (lengthbyte & ASN_LONG_LEN) {
        lengthbyte &= ~ASN_LONG_LEN;    /* turn MSb off */

        if (lengthbyte == 0) {
            snmp_set_api_error(SNMPERR_ASN_DECODE);
            return (NULL);
        }
        if (lengthbyte > sizeof(int)) {
            snmp_set_api_error(SNMPERR_ASN_DECODE);
            return (NULL);
        }
        *length = (u_int) 0;
        memcpy((char *) (length), (char *) data + 1, (int) lengthbyte);
        *length = ntohl(*length);
        *length >>= (8 * ((sizeof *length) - lengthbyte));
        return (data + lengthbyte + 1);

    }
    /* short asnlength */

    *length = (int) lengthbyte;
    return (data + 1);
}

u_char *
asn_build_length(u_char * data, int *datalength,
                 int length, int truth)
/*   u_char *data;       IN - pointer to start of object */
/*   int    *datalength; IN/OUT - # of valid bytes left in buf */
/*   int     length;     IN - length of object */
/*   int     truth;      IN - If 1, this is the true len. */
{
    u_char *start_data = data;

    if (truth) {

        /* no indefinite lengths sent */
        if (length < 0x80) {
            if (*datalength < 1) {
                snmp_set_api_error(SNMPERR_ASN_ENCODE);
                return (NULL);
            }
            *data++ = (u_char) length;

        } else if (length <= 0xFF) {
            if (*datalength < 2) {
                snmp_set_api_error(SNMPERR_ASN_ENCODE);
                return (NULL);
            }
            *data++ = (u_char) (0x01 | ASN_LONG_LEN);
            *data++ = (u_char) length;
        } else {        /* 0xFF < length <= 0xFFFF */
            if (*datalength < 3) {
                snmp_set_api_error(SNMPERR_ASN_ENCODE);
                return (NULL);
            }
            *data++ = (u_char) (0x02 | ASN_LONG_LEN);
            *data++ = (u_char) ((length >> 8) & 0xFF);
            *data++ = (u_char) (length & 0xFF);
        }

    } else {

        /* Don't know if this is the true length.  Make sure it's large
         * enough for later.
         */
        if (*datalength < 3) {
            snmp_set_api_error(SNMPERR_ASN_ENCODE);
            return (NULL);
        }
        *data++ = (u_char) (0x02 | ASN_LONG_LEN);
        *data++ = (u_char) ((length >> 8) & 0xFF);
        *data++ = (u_char) (length & 0xFF);
    }

    *datalength -= (data - start_data);
    return (data);
}

/*
 * asn_parse_objid - pulls an object indentifier out of an ASN object
 * identifier type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  "objid" is filled with the object identifier.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_objid(u_char * data, int *datalength,
                u_char * type, oid * objid, int *objidlength)
/*    u_char  *data;        IN - pointer to start of object */
/*    int     *datalength;  IN/OUT - # of valid bytes left in buf */
/*    u_char  *type;        OUT - ASN type of object */
/*    oid     *objid;       IN/OUT - pointer to start of output buffer */
/*    int     *objidlength; IN/OUT - number of sub-id's in objid */
{
    /*
     * ASN.1 objid ::= 0x06 asnlength subidentifier {subidentifier}*
     * subidentifier ::= {leadingbyte}* lastbyte
     * leadingbyte ::= 1 7bitvalue
     * lastbyte ::= 0 7bitvalue
     */
    u_char *bufp = data;
    oid *oidp = objid + 1;
    u_int subidentifier;
    int length;
    u_int asn_length;

    *type = *bufp++;
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == NULL)
        return (NULL);

    if (asn_length + (bufp - data) > *datalength) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    *datalength -= (int) asn_length + (bufp - data);

    /* Handle invalid object identifier encodings of the form 06 00 robustly */
    if (asn_length == 0)
        objid[0] = objid[1] = 0;

    length = asn_length;
    (*objidlength)--;       /* account for expansion of first byte */
    while (length > 0 && (*objidlength)-- > 0) {
        subidentifier = 0;

        do {            /* shift and add in low order 7 bits */
            subidentifier = (subidentifier << 7)
                            + (*(u_char *) bufp & ~ASN_BIT8);
            length--;
        } while (*(u_char *) bufp++ & ASN_BIT8);

        /* while last byte has high bit clear */
        if (subidentifier > (u_int) MAX_SUBID) {
            snmp_set_api_error(SNMPERR_ASN_DECODE);
            return (NULL);
        }
        *oidp++ = (oid) subidentifier;
    }

    /*
     * The first two subidentifiers are encoded into the first component
     * with the value (X * 40) + Y, where:
     *  X is the value of the first subidentifier.
     *  Y is the value of the second subidentifier.
     */
    subidentifier = (u_int) objid[1];
    if (subidentifier == 0x2B) {
        objid[0] = 1;
        objid[1] = 3;
    } else {
        objid[1] = (u_char) (subidentifier % 40);
        objid[0] = (u_char) ((subidentifier - objid[1]) / 40);
    }

    *objidlength = (int) (oidp - objid);
    return (bufp);
}

/*
 * asn_build_objid - Builds an ASN object identifier object containing the
 * input string.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_objid(u_char * data, int *datalength,
                u_char type, oid * objid, int objidlength)
/*    u_char *data;         IN - pointer to start of object */
/*    int    *datalength;   IN/OUT - # of valid bytes left in buf */
/*    u_char  type;         IN - ASN type of object */
/*    oid    *objid;        IN - pointer to start of input buffer */
/*    int     objidlength;  IN - number of sub-id's in objid */
{
    /*
     * ASN.1 objid ::= 0x06 asnlength subidentifier {subidentifier}*
     * subidentifier ::= {leadingbyte}* lastbyte
     * leadingbyte ::= 1 7bitvalue
     * lastbyte ::= 0 7bitvalue
     */
    u_char buf[MAX_OID_LEN];
    u_char *bp = buf;
    oid *op = objid;
    int asnlength;
    u_int subid, mask, testmask;
    int bits, testbits;

    if (objidlength < 2) {
        *bp++ = 0;
        objidlength = 0;
    } else {
        *bp++ = op[1] + (op[0] * 40);
        objidlength -= 2;
        op += 2;
    }

    while (objidlength-- > 0) {
        subid = *op++;
        if (subid < 127) {  /* off by one? */
            *bp++ = subid;
        } else {
            mask = 0x7F;    /* handle subid == 0 case */
            bits = 0;
            /* testmask *MUST* !!!! be of an unsigned type */
            for (testmask = 0x7F, testbits = 0; testmask != 0;
                    testmask <<= 7, testbits += 7) {
                if (subid & testmask) {     /* if any bits set */
                    mask = testmask;
                    bits = testbits;
                }
            }
            /* mask can't be zero here */
            for (; mask != 0x7F; mask >>= 7, bits -= 7) {
                /* fix a mask that got truncated above */
                if (mask == 0x1E00000)
                    mask = 0xFE00000;
                *bp++ = (u_char) (((subid & mask) >> bits) | ASN_BIT8);
            }
            *bp++ = (u_char) (subid & mask);
        }
    }

    asnlength = bp - buf;
    data = asn_build_header_with_truth(data, datalength, type, asnlength, 1);
    if (data == NULL)
        return (NULL);
    if (*datalength < asnlength) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    memcpy((char *) data, (char *) buf, asnlength);
    *datalength -= asnlength;
    return (data + asnlength);
}

#if 0
/*
 * asn_parse_null - Interprets an ASN null type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_null(u_char * data, int *datalength, u_char * type)
/*    u_char  *data;       IN - pointer to start of object */
/*    int     *datalength; IN/OUT - # of valid bytes left in buf */
/*    u_char  *type;       OUT - ASN type of object */
{
    /*
     * ASN.1 null ::= 0x05 0x00
     */
    u_char *bufp = data;
    u_int asn_length;

    *type = *bufp++;
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == NULL)
        return (NULL);

    if (asn_length != 0) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    *datalength -= (bufp - data);
    return (bufp + asn_length);
}
#endif

/*
 * asn_build_null - Builds an ASN null object.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_null(u_char * data, int *datalength, u_char type)
/*    u_char  *data;       IN - pointer to start of object */
/*    int     *datalength; IN/OUT - # of valid bytes left in buf */
/*    u_char   type;       IN - ASN type of object */
{
    /*
     * ASN.1 null ::= 0x05 0x00
     */
    return (asn_build_header_with_truth(data, datalength, type, 0, 1));
}

#if 0

/*
 * asn_parse_bitstring - pulls a bitstring out of an ASN bitstring type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  "string" is filled with the bit string.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_bitstring(u_char * data, int *datalength,
                    u_char * type, u_char * string, int *strlength)
/*   u_char  *data;        IN - pointer to start of object */
/*   int     *datalength;  IN/OUT - # of valid bytes left in buf */
/*   u_char  *type;        OUT - asn type of object */
/*   u_char  *string;      IN/OUT - pointer to start of output buf */
/*   int     *strlength;   IN/OUT - size of output buffer */
{
    /*
     * bitstring ::= 0x03 asnlength unused {byte}*
     */
    u_char *bufp = data;
    u_int asn_length;

    *type = *bufp++;
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == NULL)
        return (NULL);

    if (asn_length + (bufp - data) > *datalength) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    if (asn_length > *strlength) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    if (asn_length < 1) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    if ((int) (*(char *) bufp) < 0 || (int) (*bufp) > 7) {
        snmp_set_api_error(SNMPERR_ASN_DECODE);
        return (NULL);
    }
    memcpy((char *) string, (char *) bufp, (int) asn_length);
    *strlength = (int) asn_length;
    *datalength -= (int) asn_length + (bufp - data);
    return (bufp + asn_length);
}

/*
 * asn_build_bitstring - Builds an ASN bit string object containing the
 * input string.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_bitstring(u_char * data, int *datalength,
                    u_char type, u_char * string, int strlength)
/*   u_char  *data;       IN - pointer to start of object */
/*   int     *datalength; IN/OUT - # of valid bytes left in buf */
/*   u_char   type;       IN - ASN type of string */
/*   u_char  *string;     IN - pointer to start of input buffer */
/*   int      strlength;  IN - size of input buffer */
{
    /*
     * ASN.1 bit string ::= 0x03 asnlength unused {byte}*
     */
    if ((strlength < 1) || ((*(char *) string) < 0) || ((*string) > 7)) {
        snmp_set_api_error(SNMPERR_ASN_ENCODE);
        return (NULL);
    }
    data = asn_build_header_with_truth(data, datalength, type, strlength, 1);
    if (data == NULL)
        return (NULL);

    if (*datalength < strlength) {
        snmp_set_api_error(SNMPERR_ASN_ENCODE);
        return (NULL);
    }
    memcpy((char *) data, (char *) string, strlength);
    *datalength -= strlength;
    return (data + strlength);
}

#endif

/*
 * To do: Write an asn_parse_exception function to go with the new
 * asn_build_exception function below so that the exceptional values can
 * be handled in input packets aswell as output ones.
 */

/*
 * asn_build_exception - Builds an ASN exception object.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 *
 * ASN.1 variable exception ::= 0x8i 0x00, where 'i' is one of these
 *                                         exception identifiers:
 *                                           0 -- noSuchObject
 *                                           1 -- noSuchInstance
 *                                           2 -- endOfMibView
 */
u_char *
asn_build_exception(u_char * data, int *datalength, u_char type)
/*    u_char  *data;       IN - pointer to start of object */
/*    int     *datalength; IN/OUT - # of valid bytes left in buf */
/*    u_char   type;       IN - ASN type of object */
{
    return (asn_build_header_with_truth(data, datalength, type, 0, 1));
}

