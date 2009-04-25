/*
 * $Id: squid_endian.h,v 1.4 2004/12/21 16:17:58 hno Exp $
 *
 * AUTHOR: Alan Barrett
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

#ifndef SQUID_ENDIAN_H
#define SQUID_ENDIAN_H

/*
 * Macros to deal with byte swapping.  These macros provide
 * the following interface:
 *
 * // Byte-swap
 * u_int16_t bswap16(u_int16_t);
 * u_int32_t bswap32(u_int32_t);
 *
 * // Convert from host byte order to big-endian, and vice versa.
 * u_int16_t htobe16(u_int16_t); // equivalent to htons()
 * u_int32_t htobe32(u_int32_t); // equivalent to htonl()
 * u_int16_t be16toh(u_int16_t); // equivalent to ntohs()
 * u_int32_t be32toh(u_int32_t); // equivalent to ntohs()
 *
 * // Convert from host byte order to little-endian, and vice versa.
 * u_int16_t htole16(u_int16_t);
 * u_int32_t htole32(u_int32_t);
 * u_int16_t le16toh(u_int16_t);
 * u_int32_t le32toh(u_int32_t);
 */

#include "config.h"
#include "squid_types.h"

/*
 * Some systems define bswap_16() and bswap_32() in <byteswap.h>
 *
 * Some systems define bswap16() and bswap32() in <sys/bswap.h>.  
 *
 * Some systems define htobe16()/be16toh() and friends in <sys/endian.h>.
 */
#if HAVE_BYTESWAP_H
#  include <byteswap.h>
#endif /* HAVE_BYTESWAP_H */
#ifdef HAVE_MACHINE_BYTE_SWAP_H
#  include <machine/byte_swap.h>
#endif	/* HAVE_MACHINE_BYTE_SWAP_H */
#if HAVE_SYS_BSWAP_H
#  include <sys/bswap.h>
#endif /* HAVE_SYS_BSWAP_H */
#if HAVE_SYS_ENDIAN_H
#  include <sys/endian.h>
#endif /* HAVE_SYS_ENDIAN_H */

/*
 * Define bswap16() and bswap32() in terms of bswap_16() and bswap_32(),
 * or the hard way.
 */
#if ! HAVE_BSWAP16 && ! defined(bswap16)
#  if defined(bswap_16)
#    define bswap16(x) bswap_16(x)
#  else
#    define bswap16(x) \
       (((((u_int16_t)(x)) >> 8) & 0xff) | ((((u_int16_t)(x)) & 0xff) << 8))
#  endif
#endif /* ! HAVE_BSWAP16 && ! defined(bswap16) */
#if ! HAVE_BSWAP32 && ! defined(bswap32)
#  if defined(bswap_32)
#    define bswap32(x) bswap_32(x)
#  else
#    define bswap32(x) \
       (((((u_int32_t)(x)) & 0xff000000) >> 24) | \
        ((((u_int32_t)(x)) & 0x00ff0000) >>  8) | \
        ((((u_int32_t)(x)) & 0x0000ff00) <<  8) | \
        ((((u_int32_t)(x)) & 0x000000ff) << 24))
#  endif
#endif /* ! HAVE_BSWAP32 && ! defined(bswap32) */

/*
 * Define htobe*()/be*toh() in terms of hton*()/ntoh*().
 *
 * XXX: If htobe16() is missing, we assume that the other *be*() functions
 *      are also missing.
 */
#if ! HAVE_HTOBE16 && ! defined(htobe16)
#  ifdef WORDS_BIGENDIAN
#    define htobe16(x) (x)
#    define htobe32(x) (x)
#    define be16toh(x) (x)
#    define be32toh(x) (x)
#  else /* ! WORDS_BIGENDIAN */
#    define htobe16(x) htons(x)
#    define htobe32(x) htonl(x)
#    define be16toh(x) ntohs(x)
#    define be32toh(x) ntohl(x)
#  endif /* ! WORDS_BIGENDIAN */
#endif /* ! HAVE_HTOBE16 && ! defined(htobe16) */

/*
 * Define htole*()/le*toh() in terms of bswap*().
 *
 * XXX: If htole16() is missing, we assume that the other *le*() functions
 *      are also missing.
 *
 *      Except OpenBSD - htole16 & 32 exist, but not le16toh etc
 */
#if defined(_SQUID_OPENBSD_)
#  define le16toh(x) htole16(x)
#  define le32toh(x) htole32(x)
#endif

#if ! HAVE_HTOLE16 && ! defined(htole16)
#  ifdef WORDS_BIGENDIAN
#    define htole16(x) bswap16(x)
#    define htole32(x) bswap32(x)
#    define le16toh(x) bswap16(x)
#    define le32toh(x) bswap32(x)
#  else /* ! WORDS_BIGENDIAN */
       /*
        * XXX: What about unusual byte orders like 3412 or 2143 ?
        *      Nothing else in squid seems to care about them,
        *      so we don't worry about them here either.
        */
#    define htole16(x) (x)
#    define htole32(x) (x)
#    define le16toh(x) (x)
#    define le32toh(x) (x)
#  endif /* ! WORDS_BIGENDIAN */
#endif /* ! HAVE_HTOLE16 && ! defined(htole16) */
 
#endif /* SQUID_ENDIAN_H */
