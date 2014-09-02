/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * AUTHOR: Alan Barrett
 */

#ifndef SQUID_ENDIAN_H
#define SQUID_ENDIAN_H

/*
 * Macros to deal with byte swapping.  These macros provide
 * the following interface:
 *
 * // Byte-swap
 * uint16_t bswap16(uint16_t);
 * uint32_t bswap32(uint32_t);
 *
 * // Convert from host byte order to big-endian, and vice versa.
 * uint16_t htobe16(uint16_t); // equivalent to htons()
 * uint32_t htobe32(uint32_t); // equivalent to htonl()
 * uint16_t be16toh(uint16_t); // equivalent to ntohs()
 * uint32_t be32toh(uint32_t); // equivalent to ntohs()
 *
 * // Convert from host byte order to little-endian, and vice versa.
 * uint16_t htole16(uint16_t);
 * uint32_t htole32(uint32_t);
 * uint16_t le16toh(uint16_t);
 * uint32_t le32toh(uint32_t);
 */

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
#if HAVE_MACHINE_BYTE_SWAP_H
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
       (((((uint16_t)(x)) >> 8) & 0xff) | ((((uint16_t)(x)) & 0xff) << 8))
#  endif
#endif /* ! HAVE_BSWAP16 && ! defined(bswap16) */
#if ! HAVE_BSWAP32 && ! defined(bswap32)
#  if defined(bswap_32)
#    define bswap32(x) bswap_32(x)
#  else
#    define bswap32(x) \
       (((((uint32_t)(x)) & 0xff000000) >> 24) | \
        ((((uint32_t)(x)) & 0x00ff0000) >>  8) | \
        ((((uint32_t)(x)) & 0x0000ff00) <<  8) | \
        ((((uint32_t)(x)) & 0x000000ff) << 24))
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
#if _SQUID_OPENBSD_
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
