/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_LIB_NTLMAUTH_SUPPORT_ENDIAN_H
#define SQUID_LIB_NTLMAUTH_SUPPORT_ENDIAN_H

#if HAVE_BYTESWAP_H
#include <byteswap.h>
#endif
#if HAVE_MACHINE_BYTE_SWAP_H
#include <machine/byte_swap.h>
#endif
#if HAVE_SYS_BSWAP_H
#include <sys/bswap.h>
#endif
#if HAVE_ENDIAN_H
#include <endian.h>
#endif
#if HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif

/*
 * Macros to deal with byte swapping.  These macros provide
 * the following interface:
 *
 * // Byte-swap
 * uint16_t bswap16(uint16_t);
 * uint32_t bswap32(uint32_t);
 *
 * // Convert from host byte order to little-endian, and vice versa.
 * uint16_t htole16(uint16_t);
 * uint32_t htole32(uint32_t);
 * uint16_t le16toh(uint16_t);
 * uint32_t le32toh(uint32_t);
 *
 * XXX: What about unusual byte orders like 3412 or 2143 ?
 *      Never had any problems reported, so we dont worry about them.
 */

#if !HAVE_HTOLE16 && !defined(htole16)
/* Define bswap16() in terms of bswap_16() or the hard way. */
#if !HAVE_BSWAP16 && !defined(bswap16)
#  if HAVE_BSWAP_16 || defined(bswap_16)
#    define bswap16(x) bswap_16(x)
#  else // 'hard way'
#    define bswap16(x) \
       (((((uint16_t)(x)) >> 8) & 0xff) | ((((uint16_t)(x)) & 0xff) << 8))
#  endif
#endif

/* Define htole16() in terms of bswap16(). */
#  if defined(WORDS_BIGENDIAN)
#    define htole16(x) bswap16(x)
#  else
#    define htole16(x) (x)
#  endif
#endif

#if !HAVE_HTOLE32 && !defined(htole32)
#if ! HAVE_BSWAP32 && ! defined(bswap32)
/* Define bswap32() in terms of bswap_32() or the hard way. */
#  if HAVE_BSWAP_32 || defined(bswap_32)
#    define bswap32(x) bswap_32(x)
#  else // 'hard way'
#    define bswap32(x) \
       (((((uint32_t)(x)) & 0xff000000) >> 24) | \
        ((((uint32_t)(x)) & 0x00ff0000) >>  8) | \
        ((((uint32_t)(x)) & 0x0000ff00) <<  8) | \
        ((((uint32_t)(x)) & 0x000000ff) << 24))
#  endif

/* Define htole32() in terms of bswap32(). */
#endif
#  if defined(WORDS_BIGENDIAN)
#    define htole32(x) bswap32(x)
#  else
#    define htole32(x) (x)
#  endif
#endif

/* Define letoh*() in terms of htole*(). The swap is symmetrical. */
#if !HAVE_LE16TOH && !defined(le16toh)
#define le16toh(x) htole16(x)
#endif
#if !HAVE_LE32TOH && !defined(le32toh)
#define le32toh(x) htole32(x)
#endif

#endif /* SQUID_LIB_NTLMAUTH_SUPPORT_ENDIAN_H */

