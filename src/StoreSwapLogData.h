/*
 * $Id$
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef SQUID_STORESWAPLOGDATA_H
#define SQUID_STORESWAPLOGDATA_H

/**
 \defgroup FileFormatSwapStateAPI swap.state File Structure
 \ingroup FileSystems
 \section ImplementationNotes Implementation Notes
 \par
 *      When writing an object to disk, we must first write the meta data.
 *      This is done with a couple of functions.  First, storeSwapMetaPack()
 *      takes a StoreEntry as a parameter and returns a tlv linked
 *      list.  Second, storeSwapMetaPack() converts the tlv list
 *      into a character buffer that we can write.
 *
 \note  MemObject has a MemObject::swap_hdr_sz.
 *      This value is the size of that character buffer; the size of the
 *      swap file meta data.  The StoreEntry has a member
 *      StoreEntry::swap_file_sz that represents the size of the disk file.
 *      Thus, the size of the object "content" is
 \code    StoreEntry->swap_file_sz  - MemObject->swap_hdr_sz;    \endcode
 \note The swap file content includes the HTTP reply headers and the HTTP reply body (if any).
 *
 \par
 *      When reading a swap file, there is a similar process to extract
 *      the swap meta data.  First, storeSwapMetaUnpack() converts a
 *      character buffer into a tlv linked list.  It also tells us
 *      the value for MemObject->swap_hdr_sz.
 */

#include "squid.h"

/*
 * Do we need to have the dirn in here? I don't think so, since we already
 * know the dirn ..
 */
/**
 \ingroup FielFormatSwapStateAPI
 \note This information is current as of version 2.2.STABLE4
 *
 \li		Binary format on disk.
 \li		DO NOT randomly alter.
 \li		DO NOT add ANY virtual's.
 *
 \par
 * Defines the structure of a binary swap.state file entry.
 *
 \note StoreSwapLogData entries are written in native machine byte order
 *     They are not necessarily portable across architectures.
 */
class StoreSwapLogData
{

public:
    MEMPROXY_CLASS(StoreSwapLogData);
    StoreSwapLogData();

    /**
     * Either SWAP_LOG_ADD when an object is added to the disk storage,
     * or SWAP_LOG_DEL when an object is deleted.
     */
    char op;

    /**
     * The 32-bit file number which maps to a pathname.
     * Only the low 24-bits are relevant. The high 8-bits are
     * used as an index to an array of storage directories, and
     * are set at run time because the order of storage directories
     * may change over time.
     */
    sfileno swap_filen;

    /**
     * A 32-bit Unix time value that represents the time when
     * the origin server generated this response. If the response
     * has a valid Date: header, this timestamp corresponds
     * to that time. Otherwise, it is set to the Squid process time
     * when the response is read (as soon as the end of headers are found).
     */
    time_t timestamp;

    /**
     * The last time that a client requested this object.
     * Strictly speaking, this time is set whenever the StoreEntry
     * is locked (via storeLockObject()).
     */
    time_t lastref;

    /**
     * The value of the response's Expires: header, if any.
     * If the response does not have an Expires: header, this
     * is set to -1.
     * If the response has an invalid (unparseable)
     * Expires: header, it is also set to -1.  There are some cases
     * where Squid sets expires to -2. This happens for the
     * internal "netdb" object and for FTP URL responses.
     */
    time_t expires;

    /**
     * The value of the response's Last-modified: header, if any.
     * This is set to -1 if there is no Last-modified: header,
     * or if it is unparseable.
     */
    time_t lastmod;

    /**
     * This is the number of bytes that the object occupies on
     * disk. It includes the Squid "swap file header".
     */
    uint64_t swap_file_sz;

    /**
     * The number of times that this object has been accessed (referenced).
     * Since its a 16-bit quantity, it is susceptible to overflow
     * if a single object is accessed 65,536 times before being replaced.
     */
    uint16_t refcount;

    /**
     * A copy of the StoreEntry flags field. Used as a sanity
     * check when rebuilding the cache at startup. Objects that
     * have the KEY_PRIVATE flag set are not added back to the cache.
     */
    uint16_t flags;

    /**
     * The 128-bit MD5 hash for this object.
     */
    unsigned char key[SQUID_MD5_DIGEST_LENGTH];
};

MEMPROXY_CLASS_INLINE(StoreSwapLogData);

/// \ingroup FileFormatSwapStateAPI
class StoreSwapLogHeader
{
public:
    StoreSwapLogHeader();
    char op;
    int version;
    int record_size;
};


#endif /* SQUID_STORESWAPLOGDATA_H */
