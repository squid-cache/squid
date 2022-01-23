/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
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

#include "md5.h"
#include "mem/forward.h"
#include "store/forward.h"

/// maintains a 24-bit checksum over integer fields
class SwapChecksum24
{
public:
    SwapChecksum24() { raw[0] = raw[1] = raw[2] = 0; }

    bool operator ==(const SwapChecksum24 &o) const {
        return raw[0] == o.raw[0] && raw[1] == o.raw[1] && raw[2] == o.raw[2];
    }

    bool operator !=(const SwapChecksum24 &o) const {
        return !(*this == o);
    }

    /// compute and store checksum based on three 32bit integers
    void set(uint32_t f1, uint32_t f2, uint32_t f3);

    /// compute and store checksum based on int32_t and uint64_t integers
    void set(int32_t f1, uint64_t f2);

    // printing for debugging
    std::ostream &print(std::ostream &os) const;

private:
    uint8_t raw[3]; // designed to follow "op" members, in pading space
};

inline std::ostream &
operator <<(std::ostream &os, const SwapChecksum24 &sum)
{
    return sum.print(os);
}

/**
 \ingroup FielFormatSwapStateAPI
 *
 \par
 * Defines the structure of a binary swap.state file entry for UFS stores.
 * TODO: Move to fs/ufs
 *
 \note StoreSwapLogData entries are written in native machine byte order
 *     They are not necessarily portable across architectures.
 */
class StoreSwapLogData
{
    MEMPROXY_CLASS(StoreSwapLogData);

public:
    /// type to use for storing time-related members; must be signed
    typedef int64_t SwappedTime;

    /// consistency self-check: whether the data appears to make sense
    bool sane() const;

    /// call this before storing the log entry
    void finalize();

    /**
     * Either SWAP_LOG_ADD when an object is added to the disk storage,
     * or SWAP_LOG_DEL when an object is deleted.
     */
    uint8_t op = 0;

    /**
     * Fingerprint to weed out bogus/corrupted swap.state entries.
     */
    SwapChecksum24 checksum; // follows "op" because compiler will pad anyway

    /**
     * The 32-bit file number which maps to a pathname.
     * Only the low 24-bits are relevant. The high 8-bits are
     * used as an index to an array of storage directories, and
     * are set at run time because the order of storage directories
     * may change over time.
     */
    sfileno swap_filen = 0;

    /**
     * A Unix time value that represents the time when
     * the origin server generated this response. If the response
     * has a valid Date: header, this timestamp corresponds
     * to that time. Otherwise, it is set to the Squid process time
     * when the response is read (as soon as the end of headers are found).
     */
    SwappedTime timestamp = 0;

    /**
     * The last time that a client requested this object.
     */
    SwappedTime lastref = 0;

    /**
     * The value of the response's Expires: header, if any.
     * If the response does not have an Expires: header, this
     * is set to -1.
     * If the response has an invalid (unparseable)
     * Expires: header, it is also set to -1.  There are some cases
     * where Squid sets expires to -2. This happens for the
     * internal "netdb" object and for FTP URL responses.
     */
    SwappedTime expires = 0;

    /**
     * The value of the response's Last-modified: header, if any.
     * This is set to -1 if there is no Last-modified: header,
     * or if it is unparseable.
     */
    SwappedTime lastmod = 0;

    /**
     * This is the number of bytes that the object occupies on
     * disk. It includes the Squid "swap file header".
     */
    uint64_t swap_file_sz = 0;

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
    uint16_t flags = 0;

    /**
     * The 128-bit MD5 hash for this object.
     */
    unsigned char key[SQUID_MD5_DIGEST_LENGTH] = {};
};

/// \ingroup FileFormatSwapStateAPI
/// Swap log starts with this binary structure.
class StoreSwapLogHeader
{
public:
    // sets default values for this Squid version; loaded values may differ
    StoreSwapLogHeader();

    /// consistency self-check: whether the data appears to make sense
    bool sane() const;

    /// number of bytes after the log header before the first log entry
    size_t gapSize() const;

    uint8_t op;
    SwapChecksum24 checksum; // follows "op" because compiler will pad anyway
    int32_t version;
    int32_t record_size;
};

#endif /* SQUID_STORESWAPLOGDATA_H */

