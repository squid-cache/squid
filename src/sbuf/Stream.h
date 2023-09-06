/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SBUFSTREAM_H
#define SQUID_SBUFSTREAM_H

#include "base/PackableStream.h"
#include "sbuf/SBuf.h"

/** Stream interface to write to a SBuf.
 *
 * Data is appended using standard operator << semantics, and extracted
 * using the buf() method, in analogy with std::strstream .
 */
class SBufStream : public std::ostream
{
public:
    /** Create a SBufStream preinitialized with the contents of a SBuf
     *
     * The supplied SBuf copied: in order to retrieve the written-to contents
     * they must be later fetched using the buf() class method.
     */
    SBufStream(const SBuf &aBuf):
        std::ostream(nullptr), // initialize the parent; no stream buffer yet
        sink_(aBuf),
        streamBuffer_(sink_) // initialize the stream buffer
    {
        rdbuf(&streamBuffer_); // supply the now-initialized stream buffer
        clear(); // clear the badbit that a nullptr stream buffer has triggered
    }

    /// Create an empty SBufStream
    SBufStream(): SBufStream(SBuf()) {}

    /// bytes written so far
    SBuf buf() {
        flush();
        return sink_;
    }

    /// Clear the stream's backing store
    SBufStream& clearBuf() {
        flush();
        sink_.clear();
        return *this;
    }

private:
    /// buffer for (flushed) bytes written to the stream
    SBuf sink_;
    /// writes raw (post-formatting) bytes to the sink_
    AppendingStreamBuf<SBuf> streamBuffer_;
};

/// slowly stream-prints all arguments into a freshly allocated SBuf
template <typename... Args>
inline
SBuf ToSBuf(Args&&... args)
{
    SBufStream out;
    (out << ... << args);
    return out.buf();
}

#endif /* SQUID_SBUFSTREAM_H */

