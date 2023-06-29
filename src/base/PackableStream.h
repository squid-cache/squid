/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_PACKABLESTREAM_H
#define SQUID_SRC_BASE_PACKABLESTREAM_H

#include "base/Packable.h"

#include <ostream>

// TODO: Move to src/base/AppendingStreamBuf.h
/// write-only std::streambuf that append()s all writes to a given Buffer
template <class Buffer>
class AppendingStreamBuf : public std::streambuf
{
public:
    explicit AppendingStreamBuf(Buffer &p): buf_(p) { postInit(); }
    ~AppendingStreamBuf() override = default;

protected:
    /* std::streambuf API */

    int_type overflow(int_type aChar = traits_type::eof()) override {
        std::streamsize pending(pptr() - pbase());

        if (pending && sync())
            return traits_type::eof();

        if (aChar != traits_type::eof()) {
            const char C = static_cast<char>(aChar);
            lowAppend(&C, 1);
        }

        pbump(-pending);  // Reset pptr().
        return aChar;
    }

    int sync() override {
        std::streamsize pending(pptr() - pbase());
        lowAppend(pbase(), pending);
        postSync();
        return 0;
    }

    std::streamsize xsputn(const char * chars, std::streamsize number) override {
        lowAppend(chars, number);
        return number;
    }

private:
    /// for specializations that must customize the last construction step
    void postInit() {}

    /// for specializations that must customize the last sync() step
    void postSync() {}

    void lowAppend(const char *s, const std::streamsize n) {buf_.append(s,n);}

    Buffer &buf_; ///< the associated character sequence (a.k.a. the sink)
};

/**
 * Provides a streambuf interface for writing to Packable objects.
 * Typical use is via a PackableStream rather than direct manipulation
 */
using PackableStreamBuf = AppendingStreamBuf<Packable>;
template <> inline void PackableStreamBuf::postInit() { buf_.buffer(); }
template <> inline void PackableStreamBuf::postSync() { buf_.flush(); }

class PackableStream : public std::ostream
{
public:
    /* create a stream for writing text etc into theBuffer */
    // See http://www.codecomments.com/archive292-2005-2-396222.html
    explicit PackableStream(Packable &p) : std::ostream(nullptr), theBuffer(p) {
        rdbuf(&theBuffer); // set the buffer to now-initialized theBuffer
        clear(); //clear badbit set by calling init(0)
    }

private:
    PackableStreamBuf theBuffer;
};

#endif /* SQUID_SRC_BASE_PACKABLESTREAM_H */

