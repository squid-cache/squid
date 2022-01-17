/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_PACKABLESTREAM_H
#define SQUID_SRC_BASE_PACKABLESTREAM_H

#include "base/Packable.h"

#include <ostream>

/**
 * Provides a streambuf interface for writing to Packable objects.
 * Typical use is via a PackableStream rather than direct manipulation
 */
class PackableStreamBuf : public std::streambuf
{
public:
    explicit PackableStreamBuf(Packable &p) : buf_(p) { buf_.buffer(); }
    virtual ~PackableStreamBuf() = default;

protected:
    /** flush the current buffer and the character that is overflowing
     * to the Packable.
     */
    virtual int_type overflow(int_type aChar = traits_type::eof()) override {
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

    /** push the buffer to the Packable */
    virtual int sync() override {
        std::streamsize pending(pptr() - pbase());
        lowAppend(pbase(), pending);
        buf_.flush();
        return 0;
    }

    /** write multiple characters to the Packable
     * - this is an optimisation method.
     */
    virtual std::streamsize xsputn(const char * chars, std::streamsize number) override {
        lowAppend(chars, number);
        return number;
    }

private:
    void lowAppend(const char *s, const std::streamsize n) {buf_.append(s,n);}

    Packable &buf_;
};

class PackableStream : public std::ostream
{
public:
    /* create a stream for writing text etc into theBuffer */
    // See http://www.codecomments.com/archive292-2005-2-396222.html
    explicit PackableStream(Packable &p) : std::ostream(0), theBuffer(p) {
        rdbuf(&theBuffer); // set the buffer to now-initialized theBuffer
        clear(); //clear badbit set by calling init(0)
    }

private:
    PackableStreamBuf theBuffer;
};

#endif /* SQUID_SRC_BASE_PACKABLESTREAM_H */

