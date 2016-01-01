/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SBUFSTREAM_H
#define SQUID_SBUFSTREAM_H

#include "SBuf.h"

#include <ostream>

/** streambuf class for a SBuf-backed stream interface.
 *
 * Auxiliary class to be able to leverage an ostream generating SBuf's
 * analogous to std::ostrstream.
 */
class SBufStreamBuf : public std::streambuf
{
public:
    /// initialize streambuf; use supplied SBuf as backing store
    explicit SBufStreamBuf(SBuf aBuf) : theBuf(aBuf) {}

    /// get a copy of the stream's contents
    SBuf getBuf() {
        return theBuf;
    }

    /// clear the stream's store
    void clearBuf() {
        theBuf.clear();
    }

protected:
    virtual int_type overflow(int_type aChar = traits_type::eof()) {
        std::streamsize pending(pptr() - pbase());

        if (pending && sync())
            return traits_type::eof();

        if (aChar != traits_type::eof()) {
            char chars[1] = {static_cast<char>(aChar)};

            if (aChar != traits_type::eof())
                theBuf.append(chars, 1);
        }

        pbump(-pending);  // Reset pptr().
        return aChar;
    }

    /// push the streambuf to the backing SBuf
    virtual int sync() {
        std::streamsize pending(pptr() - pbase());

        if (pending)
            theBuf.append(pbase(), pending);

        return 0;
    }

    /** write multiple characters to the store entry
     * \note this is an optimisation consistent with std::streambuf API
     */
    virtual std::streamsize xsputn(const char * chars, std::streamsize number) {
        if (number)
            theBuf.append(chars, number);

        return number;
    }

private:
    SBuf theBuf;
    SBufStreamBuf(); // no default constructor
};

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
    SBufStream(SBuf aBuf): std::ostream(0), theBuffer(aBuf) {
        rdbuf(&theBuffer); // set the buffer to now-initialized theBuffer
        clear(); //clear badbit set by calling init(0)
    }

    /// Create an empty SBufStream
    SBufStream(): std::ostream(0), theBuffer(SBuf()) {
        rdbuf(&theBuffer); // set the buffer to now-initialized theBuffer
        clear(); //clear badbit set by calling init(0)
    }

    /// Retrieve a copy of the current stream status
    SBuf buf() {
        flush();
        return theBuffer.getBuf();
    }

    /// Clear the stream's backing store
    SBufStream& clearBuf() {
        flush();
        theBuffer.clearBuf();
        return *this;
    }

private:
    SBufStreamBuf theBuffer;
};

#endif /* SQUID_SBUFSTREAM_H */

