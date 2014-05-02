/*
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
