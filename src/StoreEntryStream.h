
/*
 * $Id: StoreEntryStream.h,v 1.2 2006/05/06 01:30:45 robertc Exp $
 *
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

#ifndef SQUID_STORE_ENTRY_STREAM_H
#define SQUID_STORE_ENTRY_STREAM_H

#include "Store.h"

#include <ostream>

/*
 * This class provides a streambuf interface for writing
 * to StoreEntries. Typical use is via a StoreEntryStream
 * rather than direct manipulation
 */

class StoreEntryStreamBuf : public std::streambuf
{

public:
    StoreEntryStreamBuf(StoreEntry *anEntry) : anEntry(anEntry)
    {

        anEntry->lock()

        ;
        anEntry->buffer();
    }

    ~StoreEntryStreamBuf()
    {
        anEntry->unlock();
    }

protected:
    /* flush the current buffer and the character that is overflowing
     * to the store entry.
     */
    virtual char overflow(char aChar = traits_type::eof())
    {
        std::streamsize pending(pptr() - pbase());

        if (pending && sync ())
            return traits_type::eof();

        if (aChar != traits_type::eof()) {
            char chars[1] = {aChar};

            if (aChar != traits_type::eof())
                anEntry->append(chars, 1);
        }

        pbump (-pending);  // Reset pptr().
        return aChar;
    }

    /* push the buffer to the store */
    virtual int sync()
    {
        std::streamsize pending(pptr() - pbase());

        if (pending)
            anEntry->append(pbase(), pending);

        anEntry->flush();

        return 0;
    }

    /* write multiple characters to the store entry
     * - this is an optimisation method.
     */
    virtual std::streamsize xsputn(const char * chars, std::streamsize number)
    {
        if (number)
            anEntry->append(chars, number);

        return number;
    }

private:
    StoreEntry *anEntry;

};

class StoreEntryStream : public std::ostream
{

public:
    /* create a stream for writing text etc into anEntry */
    StoreEntryStream(StoreEntry *anEntry) : std::ostream(&_buffer), _buffer(anEntry) { this->init(&_buffer);}

private:
    StoreEntryStreamBuf _buffer;

public:
    StoreEntryStreamBuf * rdbuf() const { return const_cast<StoreEntryStreamBuf *>(&_buffer); }
};

#endif /* SQUID_STORE_ENTRY_STREAM_H */
