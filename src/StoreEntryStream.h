/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
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
    StoreEntryStreamBuf(StoreEntry *anEntry) : theEntry(anEntry) {
        theEntry->lock("StoreEntryStreamBuf");
        theEntry->buffer();
    }

    ~StoreEntryStreamBuf() {
        theEntry->unlock("StoreEntryStreamBuf");
    }

protected:
    /* flush the current buffer and the character that is overflowing
     * to the store entry.
     */
    virtual int_type overflow(int_type aChar = traits_type::eof()) {
        std::streamsize pending(pptr() - pbase());

        if (pending && sync ())
            return traits_type::eof();

        if (aChar != traits_type::eof()) {
            // NP: cast because GCC promotes int_type to 32-bit type
            //     std::basic_streambuf<char>::int_type {aka int}
            //     despite the definition with 8-bit type value.
            char chars[1] = {char(aChar)};

            if (aChar != traits_type::eof())
                theEntry->append(chars, 1);
        }

        pbump (-pending);  // Reset pptr().
        return aChar;
    }

    /* push the buffer to the store */
    virtual int sync() {
        std::streamsize pending(pptr() - pbase());

        if (pending)
            theEntry->append(pbase(), pending);

        theEntry->flush();

        return 0;
    }

    /* write multiple characters to the store entry
     * - this is an optimisation method.
     */
    virtual std::streamsize xsputn(const char * chars, std::streamsize number) {
        if (number)
            theEntry->append(chars, number);

        return number;
    }

private:
    StoreEntry *theEntry;

};

class StoreEntryStream : public std::ostream
{

public:
    /* create a stream for writing text etc into theEntry */
    // See http://www.codecomments.com/archive292-2005-2-396222.html
    StoreEntryStream(StoreEntry *entry): std::ostream(0), theBuffer(entry) {
        rdbuf(&theBuffer); // set the buffer to now-initialized theBuffer
        clear(); //clear badbit set by calling init(0)
    }

private:
    StoreEntryStreamBuf theBuffer;
};

#endif /* SQUID_STORE_ENTRY_STREAM_H */

