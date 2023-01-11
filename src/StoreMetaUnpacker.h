/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_TYPELENGTHVALUEUNPACKER_H
#define SQUID_TYPELENGTHVALUEUNPACKER_H

class StoreMeta;
class StoreEntry;

class StoreMetaUnpacker
{

public:
    StoreMetaUnpacker (const char *buf, ssize_t bufferLength, int *hdrlen);
    StoreMeta *createStoreMeta();
    bool isBufferZero(); ///< all-zeros buffer, checkBuffer() would throw
    /// validates buffer sanity and throws if validation fails
    void checkBuffer();

private:
    static int const MinimumBufferLength;

    void getBufferLength();
    void getType();
    void getLength();
    void getTLV();
    bool doOneEntry();
    bool moreToProcess() const;

    char const * const buf;
    ssize_t buflen;
    int *hdr_len;
    int position;
    char type;
    int length;
    StoreMeta **tail;
};

#endif /* SQUID_TYPELENGTHVALUEUNPACKER_H */

