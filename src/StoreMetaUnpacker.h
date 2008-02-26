
/*
 * $Id: StoreMetaUnpacker.h,v 1.2.4.1 2008/02/25 23:08:50 amosjeffries Exp $
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

#ifndef SQUID_TYPELENGTHVALUEUNPACKER_H
#define SQUID_TYPELENGTHVALUEUNPACKER_H

class StoreMeta;

class StoreMetaUnpacker
{

public:
    StoreMetaUnpacker (const char *buf, ssize_t bufferLength, int *hdrlen);
    StoreMeta *createStoreMeta();
    bool isBufferSane();

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

/*
 * store_swapmeta.c
 */
SQUIDCEXTERN char *storeSwapMetaPack(StoreMeta * tlv_list, int *length);
SQUIDCEXTERN StoreMeta *storeSwapMetaBuild(StoreEntry * e);
SQUIDCEXTERN StoreMeta *storeSwapMetaUnpack(const char *buf, int *hdrlen);
SQUIDCEXTERN void storeSwapTLVFree(StoreMeta * n);
StoreMeta ** storeSwapTLVAdd(int type, const void *ptr, size_t len, StoreMeta ** tail);

#endif /* SQUID_TYPELENGTHVALUEUNPACKER_H */
