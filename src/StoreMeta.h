
/*
 * $Id: StoreMeta.h,v 1.3 2003/08/04 22:14:41 robertc Exp $
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

#ifndef SQUID_TYPELENGTHVALUE_H
#define SQUID_TYPELENGTHVALUE_H

class StoreEntry;

typedef class StoreMeta tlv;

class StoreMeta
{

public:
    static bool validType(char);
    static int const MaximumTLVLength;
    static int const MinimumTLVLength;
    static StoreMeta *Factory (char type, size_t len, void const *value);
    static StoreMeta **Add(StoreMeta **tail, StoreMeta *aNode);
    static void FreeList (StoreMeta **head);

    virtual char getType() const = 0;
    virtual bool validLength(int) const;
    virtual bool checkConsistency(StoreEntry *) const;
    virtual ~StoreMeta(){}

    int length;
    void *value;
    tlv *next;

private:
};

/*
 * store_swapmeta.c
 */
SQUIDCEXTERN char *storeSwapMetaPack(tlv * tlv_list, int *length);
SQUIDCEXTERN tlv *storeSwapMetaBuild(StoreEntry * e);
SQUIDCEXTERN void storeSwapTLVFree(tlv * n);

#endif /* SQUID_TYPELENGTHVALUE_H */
