
/*
 * $Id: ufsdump.cc,v 1.9 2006/09/13 19:05:11 serassio Exp $
 *
 * DEBUG: section 0     UFS Store Dump
 * AUTHOR: Robert Collins
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

#include "squid.h"
#include "StoreMeta.h"
#include "StoreMetaUnpacker.h"
#include "Store.h"
#include "Generic.h"
#undef malloc
#undef free
#include <stdexcept>
#include <iostream>
#include <cassert>

/* stub functions for parts of squid not factored to be dynamic yet */
void shut_down(int)
{}

#if WHENITMINIMAL
void
eventAdd(const char *name, EVH * func, void *arg, double when, int, bool cbdata)
{}

#endif
/* end stub functions */

struct DumpStoreMeta : public unary_function<StoreMeta, void>
{
    DumpStoreMeta(){}

    void operator()(StoreMeta const &x)
    {
        switch (x.getType()) {

        case STORE_META_KEY:
            std::cout << "MD5: " << storeKeyText((const cache_key *)x.value) << std::endl;
            break;

        case STORE_META_STD:
            break;

        case STORE_META_URL:
            assert (((char *)x.value)[x.length - 1] == 0);
            std::cout << "URL: " << (char *)x.value << std::endl;

        default:
            break;
        }
    }
};

int
main(int argc, char *argv[])
{
    int fd = -1;
    StoreMeta *metadata = NULL;

    try
    {
        if (argc != 2)
            throw std::runtime_error("No filename provided");

        fd = open (argv[1], O_RDONLY | O_BINARY);

        if (fd < 0)
            throw std::runtime_error("Could not open file.");

        char tempbuf[SM_PAGE_SIZE];

        int len = read(fd, tempbuf, SM_PAGE_SIZE);

        if (len < 0)
            throw std::runtime_error("Could not read header into memory.");

        close (fd);

        fd = -1;

        int hdr_len;

        StoreMetaUnpacker aBuilder(tempbuf, len, &hdr_len);

        metadata = aBuilder.createStoreMeta ();

        cache_key key[MD5_DIGEST_CHARS];

        memset(key, '\0', MD5_DIGEST_CHARS);

        DumpStoreMeta dumper;

        for_each(*metadata, dumper);


        return 0;
    } catch (std::runtime_error error)
    {
        std::cout << "Failed : " << error.what() << std::endl;

        if (fd >= 0)
            close(fd);

        if (metadata)
            StoreMeta::FreeList(&metadata);

        return 1;
    }
}
