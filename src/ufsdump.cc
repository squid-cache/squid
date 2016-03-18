/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 00    UFS Store Dump Tool */

#include "squid.h"
#include "Generic.h"
#include "md5.h"
#include "mgr/Registration.h"
#include "Store.h"
#include "store_key_md5.h"
#include "StoreMeta.h"
#include "StoreMetaUnpacker.h"

#undef malloc
#undef free

#include <cassert>
#include <iostream>
#include <stdexcept>

/* stub functions for parts of squid not factored to be dynamic yet */
void
eventAdd(const char *name, EVH * func, void *arg, double when, int, bool cbdata)
{}

// required by storeKeyPublicByRequest*
// XXX: what pulls in storeKeyPublicByRequest?
const char *urlCanonical(HttpRequest *) { assert(false); return NULL; }

void
storeAppendPrintf(StoreEntry * e, const char *fmt,...)
{
    va_list args;
    va_start(args, fmt);

    assert(false);

    va_end(args);
}

void
Mgr::RegisterAction(char const * action, char const * desc, OBJH * handler, int pw_req_flag, int atomic) {}

/* MinGW needs also a stub of death() */
void
death(int sig)
{
    std::cout << "Fatal: Signal " <<  sig;
    exit(1);
}

void
fatal(const char *message)
{
    fprintf(stderr, "FATAL: %s\n", message);
    exit(1);
}

/* end stub functions */

struct MetaStd {
    time_t timestamp;
    time_t lastref;
    time_t expires;
    time_t lastmod;
    size_t swap_file_sz;
    uint16_t refcount;
    uint16_t flags;
};

struct MetaStdLfs {
    time_t timestamp;
    time_t lastref;
    time_t expires;
    time_t lastmod;
    uint64_t swap_file_sz;
    uint16_t refcount;
    uint16_t flags;
};

struct DumpStoreMeta : public unary_function<StoreMeta, void> {
    DumpStoreMeta() {}

    void operator()(StoreMeta const &x) {
        switch (x.getType()) {

        case STORE_META_KEY:
            std::cout << "MD5: " << storeKeyText((const cache_key *)x.value) << std::endl;
            break;

        case STORE_META_STD:
            std::cout << "STD, Size:" << ((struct MetaStd*)x.value)->swap_file_sz <<
                      " Flags: 0x" << std::hex << ((struct MetaStd*)x.value)->flags << std::dec <<
                      " Refcount: " << ((struct MetaStd*)x.value)->refcount <<
                      std::endl;
            break;

        case STORE_META_STD_LFS:
            std::cout << "STD_LFS, Size: " << ((struct MetaStdLfs*)x.value)->swap_file_sz <<
                      " Flags: 0x" << std::hex << ((struct MetaStdLfs*)x.value)->flags << std::dec <<
                      " Refcount: " << ((struct MetaStdLfs*)x.value)->refcount <<
                      std::endl;
            break;

        case STORE_META_URL:
            assert (((char *)x.value)[x.length - 1] == 0);
            std::cout << "URL: " << (char *)x.value << std::endl;
            break;

        default:
            std::cout << "Unknown store meta type: " << (int)x.getType() <<
                      " of length " << x.length << std::endl;
            break;
        }
    }
};

int
main(int argc, char *argv[])
{
    int fd = -1;
    StoreMeta *metadata = NULL;

    try {
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

        cache_key key[SQUID_MD5_DIGEST_LENGTH];

        memset(key, '\0', SQUID_MD5_DIGEST_LENGTH);

        DumpStoreMeta dumper;

        for_each(*metadata, dumper);

        return 0;
    } catch (std::runtime_error error) {
        std::cout << "Failed : " << error.what() << std::endl;

        if (fd >= 0)
            close(fd);

        if (metadata)
            StoreMeta::FreeList(&metadata);

        return 1;
    }
}

