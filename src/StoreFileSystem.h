/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREFILESYSTEM_H
#define SQUID_STOREFILESYSTEM_H

#include "store/forward.h"
#include <vector>

/* ****** DOCUMENTATION ***** */

/**
 \defgroup FileSystems  Storage Filesystems
 *
 \section FileSystemsIntroduction Introduction
 \par
 * Traditionally, Squid has always used the Unix filesystem (\link UFS UFS\endlink)
 * to store cache objects on disk.  Over the years, the
 * poor performance of \link UFS UFS\endlink has become very obvious.  In most
 * cases, \link UFS UFS\endlink limits Squid to about 30-50 requests per second.
 * Our work indicates that the poor performance is mostly
 * due to the synchronous nature of open() and unlink()
 * system calls, and perhaps thrashing of inode/buffer caches.
 *
 \par
 * We want to try out our own, customized filesystems with Squid.
 * In order to do that, we need a well-defined interface
 * for the bits of Squid that access the permanent storage
 * devices. We also require tighter control of the replacement
 * policy by each storage module, rather than a single global
 * replacement policy.
 *
 \section BuildStructure Build structure
 \par
 * The storage types live in \em src/fs/. Each subdirectory corresponds
 * to the name of the storage type. When a new storage type is implemented
 * configure.ac must be updated to autogenerate a Makefile in
 * \em src/fs/foo/ from a Makefile.in file.
 *
 * TODO: DOCS: add template addition to configure.ac for storage module addition.
 * TODO: DOCS: add template Makefile.am for storage module addition.
 *
 \par
 * configure will take a list of storage types through the
 * --enable-store-io parameter. This parameter takes a list of
 * space separated storage types. For example,
 * --enable-store-io="ufs aufs" .
 *
 \par
 * Each storage type must create an archive file
 * in \em src/fs/foo/.a . This file is automatically linked into
 * squid at compile time.
 *
 \par
 * Each storage filesystem must inherit from StoreFileSystem and provide
 * all virtual function hooks for squid to operate with.
 *
 \section OperationOfStorageModules Operation of a Storage Module
 \par
 *    Squid understands the concept of multiple diverse storage directories.
 *    Each storage directory provides a caching object store, with object
 *    storage, retrieval, indexing and replacement.
 *
 \par
 *    Each open object has associated with it a storeIOState object. The
 *    storeIOState object is used to record the state of the current
 *    object. Each storeIOState can have a storage module specific data
 *    structure containing information private to the storage module.
 *
 \par
 *    Each SwapDir has the concept of a maximum object size. This is used
 *    as a basic hint to the storage layer in first choosing a suitable
 *    SwapDir. The checkobj function is then called for suitable
 *    candidate SwapDirs to find out whether it wants to store a
 *    given StoreEntry. A maxobjsize of -1 means 'any size'.
 */

/**
 \ingroup FileSystems
 *
 * The core API for storage modules this class provides all the hooks
 * squid uses to interact with a filesystem IO module.
 */
class StoreFileSystem
{

public:
    static void SetupAllFs();
    static void FsAdd(StoreFileSystem &);
    static void FreeAllFs();
    static std::vector<StoreFileSystem*> const &FileSystems();
    typedef std::vector<StoreFileSystem*>::iterator iterator;
    typedef std::vector<StoreFileSystem*>::const_iterator const_iterator;
    StoreFileSystem() : initialised(false) {}

    virtual ~StoreFileSystem() {}

    virtual char const *type () const = 0;
    virtual SwapDir *createSwapDir() = 0;
    virtual void done() = 0;
    virtual void setup() = 0;
    // Not implemented
    StoreFileSystem(StoreFileSystem const &);
    StoreFileSystem &operator=(StoreFileSystem const&);

protected:
    bool initialised;
    virtual void registerWithCacheManager(void);

private:
    static std::vector<StoreFileSystem*> &GetFileSystems();
    static std::vector<StoreFileSystem*> *_FileSystems;
    static void RegisterAllFsWithCacheManager(void);
};

// TODO: Kill this typedef!
typedef StoreFileSystem storefs_entry_t;

#endif /* SQUID_STOREFILESYSTEM_H */

