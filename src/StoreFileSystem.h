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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef SQUID_STOREFILESYSTEM_H
#define SQUID_STOREFILESYSTEM_H

#include "base/Vector.h"

/* ****** DOCUMENTATION ***** */

/**
 \defgroup FileSystems	Storage Filesystems
 *
 \section Introduction Introduction
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
 \todo DOCS: add template addition to configure.ac for storage module addition.
 \todo DOCS: add template Makefile.am for storage module addition.
 *
 \par
 * configure will take a list of storage types through the
 * --enable-store-io parameter. This parameter takes a list of
 * space seperated storage types. For example,
 * --enable-store-io="ufs coss" .
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

class SwapDir;

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
    static Vector<StoreFileSystem*> const &FileSystems();
    typedef Vector<StoreFileSystem*>::iterator iterator;
    typedef Vector<StoreFileSystem*>::const_iterator const_iterator;
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
    static Vector<StoreFileSystem*> &GetFileSystems();
    static Vector<StoreFileSystem*> *_FileSystems;
    static void RegisterAllFsWithCacheManager(void);
};

// TODO: Kill this typedef!
typedef StoreFileSystem storefs_entry_t;

#endif /* SQUID_STOREFILESYSTEM_H */
