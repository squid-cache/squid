/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STORE_FORWARD_H
#define SQUID_STORE_FORWARD_H

// bug 4610 see comments 22-38
// Nasty hack, but it turns out C++ allows int32_t to be
// unsigned when used as a bitmask (as sfile* are later)
#if INT_MAX == INT32_MAX
typedef signed int signed_int32_t;
#elif SHORT_MAX == INT32_MAX
typedef signed short int signed_int32_t;
#else
#error I do not know how to typedef a signed 32bit integer.
#endif
typedef signed_int32_t sfileno;
typedef signed int sdirno;

/// maximum number of entries per cache_dir
enum { SwapFilenMax = 0xFFFFFF }; // keep in sync with StoreEntry::swap_filen

/// Store key.
typedef unsigned char cache_key;

class StoreSearch;
class StoreClient;
class StoreEntry;
class MemStore;
class Transients;

namespace Store
{
/// cache "I/O" direction and status
enum IoStatus { ioUndecided, ioWriting, ioReading, ioDone };

class Storage;
class Controller;
class Controlled;
class Disks;
class Disk;
class DiskConfig;
class EntryGuard;

typedef ::StoreEntry Entry;
typedef ::MemStore Memory;
typedef ::Transients Transients;
} // namespace Store

// TODO: Remove these once all code has been transitioned to Store namespace.
typedef Store::Controller StoreController;
typedef Store::Disks StoreHashIndex;
typedef Store::Disk SwapDir;
template <class C> class RefCount;
typedef RefCount<Store::Disk> SwapDirPointer;

#endif /* SQUID_STORE_FORWARD_H */

