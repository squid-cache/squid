/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STORE_STATS_H
#define SQUID_STORE_STATS_H

/// High-level store statistics used by mgr:info action. Used inside PODs!
class StoreInfoStats
{
public:
    /// Info common to memory and disk parts of the storage. Used inside PODs!
    class Part
    {
    public:
        double size = 0.0; ///< bytes currently in use
        double count = 0.0; ///< number of cached objects
        double capacity = 0.0; ///< the size limit

        /// mean size of a cached object
        double meanObjectSize() const { return count > 0 ? size/count : 0.0; }

        /// number of unused bytes
        double available() const { return capacity - size; }
    };

    /// disk cache (all cache_dirs) storage stats
    class Swap: public Part
    {
    public:
        double open_disk_fd = 0.0; ///< number of opened disk files
    };

    /// memory cache (cache_mem) storage stats
    class Mem: public Part
    {
    public:
        bool shared = false; ///< whether memory cache is shared among workers
    };

    StoreInfoStats &operator +=(const StoreInfoStats &stats);

    Swap swap; ///< cache_mem stats
    Mem mem; ///< all cache_dirs stats

    /* stats that could be shared by memory and disk storage */
    double store_entry_count = 0.0; ///< number of StoreEntry objects in existence
    double mem_object_count = 0.0; ///< number of MemObject objects in existence
};

// TODO: this should be adjusted for use in StoreIoActionData, DiskdActionData
/// Store statistics related to low-level I/O.
class StoreIoStats
{
public:
    StoreIoStats();

    struct {
        int calls;
        int select_fail;
        int create_fail;
        int success;
    } create; ///< cache_dir selection and disk entry creation stats
};

#endif /* SQUID_STORE_STATS_H */

