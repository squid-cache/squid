#ifndef SQUID_MEMSTOREMAP_H
#define SQUID_MEMSTOREMAP_H

#include "ipc/StoreMap.h"
#include "ipc/mem/Page.h"

/// map of MemStore-cached entries
class MemStoreMap: public Ipc::StoreMap
{
public:
    // StoreEntry restoration info not already stored by Ipc::StoreMap
    class Extras {
    public:
        Ipc::Mem::PageId page; ///< shared memory page with the entry content
        int64_t storedSize; ///< total size of the stored entry content
	};

public:
    MemStoreMap(const char *const aPath, const int limit); ///< create a new shared StoreMap
    MemStoreMap(const char *const aPath); ///< open an existing shared StoreMap

    /// write access to the extras; call openForWriting() first!
    Extras &extras(const sfileno fileno);
    /// read-only access to the extras; call openForReading() first!
    const Extras &extras(const sfileno fileno) const;

private:
    /// data shared by all MemStoreMaps with the same path
    class Shared {
    public:
        static size_t MemSize(int limit);
        Extras extras[]; ///< extras storage
    };

    Shared *shared; ///< pointer to shared memory
};

#endif /* SQUID_MEMSTOREMAP_H */
