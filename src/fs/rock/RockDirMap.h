#ifndef SQUID_FS_ROCK_DIR_MAP_H
#define SQUID_FS_ROCK_DIR_MAP_H

#include "fs/rock/RockFile.h"
#include "ipc/StoreMap.h"

namespace Rock {

/// \ingroup Rock
/// map of used db slots indexed by sfileno
class DirMap: public Ipc::StoreMap
{
public:
    DirMap(const char *const aPath, const int limit); ///< create a new shared DirMap
    DirMap(const char *const aPath); ///< open an existing shared DirMap

    /// write access to the cell header; call openForWriting() first!
    DbCellHeader &header(const sfileno fileno);
    /// read-only access to the cell header; call openForReading() first!
    const DbCellHeader &header(const sfileno fileno) const;

    static int AbsoluteEntryLimit(); ///< maximum entryLimit() possible

private:
    /// data shared by all DirMaps with the same path
    class Shared {
    public:
        static size_t MemSize(int limit);
        DbCellHeader headers[]; ///< DbCellHeaders storage
    };

    Shared *shared; ///< pointer to shared memory
};

} // namespace Rock

// We do not reuse struct _fileMap because we cannot control its size,
// resulting in sfilenos that are pointing beyond the database.

/* 
 * Rock::DirMap does not implement Ipc::StoreMapCleaner API because we want
 * to avoid extra I/O necessary to mark the disk slot empty. We may create some
 * stale responses if Squid quits, but should save a lot of I/O in the common
 * cases. TODO: Consider cleaning on-disk slots on exit; always scheduling 
 * but cancelling/merging cleanup I/O; scheduling cleanup I/O after a
 * configurable delay; etc.
 */

#endif /* SQUID_FS_ROCK_DIR_MAP_H */
