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

#endif /* SQUID_FS_ROCK_DIR_MAP_H */
