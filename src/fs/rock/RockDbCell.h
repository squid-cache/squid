#ifndef SQUID_FS_ROCK_DB_CELL_H
#define SQUID_FS_ROCK_DB_CELL_H

namespace Ipc
{
class StoreMapSlot;
}

namespace Rock
{

/** \ingroup Rock
 * Meta-information at the beginning of every db cell.
 * Stored on disk and used as sizeof() argument so it must remain POD.
 */
class DbCellHeader
{
public:
    DbCellHeader();

    /// whether the freshly loaded header fields make sense
    bool sane() const;

    uint64_t key[2]; ///< StoreEntry key
    uint32_t firstSlot; ///< first slot pointer in the entry chain
    uint32_t nextSlot; ///< next slot pointer in the entry chain
    uint32_t version; ///< entry chain version
    uint32_t payloadSize; ///< cell contents size excluding this header
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_DB_CELL_H */
