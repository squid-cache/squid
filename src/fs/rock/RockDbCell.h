/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FS_ROCK_DB_CELL_H
#define SQUID_FS_ROCK_DB_CELL_H

#include "typedefs.h"

namespace Rock
{

/** \ingroup Rock
 * Meta-information at the beginning of every db cell.
 * Links multiple map slots belonging to the same entry into an entry chain.
 * Stored on disk and used as sizeof() argument so it must remain POD.
 */
class DbCellHeader
{
public:
    DbCellHeader();

    /// true iff no entry occupies this slot
    bool empty() const { return !firstSlot && !nextSlot && !payloadSize; }

    /* members below are not meaningful if empty() */

    /// whether this slot is not corrupted
    bool sane(const size_t slotSize, int slotLimit) const {
        return
            0 <= firstSlot && firstSlot < slotLimit &&
            -1 <= nextSlot && nextSlot < slotLimit &&
            version > 0 &&
            0 < payloadSize && payloadSize <= slotSize - sizeof(DbCellHeader);
    }

    uint64_t key[2]; ///< StoreEntry key
    uint64_t entrySize; ///< total entry content size or zero if still unknown
    uint32_t payloadSize; ///< slot contents size, always positive
    uint32_t version;  ///< detects conflicts among same-key entries
    sfileno firstSlot; ///< slot ID of the first slot occupied by the entry
    sfileno nextSlot; ///< slot ID of the next slot occupied by the entry
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_DB_CELL_H */

