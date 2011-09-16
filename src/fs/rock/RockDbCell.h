#ifndef SQUID_FS_ROCK_DB_CELL_H
#define SQUID_FS_ROCK_DB_CELL_H

namespace Rock
{

/** \ingroup Rock
 * Meta-information at the beginning of every db cell.
 * Stored on disk and used as sizeof() argument so it must remain POD.
 */
class DbCellHeader
{
public:
    DbCellHeader(): payloadSize(0), reserved(0) {}

    /// whether the freshly loaded header fields make sense
    bool sane() const { return payloadSize >= 0 && reserved == 0; }

    int64_t payloadSize; ///< cell contents size excluding this header
    int64_t reserved; ///< reserved for future use (next cell pointer?)
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_DB_CELL_H */
