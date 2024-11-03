/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_FS_UFS_UFSSWAPDIR_H
#define SQUID_SRC_FS_UFS_UFSSWAPDIR_H

#include "SquidString.h"
#include "Store.h"
#include "store/Disk.h"
#include "StoreIOState.h"
#include "StoreSearch.h"
#include "swap_log_op.h"
#include "UFSStrategy.h"

class HttpRequest;
class ConfigOptionVector;
class FileMap;
class DiskIOModule;

namespace Fs
{
namespace Ufs
{
/// \ingroup UFS
class UFSSwapDir : public SwapDir
{
public:
    static bool IsUFSDir(SwapDir* sd);
    static int DirClean(int swap_index);
    /** check whether swapfile belongs to the specified cachedir/l1dir/l2dir
     *
     * \param cachedir the number of the cachedir which is being tested
     * \param level1dir level-1 dir in the cachedir
     * \param level2dir level-2 dir
     */
    static bool FilenoBelongsHere(int fn, int cachedir, int level1dir, int level2dir);

    UFSSwapDir(char const *aType, const char *aModuleType);
    ~UFSSwapDir() override;

    /* Store::Disk API */
    void create() override;
    void init() override;
    void dump(StoreEntry &) const override;
    bool doubleCheck(StoreEntry &) override;
    bool unlinkdUseful() const override;
    void statfs(StoreEntry &) const override;
    void maintain() override;
    void evictCached(StoreEntry &) override;
    void evictIfFound(const cache_key *) override;
    bool canStore(const StoreEntry &e, int64_t diskSpaceNeeded, int &load) const override;
    void reference(StoreEntry &) override;
    bool dereference(StoreEntry &) override;
    StoreIOState::Pointer createStoreIO(StoreEntry &, StoreIOState::STIOCB *, void *) override;
    StoreIOState::Pointer openStoreIO(StoreEntry &, StoreIOState::STIOCB *, void *) override;
    void openLog() override;
    void closeLog() override;
    int writeCleanStart() override;
    void writeCleanDone() override;
    void logEntry(const StoreEntry & e, int op) const override;
    void parse(int index, char *path) override;
    void reconfigure() override;
    int callback() override;
    void sync() override;
    void finalizeSwapoutSuccess(const StoreEntry &) override;
    void finalizeSwapoutFailure(StoreEntry &) override;
    uint64_t currentSize() const override { return cur_size; }
    uint64_t currentCount() const override { return n_disk_objects; }
    ConfigOption *getOptionTree() const override;
    bool smpAware() const override { return false; }
    /// as long as ufs relies on the global store_table to index entries,
    /// it is wrong to ask individual ufs cache_dirs whether they have an entry
    bool hasReadableEntry(const StoreEntry &) const override { return false; }

    void unlinkFile(sfileno f);
    // move down when unlink is a virtual method
    //protected:
    Fs::Ufs::UFSStrategy *IO;
    char *fullPath(sfileno, char *) const;
    /* temp */
    void closeTmpSwapLog();
    FILE *openTmpSwapLog(int *clean_flag, int *zero_flag);
    char *swapSubDir(int subdirn) const;
    int mapBitTest(sfileno filn);
    void mapBitReset(sfileno filn);
    void mapBitSet(sfileno filn);
    /** Add a new object to the cache with empty memory copy and pointer to disk
     *
     * This method is used to rebuild a store from disk
     */
    StoreEntry *addDiskRestore(const cache_key * key,
                               sfileno file_number,
                               uint64_t swap_file_sz,
                               time_t expires,
                               time_t timestamp,
                               time_t lastref,
                               time_t lastmod,
                               uint32_t refcount,
                               uint16_t flags,
                               int clean);
    int validFileno(sfileno filn, int flag) const;
    int mapBitAllocate();

    void *fsdata;

    bool validL2(int) const;
    bool validL1(int) const;

    /** Add and remove the given StoreEntry from the replacement policy in use */
    void replacementAdd(StoreEntry *e);
    void replacementRemove(StoreEntry *e);

protected:
    FileMap *map;
    int suggest;
    int l1;
    int l2;

private:
    void parseSizeL1L2();
    static int NumberOfUFSDirs;
    static int * UFSDirToGlobalDirMapping;
    bool pathIsDirectory(const char *path)const;
    int swaplog_fd;
    static EVH CleanEvent;
    static int HandleCleanEvent();
    /** Verify that the the CacheDir exists
     *
     * If this returns < 0, then Squid exits, complains about swap
     * directories not existing, and instructs the admin to run 'squid -z'
     * Called by UFSSwapDir::init
     */
    bool verifyCacheDirs();
    void rebuild();
    int createDirectory(const char *path, int);
    void createSwapSubDirs();
    void dumpEntry(StoreEntry &) const;
    SBuf logFile(char const *ext = nullptr) const;
    void changeIO(DiskIOModule *);
    bool optionIOParse(char const *option, const char *value, int reconfiguring);
    void optionIODump(StoreEntry * e) const;
    mutable ConfigOptionVector *currentIOOptions;
    char const *ioType;
    uint64_t cur_size; ///< currently used space in the storage area
    uint64_t n_disk_objects; ///< total number of objects stored
    bool rebuilding_; ///< whether RebuildState is writing the new swap.state
};

} //namespace Ufs
} //namespace Fs
#endif /* SQUID_SRC_FS_UFS_UFSSWAPDIR_H */

