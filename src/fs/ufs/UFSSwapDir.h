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
 */

#ifndef SQUID_FS_UFS_UFSSWAPDIR_H
#define SQUID_FS_UFS_UFSSWAPDIR_H

#include "SquidString.h"
#include "Store.h"
#include "StoreIOState.h"
#include "StoreSearch.h"
#include "SwapDir.h"
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
    /** Initial setup / end destruction */
    virtual void init();
    /** Create a new SwapDir (-z command-line option) */
    virtual void create();
    virtual void dump(StoreEntry &) const;
    ~UFSSwapDir();
    virtual StoreSearch *search(String const url, HttpRequest *);
    /** double-check swap during rebuild (-S command-line option)
     *
     * called by storeCleanup if needed
     */
    virtual bool doubleCheck(StoreEntry &);
    virtual bool unlinkdUseful() const;
    /** unlink a file, and remove its entry from the filemap */
    virtual void unlink(StoreEntry &);
    virtual void statfs(StoreEntry &)const;
    virtual void maintain();
    /** check whether this filesystem can store the given object
     *
     * UFS filesystems will happily store anything as long as
     * the LRU time isn't too small
     */
    virtual bool canStore(const StoreEntry &e, int64_t diskSpaceNeeded, int &load) const;
    /** reference an object
     *
     * This routine is called whenever an object is referenced, so we can
     * maintain replacement information within the storage fs.
     */
    virtual void reference(StoreEntry &);
    /** de-reference an object
     *
     * This routine is called whenever the last reference to an object is
     * removed, to maintain replacement information within the storage fs.
     */
    virtual bool dereference(StoreEntry &, bool);
    virtual StoreIOState::Pointer createStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
    virtual StoreIOState::Pointer openStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
    virtual void openLog();
    virtual void closeLog();
    virtual int writeCleanStart();
    virtual void writeCleanDone();
    virtual void logEntry(const StoreEntry & e, int op) const;
    virtual void parse(int index, char *path); ///parse configuration and setup new SwapDir
    virtual void reconfigure(); ///reconfigure the SwapDir
    virtual int callback();
    virtual void sync();
    virtual void swappedOut(const StoreEntry &e);
    virtual uint64_t currentSize() const { return cur_size; }
    virtual uint64_t currentCount() const { return n_disk_objects; }

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
    /// Undo the effects of UFSSwapDir::addDiskRestore().
    void undoAddDiskRestore(StoreEntry *e);
    int validFileno(sfileno filn, int flag) const;
    int mapBitAllocate();
    virtual ConfigOption *getOptionTree() const;

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
    char *logFile(char const *ext = NULL)const;
    void changeIO(DiskIOModule *);
    bool optionIOParse(char const *option, const char *value, int reconfiguring);
    void optionIODump(StoreEntry * e) const;
    mutable ConfigOptionVector *currentIOOptions;
    char const *ioType;
    uint64_t cur_size; ///< currently used space in the storage area
    uint64_t n_disk_objects; ///< total number of objects stored
};

} //namespace Ufs
} //namespace Fs
#endif /* SQUID_FS_UFS_UFSSWAPDIR_H */
