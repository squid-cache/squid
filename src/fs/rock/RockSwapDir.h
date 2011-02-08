#ifndef SQUID_FS_ROCK_SWAP_DIR_H
#define SQUID_FS_ROCK_SWAP_DIR_H

#include "SwapDir.h"
#include "DiskIO/IORequestor.h"
#include "fs/rock/RockDirMap.h"

class DiskIOStrategy;
class DiskFile;
class ReadRequest;
class WriteRequest;

namespace Rock {

class Rebuild;

/// \ingroup Rock
class SwapDir: public ::SwapDir, public IORequestor
{
public:
    SwapDir();
    virtual ~SwapDir();

    /* public ::SwapDir API */
    virtual void reconfigure(int, char *);
    virtual StoreSearch *search(String const url, HttpRequest *);
    virtual StoreEntry *get(const cache_key *key);
    virtual void disconnect(StoreEntry &e);

protected:
    /* protected ::SwapDir API */
    virtual bool needsDiskStrand() const;
    virtual void create();
    virtual void init();
    virtual int canStore(StoreEntry const &) const;
    virtual StoreIOState::Pointer createStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
    virtual StoreIOState::Pointer openStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
    virtual void maintain();
    virtual void updateSize(int64_t size, int sign);
    virtual void diskFull();
    virtual void reference(StoreEntry &e);
    virtual void dereference(StoreEntry &e);
    virtual void unlink(StoreEntry &e);
    virtual void statfs(StoreEntry &e) const;

    /* IORequestor API */
    virtual void ioCompletedNotification();
    virtual void closeCompleted();
    virtual void readCompleted(const char *buf, int len, int errflag, RefCount< ::ReadRequest>);
    virtual void writeCompleted(int errflag, size_t len, RefCount< ::WriteRequest>);

    virtual void parse(int index, char *path);
    void parseSize(); ///< parses anonymous cache_dir size option
    void validateOptions(); ///< warns of configuration problems; may quit

    void rebuild(); ///< starts loading and validating stored entry metadata
    ///< used to add entries successfully loaded during rebuild
    bool addEntry(const int fileno, const StoreEntry &from);

    bool full() const; ///< no more entries can be stored without purging
    void trackReferences(StoreEntry &e); ///< add to replacement policy scope
    void ignoreReferences(StoreEntry &e); ///< delete from repl policy scope

    // TODO: change cur_size and max_size type to stop this madness
    int64_t currentSize() const { return static_cast<int64_t>(cur_size) << 10;}
    int64_t maximumSize() const { return static_cast<int64_t>(max_size) << 10;}
    int64_t diskOffset(int filen) const;
    int64_t diskOffsetLimit() const;
    int entryLimit() const { return map->entryLimit(); }

    friend class Rebuild;
    const char *filePath; ///< location of cache storage file inside path/

private:
    DiskIOStrategy *io;
    RefCount<DiskFile> theFile; ///< cache storage for this cache_dir
    DirMap *map;

    static const int64_t HeaderSize; ///< on-disk db header size
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_SWAP_DIR_H */
