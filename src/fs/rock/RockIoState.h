#ifndef SQUID_FS_ROCK_IO_STATE_H
#define SQUID_FS_ROCK_IO_STATE_H

#include "MemBuf.h"
#include "SwapDir.h"

class DiskFile;

namespace Rock
{

class DbCellHeader;
class SwapDir;

/// \ingroup Rock
class IoState: public ::StoreIOState
{
public:
    typedef RefCount<IoState> Pointer;

    IoState(SwapDir &aDir, StoreEntry *e, StoreIOState::STFNCB *cbFile, StoreIOState::STIOCB *cbIo, void *data);
    virtual ~IoState();

    void file(const RefCount<DiskFile> &aFile);

    // ::StoreIOState API
    virtual void read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data);
    virtual void write(char const *buf, size_t size, off_t offset, FREE * free_func);
    virtual void close(int how);

    void finishedWriting(int errFlag);

    int64_t diskOffset; ///< the start of this cell inside the db file
    DbCellHeader *dbSlot; ///< current db slot, used for writing

    MEMPROXY_CLASS(IoState);

private:
    void doWrite(const bool isLast = false);
    void callBack(int errflag);

    SwapDir &dir; ///< swap dir object
    const size_t slotSize; ///< db cell size
    int64_t objOffset; ///< object offset for current db slot

    RefCount<DiskFile> theFile; // "file" responsible for this I/O
    MemBuf theBuf; // use for write content accumulation only
};

MEMPROXY_CLASS_INLINE(IoState);

} // namespace Rock

#endif /* SQUID_FS_ROCK_IO_STATE_H */
