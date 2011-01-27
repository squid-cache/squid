#ifndef SQUID_FS_ROCK_IO_STATE_H
#define SQUID_FS_ROCK_IO_STATE_H

#include "MemBuf.h"
#include "SwapDir.h"

class DiskFile;

namespace Rock {

class SwapDir;

/// \ingroup Rock
class IoState: public ::StoreIOState
{
public:
    typedef RefCount<IoState> Pointer;

    IoState(SwapDir *dir, StoreEntry *e, StoreIOState::STFNCB *cbFile, StoreIOState::STIOCB *cbIo, void *data);
    virtual ~IoState();

    void file(const RefCount<DiskFile> &aFile);

    // ::StoreIOState API
    virtual void read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data);
    virtual void write(char const *buf, size_t size, off_t offset, FREE * free_func);
    virtual void close();

    /// called by SwapDir when writing is done
    void finishedWriting(int errFlag);

    int64_t slotSize; ///< db cell size
    int64_t entrySize; ///< planned or actual stored size for the entry

    MEMPROXY_CLASS(IoState);

private:
    void startWriting();
    void callBack(int errflag);

    RefCount<DiskFile> theFile; // "file" responsible for this I/O
    MemBuf theBuf; // use for write content accumulation only
};

MEMPROXY_CLASS_INLINE(IoState);

} // namespace Rock

#endif /* SQUID_FS_ROCK_IO_STATE_H */
