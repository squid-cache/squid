#ifndef SQUID_FS_ROCK_REBUILD_H
#define SQUID_FS_ROCK_REBUILD_H

#include "base/AsyncJob.h"
#include "cbdata.h"
#include "store_rebuild.h"

namespace Ipc
{
namespace Mem
{
class PageId;
}
}

namespace Rock
{

class SwapDir;

/// \ingroup Rock
/// manages store rebuild process: loading meta information from db on disk
class Rebuild: public AsyncJob
{
public:
    Rebuild(SwapDir *dir);
    ~Rebuild();

protected:
    /* AsyncJob API */
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();

private:
    void checkpoint();
    void steps();
    void steps2();
    void doOneEntry();
    void doOneSlot();
    void failure(const char *msg, int errNo = 0);
    void invalidSlot(Ipc::Mem::PageId &pageId);

    SwapDir *sd;

    int64_t dbSize;
    int dbEntrySize;
    int dbEntryLimit;
    int dbSlot;

    int fd; // store db file descriptor
    int64_t dbOffset;
    int filen;

    // TODO: use std::bitmap?
    Vector<bool> processed; ///< true iff rebuilt is complete for a given slot

    StoreRebuildData counts;

    static void Steps(void *data);
    static void Steps2(void *data);

    CBDATA_CLASS2(Rebuild);
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_REBUILD_H */
