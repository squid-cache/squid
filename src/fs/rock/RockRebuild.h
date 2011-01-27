#ifndef SQUID_FS_ROCK_REBUILD_H
#define SQUID_FS_ROCK_REBUILD_H

#include "config.h"
#include "structs.h"

namespace Rock {

class SwapDir;

/// \ingroup Rock
/// manages store rebuild process: loading meta information from db on disk
class Rebuild {
public:
    Rebuild(SwapDir *dir);
    ~Rebuild();
    void start();

private:
    CBDATA_CLASS2(Rebuild);

    void checkpoint();
    void steps();
    void doOneEntry();
    void complete();
    void failure(const char *msg, int errNo = 0);

    SwapDir *sd;

    int64_t dbSize;
    int dbEntrySize;
    int dbEntryLimit;

    int fd; // store db file descriptor
    int64_t dbOffset;
    int fileno;

    struct _store_rebuild_data counts;

    static void Steps(void *data);
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_REBUILD_H */
