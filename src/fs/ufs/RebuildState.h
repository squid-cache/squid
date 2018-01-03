/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FS_UFS_REBUILDSTATE_H
#define SQUID_FS_UFS_REBUILDSTATE_H

#include "base/RefCount.h"
#include "store_rebuild.h"
#include "UFSSwapDir.h"
#include "UFSSwapLogParser.h"

class StoreEntry;

namespace Fs
{
namespace Ufs
{

class RebuildState
{
    CBDATA_CLASS(RebuildState);

public:
    static EVH RebuildStep;

    RebuildState(RefCount<UFSSwapDir> sd);
    virtual ~RebuildState();

    virtual bool error() const;
    virtual bool isDone() const;
    virtual StoreEntry *currentItem();

    RefCount<UFSSwapDir> sd;
    int n_read;
    /*    FILE *log;*/
    Fs::Ufs::UFSSwapLogParser *LogParser;
    int curlvl1;
    int curlvl2;

    struct Flags {
        Flags() : need_to_validate(false), clean(false), init(false) {}
        bool need_to_validate;
        bool clean;
        bool init;
    } flags;
    int in_dir;
    int done;
    int fn;

    dirent_t *entry;
    DIR *td;
    char fullpath[MAXPATHLEN];
    char fullfilename[MAXPATHLEN*2];

    StoreRebuildData counts;

private:
    void rebuildFromDirectory();
    void rebuildFromSwapLog();
    void rebuildStep();
    void undoAdd();
    int getNextFile(sfileno *, int *size);
    StoreEntry *currentEntry() const;
    void currentEntry(StoreEntry *);
    StoreEntry *e;
    bool fromLog;
    bool _done;
    /// \bug (callback) should be hidden behind a proper human readable name
    void (callback)(void *cbdata);
    void *cbdata;
};

} /* namespace Ufs */
} /* namespace Fs */

#endif /* SQUID_FS_UFS_REBUILDSTATE_H */

