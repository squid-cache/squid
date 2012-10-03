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
 *
 */

#ifndef SQUID_FS_UFS_REBUILDSTATE_H
#define SQUID_FS_UFS_REBUILDSTATE_H

#include "RefCount.h"
#include "UFSSwapDir.h"
#include "UFSSwapLogParser.h"
#include "store_rebuild.h"

class StoreEntry;

namespace Fs
{
namespace Ufs
{

/// \ingroup UFS
class RebuildState : public RefCountable
{
public:
    static EVH RebuildStep;

    RebuildState(RefCount<UFSSwapDir> sd);
    ~RebuildState();

    virtual bool error() const;
    virtual bool isDone() const;
    virtual StoreEntry *currentItem();

    RefCount<UFSSwapDir> sd;
    int n_read;
    /*    FILE *log;*/
    Fs::Ufs::UFSSwapLogParser *LogParser;
    int curlvl1;
    int curlvl2;

    struct {
        unsigned int need_to_validate:1;
        unsigned int clean:1;
        unsigned int init:1;
    } flags;
    int in_dir;
    int done;
    int fn;

    dirent_t *entry;
    DIR *td;
    char fullpath[MAXPATHLEN];
    char fullfilename[MAXPATHLEN];

    StoreRebuildData counts;

private:
    CBDATA_CLASS2(RebuildState);
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
