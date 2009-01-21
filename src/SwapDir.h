/*
 * $Id$
 *
 *
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
#ifndef SQUID_SWAPDIR_H
#define SQUID_SWAPDIR_H

#include "Store.h"
#include "StoreIOState.h"

/* forward decls */
class RemovalPolicy;

/* Store dir configuration routines */
/* SwapDir *sd, char *path ( + char *opt later when the strtok mess is gone) */

class ConfigOption;

/* New class that replaces the static SwapDir methods as part of the Store overhaul */

class StoreController : public Store
{

public:
    StoreController();
    virtual ~StoreController();
    virtual int callback();
    virtual void create();

    virtual StoreEntry * get
    (const cache_key *);

    virtual void get
    (String const, STOREGETCLIENT, void * cbdata);

    virtual void init();

    virtual void maintain(); /* perform regular maintenance should be private and self registered ... */

    virtual size_t maxSize() const;

    virtual size_t minSize() const;

    virtual void stat(StoreEntry &) const;

    virtual void sync();	/* Sync the store prior to shutdown */

    virtual StoreSearch *search(String const url, HttpRequest *);

    virtual void reference(StoreEntry &);	/* Reference this object */

    virtual void dereference(StoreEntry &);	/* Unreference this object */

    virtual void updateSize(int64_t size, int sign);

    /* the number of store dirs being rebuilt. */
    static int store_dirs_rebuilding;

private:
    void createOneStore(Store &aStore);

    StorePointer swapDir;
};

/* migrating from the Config based list of swapdirs */
extern void allocate_new_swapdir(SquidConfig::_cacheSwap *);
extern void free_cachedir(SquidConfig::_cacheSwap * swap);
SQUIDCEXTERN OBJH storeDirStats;
SQUIDCEXTERN char *storeDirSwapLogFile(int, const char *);
SQUIDCEXTERN char *storeSwapFullPath(int, char *);
SQUIDCEXTERN char *storeSwapSubSubDir(int, char *);
SQUIDCEXTERN const char *storeSwapPath(int);
SQUIDCEXTERN int storeDirWriteCleanLogs(int reopen);
SQUIDCEXTERN STDIRSELECT *storeDirSelectSwapDir;
SQUIDCEXTERN int storeVerifySwapDirs(void);
SQUIDCEXTERN void storeDirCloseSwapLogs(void);
SQUIDCEXTERN void storeDirCloseTmpSwapLog(int dirn);
SQUIDCEXTERN void storeDirDiskFull(sdirno);
SQUIDCEXTERN void storeDirOpenSwapLogs(void);
SQUIDCEXTERN void storeDirSwapLog(const StoreEntry *, int op);
SQUIDCEXTERN void storeDirLRUDelete(StoreEntry *);
SQUIDCEXTERN void storeDirLRUAdd(StoreEntry *);
SQUIDCEXTERN int storeDirGetBlkSize(const char *path, int *blksize);
SQUIDCEXTERN int storeDirGetUFSStats(const char *, int *, int *, int *, int *);


class SwapDir : public Store
{

public:
    SwapDir(char const *aType) : theType (aType), cur_size (0), max_size(0), max_objsize (-1), cleanLog(NULL) {
        fs.blksize = 1024;
        path = NULL;
    }

    virtual ~SwapDir();
    virtual void reconfigure(int, char *) = 0;
    char const *type() const;

    /* official Store interface functions */
    virtual void diskFull();

    virtual StoreEntry * get
    (const cache_key *);

    virtual void get
    (String const, STOREGETCLIENT, void * cbdata);

    virtual size_t maxSize() const { return max_size;}

    virtual size_t minSize() const;
    virtual void stat (StoreEntry &anEntry) const;
    virtual StoreSearch *search(String const url, HttpRequest *) = 0;

    virtual void updateSize(int64_t size, int sign);

    /* migrated from store_dir.cc */
    bool objectSizeIsAcceptable(int64_t objsize) const;

protected:
    void parseOptions(int reconfiguring);
    void dumpOptions(StoreEntry * e) const;
    virtual ConfigOption *getOptionTree() const;

private:
    bool optionReadOnlyParse(char const *option, const char *value, int reconfiguring);
    void optionReadOnlyDump(StoreEntry * e) const;
    bool optionMaxSizeParse(char const *option, const char *value, int reconfiguring);
    void optionMaxSizeDump(StoreEntry * e) const;
    char const *theType;

public:
    int cur_size;
    int max_size;
    char *path;
    int index;			/* This entry's index into the swapDirs array */
    int64_t max_objsize;
    RemovalPolicy *repl;
    int removals;
    int scanned;

    struct Flags {
        Flags() : selected(0), read_only(0) {}
        unsigned int selected:1;
        unsigned int read_only:1;
    } flags;
    virtual void init() = 0;	/* Initialise the fs */
    virtual void create();	/* Create a new fs */
    virtual void dump(StoreEntry &)const;	/* Dump fs config snippet */
    virtual bool doubleCheck(StoreEntry &);	/* Double check the obj integrity */
    virtual void statfs(StoreEntry &) const;	/* Dump fs statistics */
    virtual void maintain();	/* Replacement maintainence */
    /* <0 == error. > 1000 == error */
    virtual int canStore(StoreEntry const &)const = 0; /* Check if the fs will store an object */
    /* These two are notifications */
    virtual void reference(StoreEntry &);	/* Reference this object */
    virtual void dereference(StoreEntry &);	/* Unreference this object */
    virtual int callback();	/* Handle pending callbacks */
    virtual void sync();	/* Sync the store prior to shutdown */
    virtual StoreIOState::Pointer createStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *) = 0;
    virtual StoreIOState::Pointer openStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *) = 0;
    virtual void unlink (StoreEntry &);
    bool canLog(StoreEntry const &e)const;
    virtual void openLog();
    virtual void closeLog();
    virtual void logEntry(const StoreEntry & e, int op) const;

    class CleanLog
    {

    public:
        virtual ~CleanLog() {}

        virtual const StoreEntry *nextEntry() = 0;
        virtual void write(StoreEntry const &) = 0;
    };

    CleanLog *cleanLog;
    virtual int writeCleanStart();
    virtual void writeCleanDone();
    virtual void parse(int index, char *path) = 0;

    struct {
        int blksize;
    } fs;
};

#endif /* SQUID_SWAPDIR_H */
