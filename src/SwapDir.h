
/*
 * $Id: SwapDir.h,v 1.1 2002/12/27 10:26:33 robertc Exp $
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

#include "StoreIOState.h"

/* Store dir configuration routines */
/* SwapDir *sd, char *path ( + char *opt later when the strtok mess is gone) */
typedef void STFSSTARTUP(void);
typedef void STFSSHUTDOWN(void);
typedef SwapDir *STFSNEW(void);
struct SwapDir {
public:
    static SwapDir *Factory (_storefs_entry const &fs);
    SwapDir() : max_objsize (-1){
	fs.blksize = 1024;
    }
    virtual ~SwapDir();
    virtual void reconfigure(int, char *) = 0;
    const char *type;
    int cur_size;
    int low_size;
    int max_size;
    char *path;
    int index;			/* This entry's index into the swapDirs array */
    ssize_t max_objsize;
    RemovalPolicy *repl;
    int removals;
    int scanned;
    struct {
	unsigned int selected:1;
	unsigned int read_only:1;
    } flags;
    virtual void init() = 0;	/* Initialise the fs */
    virtual void newFileSystem();	/* Create a new fs */
    virtual void dump(StoreEntry &)const;	/* Dump fs config snippet */
    virtual bool doubleCheck(StoreEntry &);	/* Double check the obj integrity */
    virtual void statfs(StoreEntry &) const;	/* Dump fs statistics */
    virtual void maintainfs();	/* Replacement maintainence */
    /* <0 == error. > 1000 == error */
    virtual int canStore(StoreEntry const &)const = 0; /* Check if the fs will store an object */
    /* These two are notifications */
    virtual void reference(StoreEntry &);	/* Reference this object */
    virtual void dereference(StoreEntry &);	/* Unreference this object */
    virtual int callback();	/* Handle pending callbacks */
    virtual void sync();	/* Sync the store prior to shutdown */
    virtual StoreIOState::Pointer createStoreIO(StoreEntry &, STFNCB *, STIOCB *, void *) = 0;
    virtual StoreIOState::Pointer openStoreIO(StoreEntry &, STFNCB *, STIOCB *, void *) = 0;
    virtual void unlink (StoreEntry &);
    bool canLog(StoreEntry const &e)const;
    virtual void openLog();
    virtual void closeLog();
    virtual void logEntry(const StoreEntry & e, int op) const;
    class CleanLog {
      public:
	virtual ~CleanLog(){}
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
