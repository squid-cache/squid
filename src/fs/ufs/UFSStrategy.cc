/*
 * DEBUG: section 47    Store Directory Routines
 * AUTHOR: Robert Collins
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
 */

#include "squid.h"

#include "DiskIO/DiskIOStrategy.h"
#include "UFSStrategy.h"
#include "UFSStoreState.h"
#include "UFSSwapDir.h"

bool
Fs::Ufs::UFSStrategy::shedLoad()
{
    return io->shedLoad();
}

int
Fs::Ufs::UFSStrategy::load()
{
    return io->load();
}

Fs::Ufs::UFSStrategy::UFSStrategy (DiskIOStrategy *anIO) : io(anIO)
{}

Fs::Ufs::UFSStrategy::~UFSStrategy ()
{
    delete io;
}

StoreIOState::Pointer
Fs::Ufs::UFSStrategy::createState(SwapDir *SD, StoreEntry *e, StoreIOState::STIOCB * aCallback, void *callback_data) const
{
    return new Fs::Ufs::UFSStoreState (SD, e, aCallback, callback_data);
}

DiskFile::Pointer
Fs::Ufs::UFSStrategy::newFile (char const *path)
{
    return io->newFile(path);
}

void
Fs::Ufs::UFSStrategy::unlinkFile(char const *path)
{
    io->unlinkFile(path);
}

StoreIOState::Pointer
Fs::Ufs::UFSStrategy::open(SwapDir * SD, StoreEntry * e, StoreIOState::STFNCB * file_callback,
                           StoreIOState::STIOCB * aCallback, void *callback_data)
{
    assert (((UFSSwapDir *)SD)->IO == this);
    debugs(79, 3, HERE << "fileno "<< std::setfill('0') << std::hex
           << std::uppercase << std::setw(8) << e->swap_filen);

    /* to consider: make createstate a private UFSStrategy call */
    StoreIOState::Pointer sio = createState (SD, e, aCallback, callback_data);

    sio->mode |= O_RDONLY;

    Fs::Ufs::UFSStoreState *state = dynamic_cast <Fs::Ufs::UFSStoreState *>(sio.getRaw());

    assert (state);

    char *path = ((UFSSwapDir *)SD)->fullPath(e->swap_filen, NULL);

    DiskFile::Pointer myFile = newFile (path);

    if (myFile.getRaw() == NULL)
        return NULL;

    state->theFile = myFile;

    state->opening = true;

    myFile->open (sio->mode, 0644, state);

    if (myFile->error())
        return NULL;

    return sio;
}

StoreIOState::Pointer
Fs::Ufs::UFSStrategy::create(SwapDir * SD, StoreEntry * e, StoreIOState::STFNCB * file_callback,
                             StoreIOState::STIOCB * aCallback, void *callback_data)
{
    assert (((UFSSwapDir *)SD)->IO == this);
    /* Allocate a number */
    sfileno filn = ((UFSSwapDir *)SD)->mapBitAllocate();
    debugs(79, 3, HERE << "fileno "<< std::setfill('0') <<
           std::hex << std::uppercase << std::setw(8) << filn);

    /* Shouldn't we handle a 'bitmap full' error here? */

    StoreIOState::Pointer sio = createState (SD, e, aCallback, callback_data);

    sio->mode |= O_WRONLY | O_CREAT | O_TRUNC;

    sio->swap_filen = filn;

    Fs::Ufs::UFSStoreState *state = dynamic_cast <Fs::Ufs::UFSStoreState *>(sio.getRaw());

    assert (state);

    char *path = ((UFSSwapDir *)SD)->fullPath(filn, NULL);

    DiskFile::Pointer myFile = newFile (path);

    if (myFile.getRaw() == NULL) {
        ((UFSSwapDir *)SD)->mapBitReset (filn);
        return NULL;
    }

    state->theFile = myFile;

    state->creating = true;

    myFile->create (state->mode, 0644, state);

    if (myFile->error()) {
        ((UFSSwapDir *)SD)->mapBitReset (filn);
        return NULL;
    }

    /* now insert into the replacement policy */
    ((UFSSwapDir *)SD)->replacementAdd(e);

    return sio;
}

int
Fs::Ufs::UFSStrategy::callback()
{
    return io->callback();
}

void
Fs::Ufs::UFSStrategy::init()
{
    io->init();
}

void
Fs::Ufs::UFSStrategy::sync()
{
    io->sync();
}

void
Fs::Ufs::UFSStrategy::statfs(StoreEntry & sentry)const
{
    io->statfs(sentry);
}
