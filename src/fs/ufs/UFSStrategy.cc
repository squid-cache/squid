/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 47    Store Directory Routines */

#include "squid.h"

#include "base/IoManip.h"
#include "DiskIO/DiskIOStrategy.h"
#include "UFSStoreState.h"
#include "UFSStrategy.h"
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
Fs::Ufs::UFSStrategy::open(SwapDir * const SD, StoreEntry * const e,
                           StoreIOState::STIOCB * aCallback, void *callback_data)
{
    assert (((UFSSwapDir *)SD)->IO == this);
    debugs(79, 3, "fileno " << asHex(e->swap_filen).upperCase().minDigits(8));

    /* to consider: make createstate a private UFSStrategy call */
    StoreIOState::Pointer sio = createState (SD, e, aCallback, callback_data);

    sio->mode |= O_RDONLY;

    Fs::Ufs::UFSStoreState *state = dynamic_cast <Fs::Ufs::UFSStoreState *>(sio.getRaw());

    assert (state);

    char *path = ((UFSSwapDir *)SD)->fullPath(e->swap_filen, nullptr);

    DiskFile::Pointer myFile = newFile (path);

    if (myFile.getRaw() == nullptr)
        return nullptr;

    state->theFile = myFile;

    state->opening = true;

    myFile->open (sio->mode, 0644, state);

    if (myFile->error())
        return nullptr;

    return sio;
}

StoreIOState::Pointer
Fs::Ufs::UFSStrategy::create(SwapDir * const SD, StoreEntry * const e,
                             StoreIOState::STIOCB * aCallback, void *callback_data)
{
    assert (((UFSSwapDir *)SD)->IO == this);
    /* Allocate a number */
    sfileno filn = ((UFSSwapDir *)SD)->mapBitAllocate();
    debugs(79, 3, "fileno " << asHex(filn).upperCase().minDigits(8));

    /* Shouldn't we handle a 'bitmap full' error here? */

    StoreIOState::Pointer sio = createState (SD, e, aCallback, callback_data);

    sio->mode |= O_WRONLY | O_CREAT | O_TRUNC;

    sio->swap_filen = filn;

    Fs::Ufs::UFSStoreState *state = dynamic_cast <Fs::Ufs::UFSStoreState *>(sio.getRaw());

    assert (state);

    char *path = ((UFSSwapDir *)SD)->fullPath(filn, nullptr);

    DiskFile::Pointer myFile = newFile (path);

    if (myFile.getRaw() == nullptr) {
        ((UFSSwapDir *)SD)->mapBitReset (filn);
        return nullptr;
    }

    state->theFile = myFile;

    state->creating = true;

    myFile->create (state->mode, 0644, state);

    if (myFile->error()) {
        ((UFSSwapDir *)SD)->mapBitReset (filn);
        return nullptr;
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

