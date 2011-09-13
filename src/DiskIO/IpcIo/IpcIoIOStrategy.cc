
/*
 * $Id$
 *
 * DEBUG: section 47    Store Directory Routines
 */

#include "config.h"
#include "IpcIoFile.h"
#include "IpcIoIOStrategy.h"

bool
IpcIoIOStrategy::shedLoad()
{
    return false;
}

int
IpcIoIOStrategy::load()
{
    /* Return 999 (99.9%) constant load */
    return 999;
}

DiskFile::Pointer
IpcIoIOStrategy::newFile (char const *path)
{
    return new IpcIoFile (path);
}

void
IpcIoIOStrategy::unlinkFile(char const *path)
{
#if USE_UNLINKD
    unlinkdUnlink(path);
#else
    ::unlink(path);
#endif
}
