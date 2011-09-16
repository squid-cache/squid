
/*
 * $Id$
 *
 * DEBUG: section 47    Store Directory Routines
 */

#include "config.h"
#include "MmappedFile.h"
#include "MmappedIOStrategy.h"

bool
MmappedIOStrategy::shedLoad()
{
    return false;
}

int
MmappedIOStrategy::load()
{
    /* Return 999 (99.9%) constant load */
    return 999;
}

DiskFile::Pointer
MmappedIOStrategy::newFile (char const *path)
{
    return new MmappedFile (path);
}

void
MmappedIOStrategy::unlinkFile(char const *path)
{
#if USE_UNLINKD
    unlinkdUnlink(path);
#else
    ::unlink(path);
#endif
}
