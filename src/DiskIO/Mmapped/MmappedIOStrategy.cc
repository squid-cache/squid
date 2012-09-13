/*
 * DEBUG: section 47    Store Directory Routines
 */

#include "squid.h"
#include "MmappedFile.h"
#include "MmappedIOStrategy.h"
#include "unlinkd.h"

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

bool
MmappedIOStrategy::unlinkdUseful() const
{
    return true;
}

void
MmappedIOStrategy::unlinkFile(char const *path)
{
    unlinkdUnlink(path);
}
