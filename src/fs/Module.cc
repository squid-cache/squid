#include "squid.h"
#include "Module.h"
#if defined(HAVE_FS_UFS) || defined(HAVE_FS_AUFS) || defined(HAVE_FS_DISKD)
#include "fs/ufs/StoreFSufs.h"
#include "fs/ufs/ufscommon.h"
#endif

#ifdef HAVE_FS_COSS
#include "fs/coss/StoreFScoss.h"
#endif

#ifdef HAVE_FS_UFS
static StoreFSufs<UFSSwapDir> *UfsInstance;
#endif

#ifdef HAVE_FS_AUFS
static StoreFSufs<UFSSwapDir> *AufsInstance;
#endif


#ifdef HAVE_FS_DISKD
static StoreFSufs<UFSSwapDir> *DiskdInstance;
#endif

/* TODO: Modify coss code to:
 * (a) remove the StoreFScoss::GetInstance method,
 * (b) declare the StoreFScoss::stats  as static and
 * (c) merge the StoreFScoss::stat() method with the static
 *     StoreFScoss::Stats() */
#ifdef HAVE_FS_COSS
StoreFScoss &CossInstance = StoreFScoss::GetInstance();
#endif


void Fs::Init()
{

#ifdef HAVE_FS_UFS
    UfsInstance = new StoreFSufs<UFSSwapDir>("Blocking", "ufs");
#endif

#ifdef HAVE_FS_AUFS
    AufsInstance = new StoreFSufs<UFSSwapDir>("DiskThreads", "aufs");;
#endif


#ifdef HAVE_FS_DISKD
    DiskdInstance = new StoreFSufs<UFSSwapDir>("DiskDaemon", "diskd");;
#endif

}


void Fs::Clean()
{
#ifdef HAVE_FS_UFS
    delete UfsInstance;
#endif

#ifdef HAVE_FS_AUFS
    delete AufsInstance;
#endif


#ifdef HAVE_FS_DISKD
    delete DiskdInstance;
#endif

}
