/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/statvfs.h"

#if !HAVE_STATVFS

// struct statfs has some member differences between OS versions
#if HAVE_F_FRSIZE_IN_STATFS
#define STATFS_FRSIZE(x) (x).f_frsize
#else
#define STATFS_FRSIZE(x) (x).f_bsize
#endif

int
xstatvfs(const char *path, struct statvfs *sfs)
{
#if !HAVE_STATFS && _SQUID_WINDOWS_
    char drive[4];
    DWORD spc, bps, freec, totalc;
    DWORD vsn, maxlen, flags;

    if (!sfs) {
        errno = EINVAL;
        return -1;
    }
    strncpy(drive, path, 2);
    drive[2] = '\0';
    strcat(drive, "\\");

    if (!GetDiskFreeSpace(drive, &spc, &bps, &freec, &totalc)) {
        errno = ENOENT;
        return -1;
    }
    if (!GetVolumeInformation(drive, NULL, 0, &vsn, &maxlen, &flags, NULL, 0)) {
        errno = ENOENT;
        return -1;
    }

    memset(sfs, 0, sizeof(*sfs));

    sfs->f_bsize = sfs->f_frsize = spc * bps;         /* file system block size, fragment size */
    sfs->f_blocks = totalc;                           /* size of fs in f_frsize units */
    sfs->f_bfree = sfs->f_bavail = freec;             /* # free blocks total, and available for unprivileged users */
    sfs->f_files = sfs->f_ffree = sfs->f_favail = -1; /* # inodes total, free, and available for unprivileged users */
    sfs->f_fsid = vsn;                                /* file system ID */
    sfs->f_namemax = maxlen;                          /* maximum filename length */
    return 0;

#elif HAVE_STATFS
    // use statfs() and map results from struct statfs to struct statvfs
    struct statfs tmpSfs;

    if (int x = statfs(path, &tmpSfs))
        return x;

    memset(sfs, 0, sizeof(*sfs));

    sfs->f_bsize = tmpSfs.f_bsize;         /* file system block size */
    sfs->f_frsize = STATFS_FRSIZE(tmpSfs); /* fragment size */
    sfs->f_blocks = tmpSfs.f_blocks;       /* size of fs in f_frsize units */
    sfs->f_bfree = tmpSfs.f_bfree;         /* # free blocks */
    sfs->f_bavail = tmpSfs.f_bavail;       /* # free blocks for unprivileged users */
    sfs->f_files = tmpSfs.f_files;         /* # inodes */
    sfs->f_ffree = tmpSfs.f_ffree;         /* # free inodes */
    sfs->f_favail = tmpSfs.f_ffree;        /* # free inodes for unprivileged users */
    sfs->f_fsid = tmpSfs.f_fsid;           /* file system ID */
    sfs->f_namemax = tmpSfs.f_namelen;     /* maximum filename length */

#else
#error Both statvfs() and statfs() system calls are missing.
    errno = ENOSYS;
    return -1;

#endif
}

#endif /* HAVE_STATVFS */

