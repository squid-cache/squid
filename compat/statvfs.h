/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_COMPAT_XSTATVFS_H
#define _SQUID_COMPAT_XSTATVFS_H

#if HAVE_SYS_STATVFS_H && HAVE_STATVFS
#include <sys/statvfs.h>
#endif

/* Windows and Linux use sys/vfs.h */
#if HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif

/* BSD and old Linux use sys/statfs.h */
#if !HAVE_STATVFS
#if HAVE_SYS_STATFS_H
#include <sys/statfs.h>
#endif
/* statfs() needs <sys/param.h> and <sys/mount.h> on BSD systems */
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#endif /* !HAVE_STATVFS */

#if HAVE_STATVFS
#define xstatvfs statvfs

#else

typedef unsigned long fsblkcnt_t;
typedef unsigned long fsfilcnt_t;

struct statvfs {
    unsigned long  f_bsize;    /* file system block size */
    unsigned long  f_frsize;   /* fragment size */
    fsblkcnt_t     f_blocks;   /* size of fs in f_frsize units */
    fsblkcnt_t     f_bfree;    /* # free blocks */
    fsblkcnt_t     f_bavail;   /* # free blocks for unprivileged users */
    fsfilcnt_t     f_files;    /* # inodes */
    fsfilcnt_t     f_ffree;    /* # free inodes */
    fsfilcnt_t     f_favail;   /* # free inodes for unprivileged users */
    unsigned long  f_fsid;     /* file system ID */
    unsigned long  f_flag;     /* mount flags */
    unsigned long  f_namemax;  /* maximum filename length */
};

#if defined(__cplusplus)
extern "C"
#endif
int xstatvfs(const char *path, struct statvfs *buf);

#endif

#endif /* _SQUID_COMPAT_XSTATVFS_H */

