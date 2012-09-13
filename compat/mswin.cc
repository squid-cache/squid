
/*
 * Windows support
 * AUTHOR: Guido Serassio <serassio@squid-cache.org>
 * inspired by previous work by Romeo Anghelache & Eric Stern.
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

#include "squid.h"
#include "util.h"

/* The following code section is part of an EXPERIMENTAL native */
/* Windows NT/2000 Squid port - Compiles only on MS Visual C++ or MinGW */
#if _SQUID_MSWIN_ || _SQUID_MINGW_

#undef strerror
#define sys_nerr _sys_nerr

#undef assert
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include "squid_windows.h"
#include <string.h>
#include <sys/timeb.h>
#if HAVE_WIN32_PSAPI
#include <psapi.h>
#endif

THREADLOCAL int ws32_result;
LPCRITICAL_SECTION dbg_mutex = NULL;

void GetProcessName(pid_t, char *);

#if defined(_MSC_VER)		/* Microsoft C Compiler ONLY */
size_t
getpagesize()
{
    static DWORD system_pagesize = 0;
    if (!system_pagesize) {
        SYSTEM_INFO system_info;
        GetSystemInfo(&system_info);
        system_pagesize = system_info.dwPageSize;
    }
    return system_pagesize;
}
#endif

uid_t
geteuid(void)
{
    return 100;
}

uid_t
getuid(void)
{
    return 100;
}

int
setuid(uid_t uid)
{
    return 0;
}

int
seteuid(uid_t euid)
{
    return 0;
}

gid_t
getegid(void)
{
    return 100;
}

gid_t
getgid(void)
{
    return 100;
}

int
setgid(gid_t gid)
{
    return 0;
}

int
setegid(gid_t egid)
{
    return 0;
}

int
chroot(const char *dirname)
{
    if (SetCurrentDirectory(dirname))
        return 0;
    else
        return GetLastError();
}

void
GetProcessName(pid_t pid, char *ProcessName)
{
    HANDLE hProcess;

    strcpy(ProcessName, "unknown");
#if HAVE_WIN32_PSAPI
    /* Get a handle to the process. */
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_READ,
                           FALSE, pid);
    /* Get the process name. */
    if (NULL != hProcess) {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
            GetModuleBaseName(hProcess, hMod, ProcessName, sizeof(ProcessName));
        else {
            CloseHandle(hProcess);
            return;
        }
    } else
        return;
    CloseHandle(hProcess);
#endif
}

int
kill(pid_t pid, int sig)
{
    HANDLE hProcess;
    char MyProcessName[MAX_PATH];
    char ProcessNameToCheck[MAX_PATH];

    if (sig == 0) {
        if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
                                    PROCESS_VM_READ,
                                    FALSE, pid)) == NULL)
            return -1;
        else {
            CloseHandle(hProcess);
            GetProcessName(getpid(), MyProcessName);
            GetProcessName(pid, ProcessNameToCheck);
            if (strcmp(MyProcessName, ProcessNameToCheck) == 0)
                return 0;
            return -1;
        }
    } else
        return 0;
}

#if !HAVE_GETTIMEOFDAY
int
gettimeofday(struct timeval *pcur_time, void *tzp)
{
    struct _timeb current;
    struct timezone *tz = (struct timezone *) tzp;

    _ftime(&current);

    pcur_time->tv_sec = current.time;
    pcur_time->tv_usec = current.millitm * 1000L;
    if (tz) {
        tz->tz_minuteswest = current.timezone;	/* minutes west of Greenwich  */
        tz->tz_dsttime = current.dstflag;	/* type of dst correction  */
    }
    return 0;
}
#endif

int
statfs(const char *path, struct statfs *sfs)
{
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
    sfs->f_type = flags;
    sfs->f_bsize = spc * bps;
    sfs->f_blocks = totalc;
    sfs->f_bfree = sfs->f_bavail = freec;
    sfs->f_files = -1;
    sfs->f_ffree = -1;
    sfs->f_fsid = vsn;
    sfs->f_namelen = maxlen;
    return 0;
}

#if !_SQUID_MINGW_
int
WIN32_ftruncate(int fd, off_t size)
{
    HANDLE hfile;
    unsigned int curpos;

    if (fd < 0)
        return -1;

    hfile = (HANDLE) _get_osfhandle(fd);
    curpos = SetFilePointer(hfile, 0, NULL, FILE_CURRENT);
    if (curpos == 0xFFFFFFFF
            || SetFilePointer(hfile, size, NULL, FILE_BEGIN) == 0xFFFFFFFF
            || !SetEndOfFile(hfile)) {
        int error = GetLastError();

        switch (error) {
        case ERROR_INVALID_HANDLE:
            errno = EBADF;
            break;
        default:
            errno = EIO;
            break;
        }

        return -1;
    }
    return 0;
}

int
WIN32_truncate(const char *pathname, off_t length)
{
    int fd;
    int res = -1;

    fd = open(pathname, O_RDWR);

    if (fd == -1)
        errno = EBADF;
    else {
        res = WIN32_ftruncate(fd, length);
        _close(fd);
    }

    return res;
}
#endif /* !_SQUID_MINGW_ */

struct passwd *
getpwnam(char *unused) {
    static struct passwd pwd = {NULL, NULL, 100, 100, NULL, NULL, NULL};
    return &pwd;
}

struct group *
getgrnam(char *unused) {
    static struct group grp = {NULL, NULL, 100, NULL};
    return &grp;
}

#if defined(__MINGW32__)	/* MinGW environment */
int
_free_osfhnd(int filehandle)
{
    if (((unsigned) filehandle < SQUID_MAXFD) &&
            (_osfile(filehandle) & FOPEN) &&
            (_osfhnd(filehandle) != (long) INVALID_HANDLE_VALUE)) {
        switch (filehandle) {
        case 0:
            SetStdHandle(STD_INPUT_HANDLE, NULL);
            break;
        case 1:
            SetStdHandle(STD_OUTPUT_HANDLE, NULL);
            break;
        case 2:
            SetStdHandle(STD_ERROR_HANDLE, NULL);
            break;
        }
        _osfhnd(filehandle) = (long) INVALID_HANDLE_VALUE;
        return (0);
    } else {
        errno = EBADF;		/* bad handle */
        _doserrno = 0L;		/* not an OS error */
        return -1;
    }
}
#endif

struct errorentry {
    unsigned long WIN32_code;
    int POSIX_errno;
};

static struct errorentry errortable[] = {
    {ERROR_INVALID_FUNCTION, EINVAL},
    {ERROR_FILE_NOT_FOUND, ENOENT},
    {ERROR_PATH_NOT_FOUND, ENOENT},
    {ERROR_TOO_MANY_OPEN_FILES, EMFILE},
    {ERROR_ACCESS_DENIED, EACCES},
    {ERROR_INVALID_HANDLE, EBADF},
    {ERROR_ARENA_TRASHED, ENOMEM},
    {ERROR_NOT_ENOUGH_MEMORY, ENOMEM},
    {ERROR_INVALID_BLOCK, ENOMEM},
    {ERROR_BAD_ENVIRONMENT, E2BIG},
    {ERROR_BAD_FORMAT, ENOEXEC},
    {ERROR_INVALID_ACCESS, EINVAL},
    {ERROR_INVALID_DATA, EINVAL},
    {ERROR_INVALID_DRIVE, ENOENT},
    {ERROR_CURRENT_DIRECTORY, EACCES},
    {ERROR_NOT_SAME_DEVICE, EXDEV},
    {ERROR_NO_MORE_FILES, ENOENT},
    {ERROR_LOCK_VIOLATION, EACCES},
    {ERROR_BAD_NETPATH, ENOENT},
    {ERROR_NETWORK_ACCESS_DENIED, EACCES},
    {ERROR_BAD_NET_NAME, ENOENT},
    {ERROR_FILE_EXISTS, EEXIST},
    {ERROR_CANNOT_MAKE, EACCES},
    {ERROR_FAIL_I24, EACCES},
    {ERROR_INVALID_PARAMETER, EINVAL},
    {ERROR_NO_PROC_SLOTS, EAGAIN},
    {ERROR_DRIVE_LOCKED, EACCES},
    {ERROR_BROKEN_PIPE, EPIPE},
    {ERROR_DISK_FULL, ENOSPC},
    {ERROR_INVALID_TARGET_HANDLE, EBADF},
    {ERROR_INVALID_HANDLE, EINVAL},
    {ERROR_WAIT_NO_CHILDREN, ECHILD},
    {ERROR_CHILD_NOT_COMPLETE, ECHILD},
    {ERROR_DIRECT_ACCESS_HANDLE, EBADF},
    {ERROR_NEGATIVE_SEEK, EINVAL},
    {ERROR_SEEK_ON_DEVICE, EACCES},
    {ERROR_DIR_NOT_EMPTY, ENOTEMPTY},
    {ERROR_NOT_LOCKED, EACCES},
    {ERROR_BAD_PATHNAME, ENOENT},
    {ERROR_MAX_THRDS_REACHED, EAGAIN},
    {ERROR_LOCK_FAILED, EACCES},
    {ERROR_ALREADY_EXISTS, EEXIST},
    {ERROR_FILENAME_EXCED_RANGE, ENOENT},
    {ERROR_NESTING_NOT_ALLOWED, EAGAIN},
    {ERROR_NOT_ENOUGH_QUOTA, ENOMEM}
};

#define MIN_EXEC_ERROR ERROR_INVALID_STARTING_CODESEG
#define MAX_EXEC_ERROR ERROR_INFLOOP_IN_RELOC_CHAIN

#define MIN_EACCES_RANGE ERROR_WRITE_PROTECT
#define MAX_EACCES_RANGE ERROR_SHARING_BUFFER_EXCEEDED

void
WIN32_maperror(unsigned long WIN32_oserrno)
{
    int i;

    _doserrno = WIN32_oserrno;
    for (i = 0; i < (sizeof(errortable) / sizeof(struct errorentry)); ++i) {
        if (WIN32_oserrno == errortable[i].WIN32_code) {
            errno = errortable[i].POSIX_errno;
            return;
        }
    }
    if (WIN32_oserrno >= MIN_EACCES_RANGE && WIN32_oserrno <= MAX_EACCES_RANGE)
        errno = EACCES;
    else if (WIN32_oserrno >= MIN_EXEC_ERROR && WIN32_oserrno <= MAX_EXEC_ERROR)
        errno = ENOEXEC;
    else
        errno = EINVAL;
}
#endif
