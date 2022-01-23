/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* Windows support
 * Inspired by previous work by Romeo Anghelache & Eric Stern. */

#include "squid.h"

// The following code section is part of an EXPERIMENTAL native Windows NT/2000 Squid port.
// Compiles only on MS Visual C++ or MinGW
// CygWin appears not to need any of these
#if _SQUID_WINDOWS_ && !_SQUID_CYGWIN_

#define sys_nerr _sys_nerr

#undef assert
#include <cassert>
#include <cstring>
#include <fcntl.h>
#include <sys/timeb.h>
#if HAVE_WIN32_PSAPI
#include <psapi.h>
#endif
#ifndef _MSWSOCK_
#include <mswsock.h>
#endif

THREADLOCAL int ws32_result;
LPCRITICAL_SECTION dbg_mutex = NULL;

void GetProcessName(pid_t, char *);

#if HAVE_GETPAGESIZE > 1
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
#endif /* HAVE_GETPAGESIZE > 1 */

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
    strcpy(ProcessName, "unknown");
#if HAVE_WIN32_PSAPI
    /* Get a handle to the process. */
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
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
#endif /* HAVE_WIN32_PSAPI */
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
        tz->tz_minuteswest = current.timezone; /* minutes west of Greenwich  */
        tz->tz_dsttime = current.dstflag;      /* type of dst correction  */
    }
    return 0;
}
#endif /* !HAVE_GETTIMEOFDAY */

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

#if _SQUID_MINGW_
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
        errno = EBADF;      /* bad handle */
        _doserrno = 0L;     /* not an OS error */
        return -1;
    }
}
#endif /* _SQUID_MINGW_ */

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
    _doserrno = WIN32_oserrno;
    for (size_t i = 0; i < (sizeof(errortable) / sizeof(struct errorentry)); ++i) {
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

/* syslog emulation layer derived from git */
static HANDLE ms_eventlog;

void
openlog(const char *ident, int logopt, int facility)
{
    if (ms_eventlog)
        return;

    ms_eventlog = RegisterEventSourceA(NULL, ident);

    // note: RegisterEventAtSourceA may fail and return NULL.
    //   in that case we'll just retry at the next message or not log
}
#define SYSLOG_MAX_MSG_SIZE 1024

void
syslog(int priority, const char *fmt, ...)
{
    WORD logtype;
    char *str=static_cast<char *>(xmalloc(SYSLOG_MAX_MSG_SIZE));
    int str_len;
    va_list ap;

    if (!ms_eventlog)
        return;

    va_start(ap, fmt);
    str_len = vsnprintf(str, SYSLOG_MAX_MSG_SIZE-1, fmt, ap);
    va_end(ap);

    if (str_len < 0) {
        /* vsnprintf failed */
        return;
    }

    switch (priority) {
    case LOG_EMERG:
    case LOG_ALERT:
    case LOG_CRIT:
    case LOG_ERR:
        logtype = EVENTLOG_ERROR_TYPE;
        break;

    case LOG_WARNING:
        logtype = EVENTLOG_WARNING_TYPE;
        break;

    case LOG_NOTICE:
    case LOG_INFO:
    case LOG_DEBUG:
    default:
        logtype = EVENTLOG_INFORMATION_TYPE;
        break;
    }

    //Windows API suck. They are overengineered
    ReportEventA(ms_eventlog, logtype, 0, 0, NULL, 1, 0,
                 const_cast<const char **>(&str), NULL);
}

/* note: this is all MSWindows-specific code; all of it should be conditional */
#endif /* _SQUID_WINDOWS_ */

