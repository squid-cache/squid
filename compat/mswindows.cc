/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* Windows support
 * Inspired by previous work by Romeo Anghelache & Eric Stern. */

#include "squid.h"

#include "compat/unistd.h"

// The following code section is part of an EXPERIMENTAL native Windows NT/2000 Squid port.
// Compiles only on MS Visual C++
// CygWin appears not to need any of these
#if _SQUID_WINDOWS_ && !_SQUID_CYGWIN_

#define sys_nerr _sys_nerr

#undef assert
#include <cassert>
#include <cstring>
#include <fcntl.h>
#include <sys/timeb.h>
#if HAVE_PSAPI_H
#include <psapi.h>
#endif
#ifndef _MSWSOCK_
#include <mswsock.h>
#endif

THREADLOCAL int ws32_result;
LPCRITICAL_SECTION dbg_mutex = nullptr;

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
#if defined(PSAPI_VERSION)
    /* Get a handle to the process. */
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    /* Get the process name. */
    if (hProcess) {
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
        if (!(hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)))
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

int
WIN32_ftruncate(int fd, off_t size)
{
    HANDLE hfile;
    unsigned int curpos;

    if (fd < 0)
        return -1;

    hfile = (HANDLE) _get_osfhandle(fd);
    curpos = SetFilePointer(hfile, 0, nullptr, FILE_CURRENT);
    if (curpos == 0xFFFFFFFF
            || SetFilePointer(hfile, size, nullptr, FILE_BEGIN) == 0xFFFFFFFF
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
    int res = -1;

    const auto fd = xopen(pathname, O_RDWR);

    if (fd == -1)
        errno = EBADF;
    else {
        res = WIN32_ftruncate(fd, length);
        _close(fd);
    }

    return res;
}

struct passwd *
getpwnam(char *unused) {
    static struct passwd pwd = {nullptr, nullptr, 100, 100, nullptr, nullptr, nullptr};
    return &pwd;
}

struct group *
getgrnam(char *unused) {
    static struct group grp = {nullptr, nullptr, 100, nullptr};
    return &grp;
}

/* syslog emulation layer derived from git */
static HANDLE ms_eventlog;

void
openlog(const char *ident, int logopt, int facility)
{
    if (ms_eventlog)
        return;

    ms_eventlog = RegisterEventSourceA(nullptr, ident);

    // note: RegisterEventAtSourceA may fail and return nullptr.
    //   in that case we'll just retry at the next message or not log
}
#define SYSLOG_MAX_MSG_SIZE 1024

void
syslog(int priority, const char *fmt, ...)
{
    WORD logtype;
    char buf[SYSLOG_MAX_MSG_SIZE];
    const char* strings[1] = { buf };
    int str_len;
    va_list ap;

    if (!ms_eventlog)
        return;

    va_start(ap, fmt);
    str_len = vsnprintf(buf, sizeof(buf), fmt, ap);
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
    ReportEventA(ms_eventlog, logtype, 0, 0, nullptr, 1, 0,
                 strings, nullptr);
}

/* note: this is all MSWindows-specific code; all of it should be conditional */
#endif /* _SQUID_WINDOWS_ && !_SQUID_CYGWIN_*/
