/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/signal.h"

#if _SQUID_WINDOWS_ || _SQUID_MINGW_

#ifdef HAVE_PSAPI_H
#include <psapi.h>
#endif

static void
GetProcessName(pid_t pid, char *ProcessName)
{
    strcpy(ProcessName, "unknown");

    auto hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) // If we cannot open the process, we cannot get its name.
        return;

    /* Get the process name. */
    HMODULE hMod;
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
        GetModuleBaseName(hProcess, hMod, ProcessName, sizeof(ProcessName));
    } else {
        CloseHandle(hProcess);
        return;
    }
    CloseHandle(hProcess);
}

/// true if the given pid is the current process, false otherwise
static bool
IsPidSelf(int pid)
{
    char MyProcessName[MAX_PATH];
    GetProcessName(getpid(), MyProcessName);
    char ProcessNameToCheck[MAX_PATH];
    GetProcessName(pid, ProcessNameToCheck);
    if (strcmp(MyProcessName, ProcessNameToCheck) == 0)
        return true;
    return false;
}

int
xkill(pid_t pid, int sig)
{
    auto hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (!hProcess)
        return -1;

    switch (sig) {
// Windows does not support sending generic POSIX signals.
// TODO: implement a signal sending and handling mechanism
// using Windows messages
    case SIGKILL:
        if (TerminateProcess(hProcess, 0)) {
            CloseHandle(hProcess);
            return 0;
        }
        break;
    case 0:
        CloseHandle(hProcess);
        if (IsPidSelf(pid))
            return 0; // self is always "killed" by SIGNULL
        return -1; // cannot kill other processes with SIGNULL
        break;
    default:
        // Unsupported signal
        CloseHandle(hProcess);
    }

    return -1;
}

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */