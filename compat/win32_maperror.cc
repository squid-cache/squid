/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/win32_maperror.h"

#if _SQUID_WINDOWS_ || _SQUID_MINGW_ && !_SQUID_CYGWIN_

#if HAVE_WINDOWS_H
#include <windows.h>
#endif
// for _doserrno
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <unordered_map>

void
WIN32_maperror(unsigned long WIN32_oserrno)
{
    static const auto errormap = std::unordered_map<unsigned long, int> {
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
    static const auto
        min_exec_error = ERROR_INVALID_STARTING_CODESEG,
        max_exec_error = ERROR_INFLOOP_IN_RELOC_CHAIN,
        min_eaccess_range = ERROR_WRITE_PROTECT,
        max_eaccess_range = ERROR_SHARING_BUFFER_EXCEEDED;

    _doserrno = WIN32_oserrno;
    auto it = errormap.find(WIN32_oserrno);
    if (it != errormap.end()) {
        errno = it->second;
        return;
    }
    if (WIN32_oserrno >= min_eaccess_range && WIN32_oserrno <= max_eaccess_range)
        errno = EACCES;
    else if (WIN32_oserrno >= min_exec_error && WIN32_oserrno <= max_exec_error)
        errno = ENOEXEC;
    else
        errno = EINVAL;
}


#endif