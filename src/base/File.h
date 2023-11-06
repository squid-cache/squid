/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_FILE_H
#define SQUID_BASE_FILE_H

#include "sbuf/SBuf.h"

#if HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

/// How should a file be opened/created? Should it be locked?
class FileOpeningConfig
{
public:
    static FileOpeningConfig ReadOnly(); // shared reading
    static FileOpeningConfig ReadWrite(); // exclusive creation and/or reading/writing

    /* adjustment methods; named to work well with the File::Be::X shorthand */

    /// protect concurrent accesses by attempting to obtain an appropriate lock
    FileOpeningConfig &locked(unsigned int attempts = 5);

    /// when opening a file for writing, create it if it does not exist
    FileOpeningConfig &createdIfMissing();

    /// enter_suid() to open the file; leaves suid ASAP after that
    FileOpeningConfig &openedByRoot() { openByRoot = true; return *this; }

    /* add more mode adjustment methods as needed */

private:
    friend class File;

    /* file opening parameters */
#if _SQUID_WINDOWS_
    DWORD desiredAccess = 0; ///< 2nd CreateFile() parameter
    DWORD shareMode = 0; ///< 3rd CreateFile() parameter
    DWORD creationDisposition = OPEN_EXISTING; ///< 5th CreateFile() parameter
#else
    mode_t creationMask = 0; ///< umask() parameter; the default is S_IWGRP|S_IWOTH
    int openFlags = 0; ///< opening flags; 2nd open(2) parameter
    mode_t openMode = 0644; ///< access mode; 3rd open(2) parameter
#endif

    /* file locking (disabled unless lock(n) sets positive lockAttempts) */
#if _SQUID_WINDOWS_
    DWORD lockFlags = 0; ///< 2nd LockFileEx() parameter
#elif _SQUID_SOLARIS_
    int lockType = F_UNLCK; ///< flock::type member for fcntl(F_SETLK)
#else
    int flockMode = LOCK_UN; ///< 2nd flock(2) parameter
#endif
    const unsigned int retryGapUsec = 500000; ///< pause before each lock retry
    unsigned int lockAttempts = 0; ///< how many times to try locking
    bool openByRoot = false;
};

/// a portable locking-aware exception-friendly file (with RAII API)
class File
{
public:
    typedef FileOpeningConfig Be; ///< convenient shorthand for File() callers

    /// \returns nil if File() throws or a new File object (otherwise)
    static File *Optional(const SBuf &aName, const FileOpeningConfig &cfg);

    File(const SBuf &aFilename, const FileOpeningConfig &cfg); ///< opens
    ~File(); ///< closes

    /* can move but cannot copy */
    File(const File &) = delete;
    File &operator = (const File &) = delete;
    File(File &&other);
    File &operator = (File &&other);

    const SBuf &name() const { return name_; }

    /* system call wrappers */

    /// makes the file size (and the current I/O offset) zero
    void truncate();
    SBuf readSmall(SBuf::size_type minBytes, SBuf::size_type maxBytes); ///< read(2) for small files
    void writeAll(const SBuf &data); ///< write(2) with a "wrote everything" check
    void synchronize(); ///< fsync(2)

protected:
    bool isOpen() const {
#if _SQUID_WINDOWS_
        return fd_ != InvalidHandle;
#else
        return fd_ >= 0;
#endif
    }

    void open(const FileOpeningConfig &cfg);
    void lock(const FileOpeningConfig &cfg);
    void lockOnce(const FileOpeningConfig &cfg);
    void close();

    /// \returns a description a system call-related failure
    SBuf sysCallFailure(const char *callName, const SBuf &error) const;
    /// \returns a description of an errno-based system call failure
    SBuf sysCallError(const char *callName, const int savedErrno) const;

private:
    SBuf name_; ///< location on disk

    // Windows-specific HANDLE is needed because LockFileEx() does not take POSIX FDs.
#if _SQUID_WINDOWS_
    typedef HANDLE Handle;
    static const Handle InvalidHandle;
#else
    typedef int Handle;
    static const Handle InvalidHandle = -1;
#endif
    Handle fd_ = InvalidHandle; ///< OS-specific file handle
};

#endif

