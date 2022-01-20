/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID__SRC_CFG_FILE_H
#define _SQUID__SRC_CFG_FILE_H

#include "base/Here.h"
#include "cfg/forward.h"
#include "sbuf/SBuf.h"

#include <cstdio>
#include <string>

namespace Cfg
{

/**
 * Class used to store required information for the current
 * configuration file.
 */
class File
{
public:
    File(const char *path) : filePath(path) {}
    ~File();

    /// \return true if the configuration file is open
    bool isOpen() const { return bool(fd); }

    /// \return the next line to be parsed from this file
    SBuf nextLine();

    /// \return the configuration file name and line number being processed
    SourceLocation lineInfo() const { return SourceLocation("parsing", filePath.c_str(), lineNo); }

    /// open and load contents from the file
    void load();

private:
    std::string filePath;
    FILE *fd = nullptr;

    /// Random-size blocks of raw file bytes, in fread(2) order.
    /// We do not concatenate these blocks to avoid overflowing SBuf.
    SBufList fileData;

    int lineNo = 0; ///< Current line number being parsed

    /// Whether this is a FIFO pipe instead of a regular file.
    bool isPipe = false;
};

} // namespace Cfg

#endif /* _SQUID__SRC_CFG_FILE_H */
