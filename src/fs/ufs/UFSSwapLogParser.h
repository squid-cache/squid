/*
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

#ifndef SQUID_FS_UFS_UFSSWAPLOGPARSER_H
#define SQUID_FS_UFS_UFSSWAPLOGPARSER_H

#include <stdio.h>

class StoreSwapLogData;

namespace Fs
{
namespace Ufs
{
/// \ingroup UFS
class UFSSwapLogParser
{
public:
    FILE *log;
    int log_entries;
    int record_size;

    UFSSwapLogParser(FILE *fp):log(fp),log_entries(-1), record_size(0) {
    }
    virtual ~UFSSwapLogParser() {};

    static UFSSwapLogParser *GetUFSSwapLogParser(FILE *fp);

    virtual bool ReadRecord(StoreSwapLogData &swapData) = 0;
    int SwapLogEntries();
    void Close() {
        if (log) {
            fclose(log);
            log = NULL;
        }
    }
};

} //namespace Ufs
} //namespace Fs
#endif /* SQUID_FS_UFS_UFSSWAPLOGPARSER_H */
