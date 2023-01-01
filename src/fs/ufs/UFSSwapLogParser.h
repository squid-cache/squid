/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FS_UFS_UFSSWAPLOGPARSER_H
#define SQUID_FS_UFS_UFSSWAPLOGPARSER_H

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

