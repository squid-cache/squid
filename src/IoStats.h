/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_IOSTATS_H
#define SQUID_SRC_IOSTATS_H

/// IO statistics. Currently a POD.
class IoStats
{
public:
    static const int histSize=16;

    struct {
        int reads;
        int reads_deferred;
        int read_hist[histSize];
        int writes;
        int write_hist[histSize];
    }
    Http, Ftp;
};

#endif /* SQUID_SRC_IOSTATS_H */

