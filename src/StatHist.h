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
 *  AUTHOR: Francesco Chemolli
 */

#ifndef STATHIST_H_
#define STATHIST_H_

#include "config.h"

/*
 * "very generic" histogram;
 * see important comments on hbase_f restrictions in StatHist.c
 */

class StatHist {
public:
    void clear();
    int *bins;
    int capacity;
    double min;
    double max;
    double scale;
    hbase_f *val_in;        /* e.g., log() for log-based histogram */
    hbase_f *val_out;       /* e.g., exp() for log based histogram */
};

/* StatHist */
SQUIDCEXTERN void statHistCount(StatHist * H, double val);
SQUIDCEXTERN void statHistCopy(StatHist * Dest, const StatHist * Orig);
SQUIDCEXTERN void statHistSafeCopy(StatHist * Dest, const StatHist * Orig);
SQUIDCEXTERN double statHistDeltaMedian(const StatHist * A, const StatHist * B);
SQUIDCEXTERN double statHistDeltaPctile(const StatHist * A, const StatHist * B, double pctile);
SQUIDCEXTERN void statHistDump(const StatHist * H, StoreEntry * sentry, StatHistBinDumper * bd);
SQUIDCEXTERN void statHistLogInit(StatHist * H, int capacity, double min, double max);
SQUIDCEXTERN void statHistEnumInit(StatHist * H, int last_enum);
SQUIDCEXTERN void statHistIntInit(StatHist * H, int n);
SQUIDCEXTERN StatHistBinDumper statHistEnumDumper;
SQUIDCEXTERN StatHistBinDumper statHistIntDumper;




#endif /* STATHIST_H_ */
