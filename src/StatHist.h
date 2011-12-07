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
    double deltaPctile(const StatHist &B, double pctile) const;
    double val(int bin) const; //todo: make private
    void count(double val);
    StatHist &operator=(const StatHist &);
    StatHist() : bins(NULL), capacity(0), min(0), max(0), scale(1.0),
            val_in(NULL), val_out(NULL) {};
    StatHist(const StatHist&);
    void dump(StoreEntry *sentry, StatHistBinDumper * bd) const;
    void enumInit(int last_enum);
    void intInit(int n);
    void init(int capacity, hbase_f * val_in, hbase_f * val_out, double min, double max);
private:
    int findBin(double v);
};

class StatHistLog: public StatHist
{
    public:
    StatHistLog(int capacity_, double min_, double max_);
};



/* StatHist */
void statHistCount(StatHist * H, double val);
double statHistDeltaMedian(const StatHist & A, const StatHist & B);
double statHistDeltaPctile(const StatHist & A, const StatHist & B, double pctile);
void statHistLogInit(StatHist * H, int capacity, double min, double max);
void statHistEnumInit(StatHist * H, int last_enum);
void statHistIntInit(StatHist * H, int n);
StatHistBinDumper statHistEnumDumper;
StatHistBinDumper statHistIntDumper;




#endif /* STATHIST_H_ */
