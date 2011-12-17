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
 */

#ifndef STATHIST_H_
#define STATHIST_H_

/* for StoreEntry */
#include "Store.h"


/// function signature for in/out StatHist adaptation
typedef double hbase_f(double);

/// function signature for StatHist dumping functions
typedef void StatHistBinDumper(StoreEntry *, int idx, double val, double size, int count);

/** Generic histogram class
 *
 * see important comments on hbase_f restrictions in StatHist.cc
 */
class StatHist
{
public:
    /**
     * \note the default constructor doesn't fully initialize.
     *       you have to call one of the *init functions to specialize the
     *       histogram
     * \todo merge functionality from the *init functions to the constructor and
     *       drop these
     * \todo specialize the class in a small hierarchy so that all
     *       relevant initializations are done at build-time
     */
    StatHist() : scale_(1.0) {}
    StatHist &operator=(const StatHist &);
    ~StatHist();
    /** clear the contents of the histograms
     *
     * \todo remove: this function has been replaced in its purpose
     *       by the destructor
     */
    void clear();

    /** Calculate the percentile for value pctile for the difference between
     *  this and the supplied histogram.
     */
    double deltaPctile(const StatHist &B, double pctile) const;
    /** obtain the output-transformed value from the specified bin
     *
     */
    double val(int bin) const;
    /** increment the counter for the histogram entry
     * associated to the supplied value
     */
    void count(double val);
    /** iterate the supplied bd function over the histogram values
     */
    void dump(StoreEntry *sentry, StatHistBinDumper * bd) const;
    /** Initialize the Histogram using a logarithmic values distribution
     *
     */
    void logInit(int capacity, double min, double max);
    /** initialize the histogram to count occurrences in an enum-represented set
     *
     */
    void enumInit(int last_enum);
protected:
    /** low-level initialize function. called by *Init high-level functions
     * \note Important restrictions on val_in and val_out functions:
     *
     *   - val_in:  ascending, defined on [0, oo), val_in(0) == 0;
     *   - val_out: x == val_out(val_in(x)) where val_in(x) is defined
     *
     *  In practice, the requirements are less strict,
     *  but then it gets hard to define them without math notation.
     *  val_in is applied after offseting the value but before scaling
     *  See log and linear based histograms for examples
     */
    void init(int capacity, hbase_f * val_in, hbase_f * val_out, double min, double max);
    /// find what entry in the histogram corresponds to v, by applying
    /// the preset input transformation function
    int findBin(double v);
    /// the histogram counters
    int *bins;
    int capacity_;
    /// minimum value to be stored, corresponding to the first bin
    double min_;
    /// value of the maximum counter in the histogram
    double max_;
    /// scaling factor when looking for a bin
    double scale_;
    hbase_f *val_in;        /* e.g., log() for log-based histogram */
    hbase_f *val_out;       /* e.g., exp() for log based histogram */
private:
    StatHist(const StatHist&); //not needed
};

double statHistDeltaMedian(const StatHist & A, const StatHist & B);
double statHistDeltaPctile(const StatHist & A, const StatHist & B, double pctile);
StatHistBinDumper statHistEnumDumper;
StatHistBinDumper statHistIntDumper;

#endif /* STATHIST_H_ */
