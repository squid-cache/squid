/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
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
    StatHist() = default;
    StatHist(const StatHist &);
    ~StatHist() {
        xfree(bins); // can handle case of bins being nullptr
        capacity_ = 0;  // mark as destructed, may be needed for troubleshooting
    }

    typedef uint64_t bins_type;

    StatHist &operator=(const StatHist &);

    /** Calculate the percentile for value pctile for the difference between
     *  this and the supplied histogram.
     */
    double deltaPctile(const StatHist &B, double pctile) const;

    /** obtain the output-transformed value from the specified bin
     *
     */
    double val(unsigned int bin) const;

    /** increment the counter for the histogram entry
     * associated to the supplied value
     */
    void count(double val);

    /** iterate the supplied bd function over the histogram values
     */
    void dump(StoreEntry *sentry, StatHistBinDumper * bd) const;

    /** Initialize the Histogram using a logarithmic values distribution
     */
    void logInit(unsigned int capacity, double min, double max);

    /** initialize the histogram to count occurrences in an enum-represented set
     */
    void enumInit(unsigned int last_enum);

    /** Import values from another histogram
     *
     * \note: the two histograms MUST have the same capicity, min and max or
     *      an exception will be raised
     */
    StatHist &operator += (const StatHist &B);

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
    void init(unsigned int capacity, hbase_f * val_in, hbase_f * val_out, double min, double max);

    /// find what entry in the histogram corresponds to v, by applying
    /// the preset input transformation function
    unsigned int findBin(double v);

    /// the histogram counters
    bins_type *bins = nullptr;
    unsigned int capacity_ = 0;

    /// minimum value to be stored, corresponding to the first bin
    double min_ = 0.0;

    /// value of the maximum counter in the histogram
    double max_ = 0.0;

    /// scaling factor when looking for a bin
    double scale_ = 1.0;
    hbase_f *val_in = nullptr;        /* e.g., log() for log-based histogram */
    hbase_f *val_out = nullptr;       /* e.g., exp() for log based histogram */
};

double statHistDeltaMedian(const StatHist & A, const StatHist & B);
double statHistDeltaPctile(const StatHist & A, const StatHist & B, double pctile);
StatHistBinDumper statHistEnumDumper;
StatHistBinDumper statHistIntDumper;

inline StatHist&
StatHist::operator =(const StatHist & src)
{
    if (this==&src) //handle self-assignment
        return *this;
    if (capacity_ != src.capacity_) {
        xfree(bins); // xfree can handle NULL pointers, no need to check
        capacity_=src.capacity_;
        bins = static_cast<bins_type *>(xcalloc(src.capacity_, sizeof(bins_type)));
    }
    min_=src.min_;
    max_=src.max_;
    scale_=src.scale_;
    val_in=src.val_in;
    val_out=src.val_out;
    if (bins)
        memcpy(bins,src.bins,capacity_*sizeof(*bins));
    return *this;
}

#endif /* STATHIST_H_ */

