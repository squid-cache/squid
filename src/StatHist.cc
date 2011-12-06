
/*
 * $Id$
 *
 * DEBUG: section 62    Generic Histogram
 * AUTHOR: Duane Wessels
 *
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

/*
 * Important restrictions on val_in and val_out functions:
 *
 *   - val_in:  ascending, defined on [0, oo), val_in(0) == 0;
 *   - val_out: x == val_out(val_in(x)) where val_in(x) is defined
 *
 *  In practice, the requirements are less strict,
 *  but then it gets hard to define them without math notation.
 *  val_in is applied after offseting the value but before scaling
 *  See log and linear based histograms for examples
 */

#include "squid.h"
#include "StatHist.h"
#include "Store.h"

/* Local functions */
static StatHistBinDumper statHistBinDumper;

namespace Math
{
hbase_f Log;
hbase_f Exp;
hbase_f Null;
};

/* low level init, higher level functions has less params */
void
StatHist::init(int capacity_, hbase_f * val_in_, hbase_f * val_out_, double min_, double max_)
{
    assert(capacity_ > 0);
    assert(val_in_ && val_out_);
    /* check before we divide to get scale */
    assert(val_in_(max_ - min_) > 0);
    min = min_;
    max = max_;
    capacity = capacity_;
    val_in = val_in_;
    val_out = val_out_;
    bins = (int *)xcalloc(capacity, sizeof(int));
    scale = capacity / val_in(max - min);

    /* check that functions are valid */
    /* a min value should go into bin[0] */
    assert(findBin(min) == 0);
    /* a max value should go into the last bin */
    assert(findBin(max) == capacity - 1);
    /* it is hard to test val_out, here is a crude test */
    assert(((int) floor(0.99 + val(0) - min)) == 0);
}

void
StatHist::clear()
{
    xfree(bins);
    bins = NULL;
}

/* assumes that somebody already called init for Dest */
/* TODO: remove assumption */
StatHist&
StatHist::operator =(const StatHist & src)
{
    assert(src.bins != NULL);
    assert(capacity==src.capacity);
    assert(min==src.min);
    assert(max==src.max);
    assert(fabs(scale - src.scale) < 0.0000001);
    assert(val_in==src.val_in);
    assert(val_out==src.val_out);
    memcpy(bins,src.bins,capacity*sizeof(*bins));
    return *this;
}

void
StatHist::count(double val)
{
    const int bin = findBin(val);
    assert(bins);		/* make sure it got initialized */
    assert(0 <= bin && bin < capacity);
    ++bins[bin];
}

int
StatHist::findBin(double v)
{
    int bin;

    v -= min;		/* offset */

    if (v <= 0.0)		/* too small */
        return 0;

    bin = (int) floor(scale * val_in(v) + 0.5);

    if (bin < 0)		/* should not happen */
        bin = 0;

    if (bin >= capacity)	/* too big */
        bin = capacity - 1;

    return bin;
}

double
StatHist::val(int bin) const
{
    return val_out((double) bin / scale) + min;
}

double
statHistDeltaMedian(const StatHist & A, const StatHist & B)
{
    return statHistDeltaPctile(A,B, 0.5);
}

double
statHistDeltaPctile(const StatHist & A, const StatHist & B, double pctile)
{
    int i;
    int s1 = 0;
    int h = 0;
    int a = 0;
    int b = 0;
    int I = 0;
    int J = A.capacity;
    int K;
    double f;

    assert(A.capacity == B.capacity);

    int *D = (int *)xcalloc(A.capacity, sizeof(int));

    for (i = 0; i < A.capacity; ++i) {
        D[i] = B.bins[i] - A.bins[i];
        assert(D[i] >= 0);
    }

    for (i = 0; i < A.capacity; ++i)
        s1 += D[i];

    h = int(s1 * pctile);

    for (i = 0; i < A.capacity; ++i) {
        J = i;
        b += D[J];

        if (a <= h && h <= b)
            break;

        I = i;

        a += D[I];
    }

    xfree(D);

    if (s1 == 0)
        return 0.0;

    if (a > h)
        return 0.0;

    if (a >= b)
        return 0.0;

    if (I >= J)
        return 0.0;

    f = (h - a) / (b - a);

    K = (int) floor(f * (double) (J - I) + I);

    return A.val(K);
}

static void
statHistBinDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    if (count)
        storeAppendPrintf(sentry, "\t%3d/%f\t%d\t%f\n",
                          idx, val, count, count / size);
}

void
statHistDump(const StatHist * H, StoreEntry * sentry, StatHistBinDumper * bd)
{
    int i;
    double left_border = H->min;

    if (!bd)
        bd = statHistBinDumper;

    for (i = 0; i < H->capacity; i++) {
        const double right_border = H->val(i + 1);
        assert(right_border - left_border > 0.0);
        bd(sentry, i, left_border, right_border - left_border, H->bins[i]);
        left_border = right_border;
    }
}

/* log based histogram */
double
Math::Log(double x)
{
    assert((x + 1.0) >= 0.0);
    return log(x + 1.0);
}

double
Math::Exp(double x)
{
    return exp(x) - 1.0;
}

void
statHistLogInit(StatHist * H, int capacity, double min, double max)
{
    H->init(capacity, Math::Log, Math::Exp, min, max);
}

/* linear histogram for enums */
/* we want to be have [-1,last_enum+1] range to track out of range enums */
double
Math::Null(double x)
{
    return x;
}

void
statHistEnumInit(StatHist * H, int last_enum)
{
    H->init(last_enum + 3, Math::Null, Math::Null, (double) -1, (double) (last_enum + 1 + 1));
}

void
statHistEnumDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    if (count)
        storeAppendPrintf(sentry, "%2d\t %5d\t %5d\n",
                          idx, (int) val, count);
}

void
statHistIntInit(StatHist * H, int n)
{
    H->init(n, Math::Null, Math::Null, (double) 0, (double) n - 1);
}

void
statHistIntDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    if (count)
        storeAppendPrintf(sentry, "%9d\t%9d\n", (int) val, count);
}
