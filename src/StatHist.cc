/*
 * $Id: StatHist.cc,v 1.1 1998/02/25 09:55:06 rousskov Exp $
 *
 * DEBUG: section 62    Generic Histogram
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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

/* Local functions */
static void statHistInit(StatHist * H, int capacity, hbase_f val_in, hbase_f val_out, double min, double max);
static int statHistBin(const StatHist * H, double v);
static double statHistVal(const StatHist * H, int bin);
static void statHistBinDumper(StoreEntry * sentry, int idx, double val, double size, int count);



/* low level init, higher level functions has less params */
static void
statHistInit(StatHist * H, int capacity, hbase_f val_in, hbase_f val_out, double min, double max)
{
    assert(H);
    assert(capacity > 0);
    assert(val_in && val_out);
    /* check that functions are valid */
    assert(val_in(0.0) == 0.0 && val_out(val_in(0.0)) == 0.0);
    H->bins = xcalloc(capacity, sizeof(int));
    H->min = min;
    H->max = max;
    H->capacity = capacity;
    H->scale = capacity / val_in(max - min);
    H->val_in = val_in;
    H->val_out = val_out;
}

void
statHistClean(StatHist * H)
{
    xfree(H->bins);
    H->bins = NULL;
}

/* assumes that somebody already called init for Dest */
void
statHistCopy(StatHist * Dest, const StatHist * Orig)
{
    assert(Dest && Orig);
    assert(Dest->bins);
    /* better be safe than sorry */
    assert(Dest->capacity == Orig->capacity);
    assert(Dest->min == Orig->min && Dest->max == Orig->max);
    assert(Dest->scale == Orig->scale);
    assert(Dest->val_in == Orig->val_in && Dest->val_out == Orig->val_out);
    /* actual copy */
    xmemcpy(Dest->bins, Orig->bins, Dest->capacity*sizeof(*Dest->bins));
}

void
statHistCount(StatHist * H, double val)
{
    const int bin = statHistBin(H, val);
    assert(H->bins);	/* make sure it got initialized */
    assert(0 <= bin && bin < H->capacity);
    H->bins[bin]++;
}

static int
statHistBin(const StatHist * H, double v)
{
    int bin;
    v -= H->min; /* offset */
    if (v < 0.0) /* too small */
	return 0;
    bin = (int) (H->scale * H->val_in(v) + 0.5);
    if (bin < 0) /* should not happen */
	bin = 0;
    if (bin >= H->capacity) /* too big */
	bin = H->capacity - 1;
    return bin;
}

static double
statHistVal(const StatHist * H, int bin)
{
    return H->val_out(bin / H->scale) + H->min;
}

double
statHistDeltaMedian(const StatHist * A, const StatHist * B)
{
    int i;
    int s1 = 0;
    int h = 0;
    int a = 0;
    int b = 0;
    int I = 0;
    int J = A->capacity;
    int K;
    double f;
    int *D = xcalloc(A->capacity, sizeof(int));
    assert(A->capacity == B->capacity);
    for (i = 0; i < A->capacity; i++) {
	D[i] = B->bins[i] - A->bins[i];
	assert(D[i] >= 0);
    }
    for (i = 0; i < A->capacity; i++)
	s1 += D[i];
    h = s1 >> 1;
    for (i = 0; i < A->capacity; i++) {
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
    if (a > h) {
	debug(0, 0) ("statHistDeltaMedian: a=%d, h=%d\n", a, h);
	return 0.0;
    }
    if (a >= b) {
	debug(0, 0) ("statHistDeltaMedian: a=%d, b=%d\n", a, b);
	return 0.0;
    }
    if (I >= J) {
	debug(0, 0) ("statHistDeltaMedian: I=%d, J=%d\n", I, J);
	return 0.0;
    }
    f = (h - a) / (b - a);
    K = (int) (f * (double) (J - I) + I);
    return statHistVal(A, K);
}

static void
statHistBinDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    if (count)
	storeAppendPrintf(sentry, "\t%3d/%f\t%d\t%f\n",
	    idx, val, count, count/size);
}

void
statHistDump(const StatHist * H, StoreEntry * sentry, StatHistBinDumper bd)
{
    int i;
    double left_border = H->min;
    if (!bd)
	bd = statHistBinDumper;
    for (i = 0; i < H->capacity; i++) {
	const double right_border = statHistVal(H, i+1);
	assert(right_border - left_border > 0.0);
	bd(sentry, i, left_border, right_border - left_border, H->bins[i]);
	left_border = right_border;
    }
}

/* log based histogram */
static double Log(double x) { return log(x+1); }
static double Exp(double x) { return exp(x)-1; }
void
statHistLogInit(StatHist * H, int capacity, double min, double max)
{
    statHistInit(H, capacity, &Log, &Exp, min, max);
}

/* linear histogram for enums */
/* we want to be have [-1,last_enum+1] range to track out of range enums */
static double Null(double x) { return x; }
void
statHistEnumInit(StatHist * H, int last_enum)
{
    statHistInit(H, last_enum+3, &Null, &Null, -1, last_enum+1+1);
}
