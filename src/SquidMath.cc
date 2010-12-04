#include "config.h"
#include "SquidMath.h"

int
Math::intPercent(const int a, const int b)
{
    return b ? ((int) (100.0 * a / b + 0.5)) : 0;
}

int64_t
Math::int64Percent(const int64_t a, const int64_t b)
{
    return b ? ((int64_t) (100.0 * a / b + 0.5)) : 0;
}

double
Math::doublePercent(const double a, const double b)
{
    return b ? (100.0 * a / b) : 0.0;
}

double
Math::doubleAverage(const double cur, const double newD, int N, const int max)
{
    if (N > max)
        N = max;

    return (cur * (N - 1.0) + newD) / N;
}

int
Math::intAverage(const int cur, const int newI, int n, const int max)
{
    if (n > max)
        n = max;

    return (cur * (n - 1) + newI) / n;
}
