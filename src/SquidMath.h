#ifndef _SQUID_SRC_SQUIDMATH_H
#define _SQUID_SRC_SQUIDMATH_H

/* Math functions we define locally for Squid */
namespace Math
{

extern int intPercent(const int a, const int b);
extern double doublePercent(const double, const double);
extern int intAverage(const int, const int, int, const int);
extern double doubleAverage(const double, const double, int, const int);

}; // namespace Math

#endif /* _SQUID_SRC_SQUIDMATH_H */
