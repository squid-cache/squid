#ifndef _SQUID_SRC_SQUIDMATH_H
#define _SQUID_SRC_SQUIDMATH_H

/* Math functions we define locally for Squid */
namespace Math
{

extern int intPercent(int a, int b);
extern double doublePercent(double, double);
extern int intAverage(int, int, int, int);
extern double doubleAverage(double, double, int, int);

}; // namespace Math

#endif /* _SQUID_SRC_SQUIDMATH_H */
