

/* borrowed from libc/misc/drand48.c in Linux libc-5.4.46 this quick
 * hack by Martin Hamilton <martinh@gnu.org> to make Squid build on
 * Win32 with GNU-Win32 - sorry, folks! */

#ifndef HAVE_DRAND48

#define N	16
#define MASK	((unsigned)(1 << (N - 1)) + (1 << (N - 1)) - 1)
#define LOW(x)	((unsigned)(x) & MASK)
#define HIGH(x)	LOW((x) >> N)
#define MUL(x, y, z)	{ long l = (long)(x) * (long)(y); \
		(z)[0] = LOW(l); (z)[1] = HIGH(l); }
#define CARRY(x, y)	((long)(x) + (long)(y) > MASK)
#define ADDEQU(x, y, z)	(z = CARRY(x, (y)), x = LOW(x + (y)))
#define X0	0x330E
#define X1	0xABCD
#define X2	0x1234
#define A0	0xE66D
#define A1	0xDEEC
#define A2	0x5
#define C	0xB

static void next(void);
static unsigned x[3] =
{X0, X1, X2}, a[3] =
{A0, A1, A2}, c = C;

double drand48(void);

double
drand48(void)
{
    static double two16m = 1.0 / (1L << N);
    next();
    return (two16m * (two16m * (two16m * x[0] + x[1]) + x[2]));
}

static void
next(void)
{
    unsigned p[2], q[2], r[2], carry0, carry1;

    MUL(a[0], x[0], p);
    ADDEQU(p[0], c, carry0);
    ADDEQU(p[1], carry0, carry1);
    MUL(a[0], x[1], q);
    ADDEQU(p[1], q[0], carry0);
    MUL(a[1], x[0], r);
    x[2] = LOW(carry0 + carry1 + CARRY(p[1], r[0]) + q[1] + r[1] +
	a[0] * x[2] + a[1] * x[1] + a[2] * x[0]);
    x[1] = LOW(p[1] + r[0]);
    x[0] = LOW(p[0]);
}

#endif /* HAVE_DRAND48 */
