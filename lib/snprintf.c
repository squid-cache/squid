/**************************************************************
 * Original:
 * Patrick Powell Tue Apr 11 09:48:21 PDT 1995
 * A bombproof version of doprnt (dopr) included.
 * Sigh. This sort of thing is always nasty do deal with. Note that
 * the version here does not include floating point...
 *
 * snprintf() is used instead of sprintf() as it does limit checks
 * for string length. This covers a nasty loophole.
 *
 * The other functions are there to prevent NULL pointers from
 * causing nast effects.
 **************************************************************/

/* Original RCS tag:
  Id: snprintf.c,v 1.1 1995/08/19 20:36:09 papowell Exp */

static void dopr();
static char *end;

#include "config.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif

/* varargs declarations: */

#if defined(HAVE_STDARG_H)
#include <stdarg.h>
#define HAVE_STDARGS		/* let's hope that works everywhere (mj) */
#define VA_LOCAL_DECL va_list ap;
#define VA_START(f) va_start(ap, f)
#define VA_SHIFT(v,t) ;		/* no-op for ANSI */
#define VA_END va_end(ap)
#else
#if defined(HAVE_VARARGS_H)
#include <varargs.h>
#undef HAVE_STDARGS
#define VA_LOCAL_DECL va_list ap;
#define VA_START(f) va_start(ap)	/* f is ignored! */
#define VA_SHIFT(v,t) v = va_arg(ap,t)
#define VA_END va_end(ap)
#else
XX **NO VARARGS ** XX
#endif
#endif

#ifdef HAVE_STDARGS
int snprintf(char *str, size_t count, const char *fmt,...);
int vsnprintf(char *str, size_t count, const char *fmt, va_list arg);
#else
int snprintf();
int vsnprintf();
#endif

int
vsnprintf(str, count, fmt, args)
     char *str;
     size_t count;
     const char *fmt;
     va_list args;
{
    str[0] = 0;
    end = str + count - 1;
    dopr(str, fmt, args);
    if (count > 0) {
	end[0] = 0;
    }
    return (strlen(str));
}

/* VARARGS3 */
#ifdef HAVE_STDARGS
int
snprintf(char *str, size_t count, const char *fmt,...)
#else
int
snprintf(va_alist)
     va_dcl
#endif
{
#ifndef HAVE_STDARGS
    char *str;
    size_t count;
    char *fmt;
#endif
    VA_LOCAL_DECL

	VA_START(fmt);
    VA_SHIFT(str, char *);
    VA_SHIFT(count, size_t);
    VA_SHIFT(fmt, char *);
    (void) vsnprintf(str, count, fmt, ap);
    VA_END;
    return (strlen(str));
}

/*
 * dopr(): poor man's version of doprintf
 */

static void fmtstr(char *value, int ljust, int len, int zpad);
static void fmtnum(long value, int base, int dosign,
    int ljust, int len, int zpad);
static void dostr(char *);
static char *output;
static void dopr_outch(int c);

static void
dopr(buffer, format, args)
     char *buffer;
     char *format;
     va_list args;
{
    int ch;
    long value;
    int longflag = 0;
    char *strvalue;
    int ljust;
    int len;
    int zpad;

    output = buffer;
    while ((ch = *format++)) {
	switch (ch) {
	case '%':
	    ljust = len = zpad = 0;
	  nextch:
	    ch = *format++;
	    switch (ch) {
	    case 0:
		dostr("**end of format**");
		return;
	    case '-':
		ljust = 1;
		goto nextch;
	    case '0':		/* set zero padding if len not set */
		if (len == 0)
		    zpad = '0';
	    case '1':
	    case '2':
	    case '3':
	    case '4':
	    case '5':
	    case '6':
	    case '7':
	    case '8':
	    case '9':
		len = len * 10 + ch - '0';
		goto nextch;
	    case 'l':
		longflag = 1;
		goto nextch;
	    case 'u':
	    case 'U':
		/*fmtnum(value,base,dosign,ljust,len,zpad) */
		if (longflag) {
		    value = va_arg(args, long);
		} else {
		    value = va_arg(args, int);
		}
		fmtnum(value, 10, 0, ljust, len, zpad);
		break;
	    case 'o':
	    case 'O':
		/*fmtnum(value,base,dosign,ljust,len,zpad) */
		if (longflag) {
		    value = va_arg(args, long);
		} else {
		    value = va_arg(args, int);
		}
		fmtnum(value, 8, 0, ljust, len, zpad);
		break;
	    case 'd':
	    case 'D':
		if (longflag) {
		    value = va_arg(args, long);
		} else {
		    value = va_arg(args, int);
		}
		fmtnum(value, 10, 1, ljust, len, zpad);
		break;
	    case 'x':
		if (longflag) {
		    value = va_arg(args, long);
		} else {
		    value = va_arg(args, int);
		}
		fmtnum(value, 16, 0, ljust, len, zpad);
		break;
	    case 'X':
		if (longflag) {
		    value = va_arg(args, long);
		} else {
		    value = va_arg(args, int);
		}
		fmtnum(value, -16, 0, ljust, len, zpad);
		break;
	    case 's':
		strvalue = va_arg(args, char *);
		fmtstr(strvalue, ljust, len, zpad);
		break;
	    case 'c':
		ch = va_arg(args, int);
		dopr_outch(ch);
		break;
	    case '%':
		dopr_outch(ch);
		continue;
	    default:
		dostr("???????");
	    }
	    longflag = 0;
	    break;
	default:
	    dopr_outch(ch);
	    break;
	}
    }
    *output = 0;
}

static void
fmtstr(value, ljust, len, zpad)
     char *value;
     int ljust, len, zpad;
{
    int padlen, strlen;		/* amount to pad */

    if (value == 0) {
	value = "<NULL>";
    }
    for (strlen = 0; value[strlen]; ++strlen);	/* strlen */
    padlen = len - strlen;
    if (padlen < 0)
	padlen = 0;
    if (ljust)
	padlen = -padlen;
    while (padlen > 0) {
	dopr_outch(' ');
	--padlen;
    }
    dostr(value);
    while (padlen < 0) {
	dopr_outch(' ');
	++padlen;
    }
}

static void
fmtnum(value, base, dosign, ljust, len, zpad)
     long value;
     int base, dosign, ljust, len, zpad;
{
    int signvalue = 0;
    unsigned long uvalue;
    char convert[20];
    int place = 0;
    int padlen = 0;		/* amount to pad */
    int caps = 0;

    /* DEBUGP(("value 0x%x, base %d, dosign %d, ljust %d, len %d, zpad %d\n",
     * value, base, dosign, ljust, len, zpad )); */
    uvalue = value;
    if (dosign) {
	if (value < 0) {
	    signvalue = '-';
	    uvalue = -value;
	}
    }
    if (base < 0) {
	caps = 1;
	base = -base;
    }
    do {
	convert[place++] =
	    (caps ? "0123456789ABCDEF" : "0123456789abcdef")
	    [uvalue % (unsigned) base];
	uvalue = (uvalue / (unsigned) base);
    } while (uvalue);
    convert[place] = 0;
    padlen = len - place;
    if (padlen < 0)
	padlen = 0;
    if (ljust)
	padlen = -padlen;
    /* DEBUGP(( "str '%s', place %d, sign %c, padlen %d\n",
     * convert,place,signvalue,padlen)); */
    if (zpad && padlen > 0) {
	if (signvalue) {
	    dopr_outch(signvalue);
	    --padlen;
	    signvalue = 0;
	}
	while (padlen > 0) {
	    dopr_outch(zpad);
	    --padlen;
	}
    }
    while (padlen > 0) {
	dopr_outch(' ');
	--padlen;
    }
    if (signvalue)
	dopr_outch(signvalue);
    while (place > 0)
	dopr_outch(convert[--place]);
    while (padlen < 0) {
	dopr_outch(' ');
	++padlen;
    }
}

static void
dostr(str)
     char *str;
{
    while (*str)
	dopr_outch(*str++);
}

static void
dopr_outch(c)
     int c;
{
    if (iscntrl(c) && c != '\n' && c != '\t') {
	c = '@' + (c & 0x1F);
	if (end == 0 || output < end) {
	    *output++ = '^';
	}
    }
    if (end == 0 || output < end) {
	*output++ = c;
    }
}
