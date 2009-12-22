dnl 
dnl AUTHOR: Squid Web Cache team
dnl
dnl SQUID Web Proxy Cache          http://www.squid-cache.org/
dnl ----------------------------------------------------------
dnl Squid is the result of efforts by numerous individuals from
dnl the Internet community; see the CONTRIBUTORS file for full
dnl details.   Many organizations have provided support for Squid's
dnl development; see the SPONSORS file for full details.  Squid is
dnl Copyrighted (C) 2001 by the Regents of the University of
dnl California; see the COPYRIGHT file for full details.  Squid
dnl incorporates software developed and/or copyrighted by other
dnl sources; see the CREDITS file for full details.
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.


dnl check that strnstr() works fine. On Macos X it can cause a buffer overrun
dnl sets squid_cv_func_strnstr to "yes" or "no", and defines HAVE_STRNSTR
AC_DEFUN([SQUID_CHECK_FUNC_STRNSTR],[

# Yay!  This one is  a MacOSX brokenness.  Its not good enough
# to know that strnstr() exists, because MacOSX 10.4 have a bad
# copy that crashes with a buffer over-run!
AH_TEMPLATE(HAVE_STRNSTR,[MacOS brokenness: strnstr() can overrun on that system])
AC_CACHE_CHECK([if strnstr is well implemented], squid_cv_func_strnstr,
  AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
    // we expect this to succeed, or crash on over-run.
    // if it passes otherwise we may need a better check.
int main(int argc, char **argv)
{
    int size = 20;
    char *str = malloc(size);
    memset(str, 'x', size);
    strnstr(str, "fubar", size);
    return 0;
}
  ]])],[squid_cv_func_strnstr="yes"],[squid_cv_func_strnstr="no"],[])
)
if test "$squid_cv_func_strnstr" = "yes" ; then
  AC_DEFINE(HAVE_STRNSTR,1)
fi

]) dnl SQUID_CHECK_FUNC_STRNSTR

dnl check that va_copy is implemented and works
dnl sets squid_cv_func_va_copy and defines HAVE_VA_COPY
AC_DEFUN([SQUID_CHECK_FUNC_VACOPY],[

# check that the system provides a functional va_copy call

AH_TEMPLATE(HAVE_VA_COPY, [The system implements a functional va_copy() ])
AC_CACHE_CHECK(if va_copy is implemented, squid_cv_func_va_copy,
  AC_RUN_IFELSE([AC_LANG_SOURCE([[
      #include <stdarg.h>
      #include <stdlib.h>
      int f (int i, ...) {
         va_list args1, args2;
         va_start (args1, i);
         va_copy (args2, args1);
         if (va_arg (args2, int) != 42 || va_arg (args1, int) != 42)
            return 1;
         va_end (args1); va_end (args2);
         return 0;
      }
      int main(int argc, char **argv) { return f (0, 42); }
      ]])],[squid_cv_func_va_copy="yes"],[squid_cv_func_va_copy="no"],[])
)
if test "$squid_cv_func_va_copy" = "yes" ; then
  AC_DEFINE(HAVE_VA_COPY, 1)
fi

]) dnl SQUID_CHECK_FUNC_VACOPY

dnl same sa SQUID_CHECK_FUNC_VACOPY, but checks __va_copy
dnl sets squid_cv_func___va_copy, and defines HAVE___VA_COPY
AC_DEFUN([SQUID_CHECK_FUNC___VACOPY],[

AH_TEMPLATE(HAVE___VA_COPY,[Some systems have __va_copy instead of va_copy])
AC_CACHE_CHECK(if __va_copy is implemented, squid_cv_func___va_copy,
  AC_RUN_IFELSE([AC_LANG_SOURCE([[
      #include <stdarg.h>
      #include <stdlib.h>
      int f (int i, ...) {
         va_list args1, args2;
         va_start (args1, i);
         __va_copy (args2, args1);
         if (va_arg (args2, int) != 42 || va_arg (args1, int) != 42)
            return 1;
         va_end (args1); va_end (args2);
         return 0;
      }
      int main(int argc, char **argv) { return f (0, 42); }
      ]])],[squid_cv_func___va_copy="yes"],[squid_cv_func___va_copy="no"],[])
)
if test "$squid_cv_func___va_copy" = "yes" ; then
  AC_DEFINE(HAVE___VA_COPY, 1)
fi
]) dnl SQUID_CHECK_FUNC___VACOPY
