dnl AC_CHECK_SIZEOF_SYSTYPE is as the standard AC_CHECK_SIZEOF macro
dnl but also capable of checking the size of system defined types, not
dnl only compiler defined types.

dnl AC_CHECK_SIZEOF_SYSTYPE(TYPE [, CROSS-SIZE])
AC_DEFUN(AC_CHECK_SIZEOF_SYSTYPE,
[changequote(<<, >>)dnl
dnl The name to #define.
define(<<AC_TYPE_NAME>>, translit(sizeof_$1, [a-z *], [A-Z_P]))dnl
dnl The cache variable name.
define(<<AC_CV_NAME>>, translit(ac_cv_sizeof_$1, [ *], [_p]))dnl
changequote([, ])dnl
AC_MSG_CHECKING(size of $1)
AC_CACHE_VAL(AC_CV_NAME,
[AC_TRY_RUN([#include <stdio.h>
#if HAVE_STDINT_H
#include <stdint.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
int main()
{
  FILE *f=fopen("conftestval", "w");
  if (!f) return(1);
  fprintf(f, "%d\n", sizeof($1));
  return(0);
}], AC_CV_NAME=`cat conftestval`, AC_CV_NAME=0, ifelse([$2], , , AC_CV_NAME=$2))])dnl
AC_MSG_RESULT($AC_CV_NAME)
AC_DEFINE_UNQUOTED(AC_TYPE_NAME, $AC_CV_NAME)
undefine([AC_TYPE_NAME])dnl
undefine([AC_CV_NAME])dnl
])

