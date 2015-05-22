## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

##
## AX_CXX_TYPE_NULLPTR shamelessly copied from the DUNE sources under GPL version 2
## 
AC_DEFUN([AX_CXX_TYPE_NULLPTR],[
  AC_REQUIRE([AC_PROG_CXX])
  AC_LANG_PUSH([C++])
  AC_MSG_CHECKING([whether nullptr is supported])
  AC_TRY_COMPILE([],[char* ch = nullptr;], [
    HAVE_NULLPTR=yes
    AC_MSG_RESULT(yes)], [
    HAVE_NULLPTR=no
    AC_MSG_RESULT(no)])
  if test "x$HAVE_NULLPTR" = xyes; then
    AC_DEFINE(HAVE_NULLPTR, 1, [Define to 1 if nullptr is supported])
  fi
  AC_MSG_CHECKING([whether nullptr_t is supported])
  AC_TRY_COMPILE([#include <cstddef>],[typedef nullptr_t peng;], [
    HAVE_NULLPTR_T=yes
    AC_MSG_RESULT(yes)], [
    HAVE_NULLPTR_T=no
    AC_MSG_RESULT(no)])
  if test "x$HAVE_NULLPTR_T" = xyes; then
    AC_DEFINE(HAVE_NULLPTR_T, 1, [Define to 1 if nullptr_t is supported])
  fi
  AC_LANG_POP
])

## Hand crafted for Squid under GPL version 2
AC_DEFUN([AX_CXX_TYPE_UNIQUE_PTR],[
  AC_REQUIRE([AC_PROG_CXX])
  AC_LANG_PUSH([C++])
  AC_MSG_CHECKING([whether std::unique_ptr<T> is supported])
  AC_TRY_COMPILE([#include <memory>],[std::unique_ptr<char> c;], [
    HAVE_UNIQUE_PTR=yes
    AC_MSG_RESULT(yes)], [
    HAVE_UNIQUE_PTR=no
    AC_MSG_RESULT(no)])
  if test "x$HAVE_UNIQUE_PTR" = xyes; then
    AC_DEFINE(HAVE_UNIQUE_PTR, 1, [Define to 1 if std::unique_ptr<T> is supported])
  fi
  AC_LANG_POP
])

## Hand crafted for Squid under GPL version 2
AC_DEFUN([AX_CXX_TYPE_UNIFORM_DISTRIBUTIONS],[
  AC_REQUIRE([AC_PROG_CXX])
  AC_LANG_PUSH([C++])
  AC_MSG_CHECKING([whether std::uniform_int_distribution<T> is supported])
  AC_TRY_COMPILE([#include <random>],[std::uniform_int_distribution<int> c;], [
    HAVE_UNIFORM_INT_DISTRIBUTION=yes
    AC_MSG_RESULT(yes)], [
    HAVE_UNIFORM_INT_DISTRIBUTION=no
    AC_MSG_RESULT(no)])
  if test "x$HAVE_UNIFORM_INT_DISTRIBUTION" = xno; then
    AC_DEFINE(uniform_int_distributon, tr1::uniform_int, [Leave undefined if std::uniform_int_distribution<T> is supported])
  fi
  AC_MSG_CHECKING([whether std::uniform_real_distribution<T> is supported])
  AC_TRY_COMPILE([#include <random>],[std::uniform_real_distribution<double> c;], [
    HAVE_UNIFORM_REAL_DISTRIBUTION=yes
    AC_MSG_RESULT(yes)], [
    HAVE_UNIFORM_REAL_DISTRIBUTION=no
    AC_MSG_RESULT(no)])
  if test "x$HAVE_UNIFORM_REAL_DISTRIBUTION" = xno; then
    AC_DEFINE(uniform_real_distributon, tr1::uniform_real, [Leave undefined if std::uniform_real_distribution<T> is supported])
  fi
  AC_LANG_POP
])
