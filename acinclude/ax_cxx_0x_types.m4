## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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
  if test "x$HAVE_NULLPTR" = xno; then
    AC_DEFINE(nullptr, NULL, [Leave undefined if nullptr is supported])
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
  if test "x$HAVE_UNIQUE_PTR" = xno; then
    AC_DEFINE(unique_ptr, auto_ptr, [Leave undefined if std::unique_ptr<T> is supported])
  fi
  if test "x$HAVE_UNIQUE_PTR" = xyes; then
    AC_DEFINE(HAVE_UNIQUE_PTR, 1, [Define to 1 if std::unique_ptr<T> is supported])
  fi
  AC_LANG_POP
])

## Hand crafted for Squid under GPL version 2
AC_DEFUN([AX_CXX_TYPE_UNIFORM_DISTRIBUTIONS],[
  AC_REQUIRE([AC_PROG_CXX])
  AC_LANG_PUSH([C++])
  AC_CHECK_HEADERS(tr1/random)
  AC_CACHE_CHECK([whether std::uniform_int_distribution<T> is supported],
                 [squid_cv_std_uniform_int_distribution_works],[
    AC_TRY_COMPILE([#include <random>],[std::uniform_int_distribution<int> c;],
      [squid_cv_std_uniform_int_distribution_works=yes],
      [squid_cv_std_uniform_int_distribution_works=no])
    ])
  SQUID_DEFINE_BOOL([HAVE_STD_UNIFORM_INT_DISTRIBUTION],
      [$squid_cv_std_uniform_int_distribution_works],
      [Define if c++11 std::uniform_int_distribution is supported])

  AC_CACHE_CHECK([whether std::uniform_real_distribution<T> is supported],
                 [squid_cv_std_uniform_real_distribution_works],[
    AC_REQUIRE([AC_PROG_CXX])
    AC_LANG_PUSH([C++])
    AC_TRY_COMPILE([#include <random>],[std::uniform_real_distribution<double> c;],
      [squid_cv_std_uniform_real_distribution_works=yes],
      [squid_cv_std_uniform_real_distribution_works=no])
    ])
  SQUID_DEFINE_BOOL([HAVE_STD_UNIFORM_REAL_DISTRIBUTION],
      [$squid_cv_std_uniform_real_distribution_works],
      [Define if c++11 std::uniform_real_distribution is supported])

  AC_LANG_POP
])

## SQUID_CXX_STD_UNDERLYING_TYPE
## checks whether the std::underlying_type<enumType>::type trait exists
AC_DEFUN([SQUID_CXX_STD_UNDERLYING_TYPE],[
  AC_CACHE_CHECK([whether compiler supports std::underlying_type],
    [squid_cv_have_std_underlying_type],[
      AC_REQUIRE([AC_PROG_CXX])
      AC_LANG_PUSH([C++])
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([
#include <type_traits>
enum class testEnum { one, two, three };
        ],[
        std::underlying_type<testEnum>::type testNum = 0;
        ])],
        [squid_cv_have_std_underlying_type=yes],
        [squid_cv_have_std_underlying_type=no])
      AC_LANG_POP
  ])
  SQUID_DEFINE_BOOL([HAVE_STD_UNDERLYING_TYPE],
     [$squid_cv_have_std_underlying_type],
     [Define if stdlibc support std::underlying_type for enums])
])
