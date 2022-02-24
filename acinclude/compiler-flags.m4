## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# check if the compiler accepts a supplied flag
# first argument is the variable containing the result 
# (will be set to "yes" or "no")
# second argument is the flag to be tested, verbatim
#
AC_DEFUN([SQUID_CC_CHECK_ARGUMENT],[
  AC_CACHE_CHECK([whether compiler accepts $2],[$1],
  [
    AC_REQUIRE([AC_PROG_CC])
    SQUID_STATE_SAVE([ARGCHECK])
    CFLAGS="$CFLAGS $2"
    CXXFLAGS="$CXXFLAGS $2"
    AC_TRY_LINK([],[int foo; ],
      [$1=yes],[$1=no])
    SQUID_STATE_ROLLBACK([ARGCHECK])
  ])
])

# Check if the compiler requires a supplied flag to build a test program.
# When cross-compiling set flags explicitly.
#
# first argument is the variable containing the result 
# (will be set to "yes" or "no")
# second argument is the flag to be tested, verbatim
# third is the #include and global setup for test program, verbatim
# fourth is the test program to compile, verbatim
#
AC_DEFUN([SQUID_CC_REQUIRE_ARGUMENT],[
  AC_CACHE_CHECK([whether compiler requires $2],[$1],
  [{
    AC_REQUIRE([AC_PROG_CC])
    SQUID_STATE_SAVE([ARGREQ])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM($3,$4)],[$1=no],[],[$1=no])
    if test "x$$1" != "xno" ; then
      CFLAGS="$CFLAGS $2"
      CXXFLAGS="$CXXFLAGS $2"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM($3,$4)],[$1=yes],[$1=no],[$1=no])
    fi
    SQUID_STATE_ROLLBACK([ARGREQ])
  }])
])

# detect what kind of compiler we're using, either by using hints from
# autoconf itself, or by using predefined preprocessor macros
# sets the variable squid_cv_compiler to one of
#  - gcc
#  - sunstudio
#  - none (undetected)
# 
AC_DEFUN([SQUID_CC_GUESS_VARIANT], [ 
 AC_CACHE_CHECK([what kind of compiler we're using],[squid_cv_compiler],
 [
  AC_REQUIRE([AC_PROG_CC])
  dnl repeat the next block for each compiler, changing the
  dnl preprocessor definition so that it depends on platform-specific
  dnl predefined macros
  dnl SunPro CC
  if test -z "$squid_cv_compiler" ; then
   AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
#if !defined(__SUNPRO_C) && !defined(__SUNPRO_CC)
#error "not sunpro c"
#endif
    ]])],[squid_cv_compiler="sunstudio"],[])
  fi
  dnl Intel CC
  if test -z "$squid_cv_compiler" ; then
   AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
#if !defined(__ICC)
#error "not Intel(R) C++ Compiler"
#endif
    ]])],[squid_cv_compiler="icc"],[])
  fi
  dnl clang
  if test -z "$squid_cv_compiler" ; then
   AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
#if !defined(__clang__)
#error "not clang"
#endif
    ]])],[squid_cv_compiler="clang"],[])
  fi
  dnl microsoft visual c++
  if test -z "$squid_cv_compiler" ; then
   AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
#if !defined(_MSC_VER)
#error "not Microsoft VC++"
#endif
    ]])],[squid_cv_compiler="msvc"],[])
  fi
  dnl gcc. MUST BE LAST as many other compilers also define it for compatibility
  if test -z "$squid_cv_compiler" ; then
   AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
#if !defined(__GNUC__)
#error "not gcc"
#endif
    ]])],[squid_cv_compiler="gcc"],[])
  fi
  dnl end of block to be repeated
  if test -z "$squid_cv_compiler" ; then
   squid_cv_compiler="none"
  fi
  ]) dnl AC_CACHE_CHECK
 ]) dnl AC_DEFUN

AC_DEFUN([SQUID_CC_ADD_CXXFLAG_IF_SUPPORTED_INTERNAL],[
  SQUID_STATE_SAVE([CXXARGTEST])
  CXXFLAGS="$CXXFLAGS $SQUID_CXXFLAGS"
  SQUID_CC_CHECK_ARGUMENT([$2],[$1])
  SQUID_STATE_ROLLBACK([CXXARGTEST])
  AS_IF([test "x${$2}" = "xyes"],[SQUID_CXXFLAGS="$SQUID_CXXFLAGS $1"])
])

dnl argument is a compiler flag. It will be attempted, and if suppported
dnl it will be added to SQUID_CXXFLAGS in the same order as calls to the macro
AC_DEFUN([SQUID_CC_ADD_CXXFLAG_IF_SUPPORTED],[
  SQUID_CC_ADD_CXXFLAG_IF_SUPPORTED_INTERNAL($1,m4_bpatsubst(m4_tolower([squid_cv_cc_arg$1]),[[^a-zA-Z0-9_]], [_]))
])

# define the flag to use to have the compiler treat warnings as errors
# requirs SQUID_CC_GUESS_VARIANT
# Sets a few variables to contain some compiler-dependent command line
# options, or to empty strings if the compiler doesn't support those
# options
# They are (with their GCC equivalent):
# squid_cv_cc_option_werror   (-Werror)
# squid_cv_cxx_option_werror  (-Werror)
# squid_cv_cc_option_wall     (-Wall)
# squid_cv_cc_option_optimize (-O3)
# 
AC_DEFUN([SQUID_CC_GUESS_OPTIONS], [
 AC_REQUIRE([SQUID_CC_GUESS_VARIANT])
 AC_MSG_CHECKING([for compiler variant])
 case "$squid_cv_compiler" in
  gcc) 
   squid_cv_cc_option_werror="-Werror" 
   squid_cv_cxx_option_werror="-Werror" 
   squid_cv_cc_option_wall="-Wall"
   squid_cv_cc_option_optimize="-O3"
   squid_cv_cc_arg_pipe="-pipe"
   ;;
  sunstudio) 
   squid_cv_cc_option_werror="-errwarn=%all -errtags" 
   squid_cv_cxx_option_werror="-errwarn=%all,no%badargtype2w,no%wbadinit,no%wbadasg -errtags" 
   squid_cv_cc_option_wall="+w"
   squid_cv_cc_option_optimize="-fast"
   squid_cv_cc_arg_pipe=""
   ;;
  clang) 
   squid_cv_cxx_option_werror="-Werror"
   squid_cv_cc_option_werror="$squid_cv_cxx_option_werror"
   squid_cv_cc_option_wall="-Wall"
   squid_cv_cc_option_optimize="-O2"
   squid_cv_cc_arg_pipe=""
   ;;
  icc) 
   squid_cv_cxx_option_werror="-Werror"
   squid_cv_cc_option_werror="$squid_cv_cxx_option_werror" 
   squid_cv_cc_option_wall="-Wall"
   squid_cv_cc_option_optimize="-O2"
   squid_cv_cc_arg_pipe=""
   ;;
  *) 
   squid_cv_cxx_option_werror="" 
   squid_cv_cc_option_werror="" 
   squid_cv_cc_option_wall=""
   squid_cv_cc_option_optimize="-O"
   squid_cv_cc_arg_pipe=""
   ;;
 esac
 AC_MSG_RESULT([$squid_cv_compiler])
])
