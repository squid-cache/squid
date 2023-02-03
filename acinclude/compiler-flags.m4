## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
    AC_LINK_IFELSE([AC_LANG_PROGRAM([],[])],[$1=yes],[$1=no])
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
    AS_IF([test "x$$1" != "xno"],[
      CFLAGS="$CFLAGS $2"
      CXXFLAGS="$CXXFLAGS $2"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM($3,$4)],[$1=yes],[$1=no],[$1=no])
    ])
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
  AS_IF([test -z "$squid_cv_compiler"],[
   AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
#if !defined(__SUNPRO_C) && !defined(__SUNPRO_CC)
#error "not sunpro c"
#endif
    ]])],[squid_cv_compiler="sunstudio"],[])
  ])
  dnl Intel CC
  AS_IF([test -z "$squid_cv_compiler"],[
   AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
#if !defined(__ICC)
#error "not Intel(R) C++ Compiler"
#endif
    ]])],[squid_cv_compiler="icc"],[])
  ])
  dnl clang
  AS_IF([test -z "$squid_cv_compiler"],[
   AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
#if !defined(__clang__)
#error "not clang"
#endif
    ]])],[squid_cv_compiler="clang"],[])
  ])
  dnl microsoft visual c++
  AS_IF([test -z "$squid_cv_compiler"],[
   AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
#if !defined(_MSC_VER)
#error "not Microsoft VC++"
#endif
    ]])],[squid_cv_compiler="msvc"],[])
  ])
  dnl gcc. MUST BE LAST as many other compilers also define it for compatibility
  AS_IF([test -z "$squid_cv_compiler"],[
   AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
#if !defined(__GNUC__)
#error "not gcc"
#endif
    ]])],[squid_cv_compiler="gcc"],[])
  ])
  dnl end of block to be repeated
  AS_IF([test -z "$squid_cv_compiler"],[squid_cv_compiler="none"])
  ]) dnl AC_CACHE_CHECK
 ]) dnl AC_DEFUN

dnl SQUID_CC_ADD_CXXFLAG_WARNING_IF_SUPPORTED helper
dnl $1 is a compiler warning option (e.g., -Wall).
dnl $2 is a "squid_cv_cc_arg<snake_case_warning_name_equivalent>" string.
AC_DEFUN([SQUID_CC_ADD_CXXFLAG_WARNING_IF_SUPPORTED_],[
  AC_REQUIRE([SQUID_CC_GUESS_VARIANT])
  SQUID_STATE_SAVE([CXXARGTEST])
  CXXFLAGS="$CXXFLAGS $SQUID_CXXFLAGS"
  AS_CASE([$squid_cv_compiler],
    [gcc],[
      # Testing with -Werror -Wfoobar does not work well because GCC ignores
      # unsupported _negative_ options, so we test with -Werror=foobar instead
      # (where "foobar" is a name of a warning that may be given to us in
      # positive -Wfoobar or negative -Wno-foobar form).
      SQUID_CC_CHECK_ARGUMENT([$2],m4_bpatsubst([$1],[^-W],[-Werror=]))
    ],
    [clang],[
      # Testing with -Werror=foobar (as we do for GCC above) is useless
      # because clang does not recognize that pattern as a -Werror
      # specialization, so we test with -Werror -Wfoobar instead.
      SQUID_CC_CHECK_ARGUMENT([$2],[-Werror $1])
    ],
    [
      # We lack code to reliably test whether this compiler supports a given
      # warning. Some compilers (e.g, icc) succeed with bogus warning names.
      # If $squid_cv_cxx_option_werror is set, we add that option because it
      # helps in some (but not all) known cases.
      SQUID_CC_CHECK_ARGUMENT([$2],[$squid_cv_cxx_option_werror $1])
    ]
  )
  SQUID_STATE_ROLLBACK([CXXARGTEST])
  AS_IF([test "x${$2}" = "xyes"],[SQUID_CXXFLAGS="$SQUID_CXXFLAGS $1"])
])

dnl The argument is a compiler warning option (e.g. -Wall). If linking a
dnl warning-free program while using the given warning succeeds, then the
dnl option is added to SQUID_CXXFLAGS in the same order as calls to the macro.
AC_DEFUN([SQUID_CC_ADD_CXXFLAG_WARNING_IF_SUPPORTED],[
  SQUID_CC_ADD_CXXFLAG_WARNING_IF_SUPPORTED_($1,m4_bpatsubst(m4_tolower([squid_cv_cc_arg$1]),[[^a-zA-Z0-9_]],[_]))
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
  AS_CASE([$squid_cv_compiler],
    [gcc],[
      squid_cv_cc_option_werror="-Werror"
      squid_cv_cxx_option_werror="-Werror"
      squid_cv_cc_option_wall="-Wall"
      squid_cv_cc_option_optimize="-O3"
      squid_cv_cc_arg_pipe="-pipe"
    ],
    [sunstudio],[
      squid_cv_cc_option_werror="-errwarn=%all -errtags"
      squid_cv_cxx_option_werror="-errwarn=%all,no%badargtype2w,no%wbadinit,no%wbadasg -errtags"
      squid_cv_cc_option_wall="+w"
      squid_cv_cc_option_optimize="-fast"
      squid_cv_cc_arg_pipe=""
    ],
    [clang],[
      squid_cv_cxx_option_werror="-Werror"
      squid_cv_cc_option_werror="$squid_cv_cxx_option_werror"
      squid_cv_cc_option_wall="-Wall"
      squid_cv_cc_option_optimize="-O2"
      squid_cv_cc_arg_pipe=""
    ],
    [icc],[
      squid_cv_cxx_option_werror="-Werror"
      squid_cv_cc_option_werror="$squid_cv_cxx_option_werror"
      squid_cv_cc_option_wall="-Wall"
      squid_cv_cc_option_optimize="-O2"
      squid_cv_cc_arg_pipe=""
    ],
    [
      squid_cv_cxx_option_werror=""
      squid_cv_cc_option_werror=""
      squid_cv_cc_option_wall=""
      squid_cv_cc_option_optimize="-O"
      squid_cv_cc_arg_pipe=""
    ]
  )
  AC_MSG_RESULT([$squid_cv_compiler])
])
