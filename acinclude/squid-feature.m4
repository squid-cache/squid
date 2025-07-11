## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

dnl check the build parameters for a Squid feature
dnl Parameters for this macro are:
dnl 1) feature name
dnl 2) default: ON/OFF
dnl 3) brief title/description for log entry
dnl 4) long description for --help text
dnl 5) conditions to be tested
AC_DEFUN([SQUID_FEATURE],[

  pushdef([FEATURE],$1)
  pushdef([DEFAULT],m4_if([$2],[on],yes,no))
  pushdef([INVERT],m4_if([$2],[on],disable,enable))
  pushdef([ACVARIABLE],m4_translit(enable_[]FEATURE[],[-+.],[___]))
  pushdef([AMVARIABLE],m4_toupper([]ACVARIABLE[]))
  pushdef([PPVARIABLE],m4_toupper(m4_translit(USE_[]FEATURE[],[-+.],[___])))

  AH_TEMPLATE([]PPVARIABLE[],[Define to have $3])
  AC_ARG_ENABLE([]FEATURE[],
    AS_HELP_STRING([--INVERT-FEATURE],[$3. $4]),
    SQUID_YESNO([$enableval],[--INVERT-FEATURE])
  )
  AS_IF([test "x${ACVARIABLE:=DEFAULT}" != "xno"],[
    $5
  ])
  SQUID_DEFINE_BOOL([]PPVARIABLE[],[${ACVARIABLE:=DEFAULT}])
  AM_CONDITIONAL([]AMVARIABLE[],[test "x$ACVARIABLE" != "xno"])
  AC_MSG_NOTICE([$3 enabled: ${ACVARIABLE:=DEFAULT (auto)}])

  popdef([PPVARIABLE])
  popdef([AMVARIABLE])
  popdef([ACVARIABLE])
  popdef([INVERT])
  popdef([DEFAULT])
  popdef([FEATURE])
])
