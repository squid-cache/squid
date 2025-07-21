## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

dnl check the build parameters for a Squid module.
dnl
dnl Parameters for this macro are:
dnl 1) feature name
dnl 2) list of modules in this feature
dnl 3) brief title/description for log entry
dnl 4) long description for --help text
dnl 5) conditions to be tested
dnl
AC_DEFUN([SQUID_MODULE],[
  pushdef([FEATURE],$1)
  pushdef([MODULES],[$2])
  pushdef([CANDIDATES],m4_translit(squid_[]FEATURE[]_candidates,[-+.],[___]))
  pushdef([ACVARIABLE],m4_translit(enable_[]FEATURE[],[-+.],[___]))
  pushdef([AMVARIABLE],m4_toupper([]ACVARIABLE[]))
  pushdef([PPVARIABLE],m4_toupper(m4_translit(USE_[]FEATURE[],[-+.],[___])))

  CANDIDATES=MODULES

  AH_TEMPLATE([]PPVARIABLE[],[Define to have $3])
  AC_ARG_ENABLE([]FEATURE[],
    AS_HELP_STRING([--enable-FEATURE="list of modules"],[$3. $4]),
    AS_CASE(["$enableval"],
      [""|yes],[ACVARIABLE="yes"],
      [no|none],[ACVARIABLE="no"],
      [CANDIDATES="$enableval"]
    )
  )
  SQUID_CLEANUP_MODULES_LIST(CANDIDATES)
  $5
  SQUID_DEFINE_BOOL([]PPVARIABLE[],[${ACVARIABLE:-yes}],[FEATURE modules are expected to be available.])
  AM_CONDITIONAL([]AMVARIABLE[],[test "x$ACVARIABLE" != "xno"])
  AC_MSG_NOTICE([$2 modules enabled: ${ACVARIABLE:-yes (auto)} ${CANDIDATES:-none}])

  popdef([PPVARIABLE])
  popdef([AMVARIABLE])
  popdef([ACVARIABLE])
  popdef([CANDIDATES])
  popdef([MODULES])
  popdef([FEATURE])
])
