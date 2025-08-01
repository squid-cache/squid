## Copyright (C) 1996-2025 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

dnl Check the build parameters for a Squid feature with optional modules.
dnl Defines all the Squid required USE_FOO and ENABLE_FOO conditionals
dnl to enable the feature as a whole, and each individual module.
dnl
dnl Parameters for this macro are:
dnl 1) feature name
dnl 2) list of modules in this feature
dnl 3) brief title/description for log entry
dnl 4) long description for --help text
dnl 5) 5) conditions to be tested unless disabled
dnl
AC_DEFUN([SQUID_MODULE],[
  pushdef([FEATURE],$1)
  pushdef([MODULES],[$2])
  pushdef([BASEPATH],m4_translit($srcdir/src/[]FEATURE[],[-],[/]))
  pushdef([CANDIDATES],m4_translit(squid_[]FEATURE[]_candidates,[-],[_]))
  pushdef([ACVARIABLE],m4_translit(enable_[]FEATURE[],[-],[_]))
  pushdef([AMVARIABLE],m4_toupper([]ACVARIABLE[]))
  pushdef([PPVARIABLE],m4_toupper(m4_translit(USE_[]FEATURE[],[-],[_])))
  pushdef([FOUND],m4_toupper(m4_translit([]FEATURE[]_MODULES,[-],[_])))

  CANDIDATES="MODULES"
  FOUND=""

  AH_TEMPLATE([]PPVARIABLE[],[Define to have $3])
  AC_ARG_ENABLE([]FEATURE[],
    AS_HELP_STRING([--enable-FEATURE="list of modules"],[$3. $4]),
    AS_CASE(["$enableval"],
      [""|yes],[
        ACVARIABLE="yes"
        SQUID_LOOK_FOR_MODULES([BASEPATH],CANDIDATES)
      ],
      [no|none],[
        ACVARIABLE="no"
        CANDIDATES=""
      ],
      [
        ACVARIABLE="yes"
        CANDIDATES="$enableval"
      ]
    )
  )
  SQUID_CLEANUP_MODULES_LIST(CANDIDATES)
  SQUID_CHECK_EXISTING_MODULES([BASEPATH],CANDIDATES)
  AS_IF([test "x$ACVARIABLE" != "xno"],[
    $5
  ])
  SQUID_DEFINE_BOOL([]PPVARIABLE[],[${ACVARIABLE:-yes}],[FEATURE modules are expected to be available.])
  AM_CONDITIONAL([]AMVARIABLE[],[test "x$ACVARIABLE" != "xno"])
  m4_foreach_w([MODULE],MODULES,[
    AS_IF([test "x$CANDIDATES[]_[]MODULE" = "xyes"],[
      FOUND="$FOUND MODULE"
      FOUND[]_LIBS="$FOUND[]_LIBS MODULE/lib[]MODULE[].la"
    ])
    SQUID_DEFINE_BOOL([]PPVARIABLE[]_[]m4_toupper([]MODULE[]),[${CANDIDATES[]_[]MODULE:-no}],[FEATURE MODULE is expected to be available.])
    AM_CONDITIONAL([]AMVARIABLE[]_[]m4_toupper([]MODULE[]),[test "x${CANDIDATES[]_[]MODULE:-no}" = "xyes"])
  ])
  AM_CONDITIONAL([]FOUND[],[test "x$ACVARIABLE[]_[]MODULE" = "xyes"])
  AC_SUBST([]FOUND[])
  AC_MSG_NOTICE([FEATURE modules enabled: ${ACVARIABLE:-yes (auto)} ${FOUND:-none}])
  AC_SUBST([]FOUND[]_LIBS)

  popdef([FOUND])
  popdef([PPVARIABLE])
  popdef([AMVARIABLE])
  popdef([ACVARIABLE])
  popdef([CANDIDATES])
  popdef([BASEPATH])
  popdef([MODULES])
  popdef([FEATURE])
])
