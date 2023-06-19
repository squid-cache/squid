## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

dnl check which printf code to use for a type
dnl $1 - the type being checked
dnl $2 - the PRIxxx macro to define
dnl $3 - a list of possible codes
AC_DEFUN([SQUID_CHECK_PRINTF_CODES],[
  AH_TEMPLATE([$2],[printf display of $1])
  AC_CACHE_CHECK([which printf code displays $1],
                 [squid_cv_printf_$2],[
    SQUID_STATE_SAVE($2)
    CXXFLAGS="$CXXFLAGS -Werror=format"
    for code in $3; do
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <cstdio>
      ]],[[$1 val={};printf("%$code", val);]])],[
        squid_cv_printf_$2=$code
        break
      ])
    done
    SQUID_STATE_ROLLBACK($2)
  ])
  AS_IF([test -z "$squid_cv_printf_$2"],
    AC_MSG_FAILURE([no printf support for $1 (tried: $3)])
  )
  AC_DEFINE_UNQUOTED($2,["$squid_cv_printf_$2"])
  AC_MSG_RESULT($squid_cv_printf_$2)
])
