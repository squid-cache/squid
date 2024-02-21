## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

dnl save main environment variables to variables to the namespace defined by the
dnl first argument (prefix)
dnl e.g. SQUID_SAVEFLAGS([foo]) will save CFLAGS to foo_CFLAGS etc.
dnl Saved variables are:
dnl CFLAGS, CXXFLAGS, LDFLAGS, LIBS plus any variables specified as
dnl second argument
AC_DEFUN([SQUID_STATE_SAVE],[
# save state, key is $1
$1_CFLAGS="${CFLAGS}"
$1_CXXFLAGS="${CXXFLAGS}"
$1_LDFLAGS="${LDFLAGS}"
$1_LIBS="${LIBS}"
$1_CC="${CC}"
$1_CXX="${CXX}"
$1_CPPFLAGS="${CPPFLAGS}"
$1_squid_saved_vars="$2"
for squid_util_var_tosave in $$1_squid_saved_vars
do
    squid_util_var_tosave2="$1_${squid_util_var_tosave}"
    eval "${squid_util_var_tosave2}=\"${squid_util_var_tosave}\""
done
])

dnl commit the state changes: deleting the temporary state defined in SQUID_STATE_SAVE
dnl with the same prefix. It's not necessary to specify the extra variables passed
dnl to SQUID_STATE_SAVE again, they will be automatically reclaimed.
AC_DEFUN([SQUID_STATE_COMMIT],[
# commit state, key is $1
unset $1_CFLAGS
unset $1_CXXFLAGS
unset $1_LDFLAGS
unset $1_LIBS
unset $1_CC
unset $1_CXX
unset $1_CPPFLAGS
for squid_util_var_tosave in $$1_squid_saved_vars
do
    unset ${squid_util_var_tosave}
done
])

dnl rollback state to the call of SQUID_STATE_SAVE with the same namespace argument.
dnl all temporary state will be cleared, including the custom variables specified
dnl at call time. It's not necessary to explicitly name them, they will be automatically
dnl cleared.
AC_DEFUN([SQUID_STATE_ROLLBACK],[
# rollback state, key is $1
CFLAGS="${$1_CFLAGS}"
CXXFLAGS="${$1_CXXFLAGS}"
LDFLAGS="${$1_LDFLAGS}"
LIBS="${$1_LIBS}"
CC="${$1_CC}"
CXX="${$1_CXX}"
CPPFLAGS="${$1_CPPFLAGS}"
for squid_util_var_tosave in $$1_squid_saved_vars
do
    squid_util_var_tosave2="\$$1_${squid_util_var_tosave}"
    eval "$squid_util_var_tosave=\"${squid_util_var_tosave2}\""
done
SQUID_STATE_COMMIT($1)
])


dnl look for modules in the base-directory supplied as argument.
dnl fill-in the variable pointed-to by the second argument with the
dnl space-separated list of modules
AC_DEFUN([SQUID_LOOK_FOR_MODULES],[
$2=""
for dir in $1/*; do
  module="`basename $dir`"
  AS_IF([test -d "$dir" -a "$module" != "CVS"], $2="$$2 $module")
done
])

dnl remove commas, extra whitespace, and duplicates out of a list.
dnl argument is the name of a variable to be checked and cleaned up
AC_DEFUN([SQUID_CLEANUP_MODULES_LIST],[
squid_cleanup_tmp_outlist=""
for squid_cleanup_tmp in `echo "$$1" | sed -e 's/,/ /g;s/  */ /g'`
do
  squid_cleanup_tmp_dupe=0
  for squid_cleanup_tmp2 in $squid_cleanup_tmp_outlist
  do
    AS_IF([test "$squid_cleanup_tmp" = "$squid_cleanup_tmp2"],[
      squid_cleanup_tmp_dupe=1
      break
    ])
  done
  AS_IF([test $squid_cleanup_tmp_dupe -eq 0],[
    squid_cleanup_tmp_outlist="${squid_cleanup_tmp_outlist} $squid_cleanup_tmp"
  ])
done
$1=`echo "$squid_cleanup_tmp_outlist" | sed -e 's/^ *//'`
unset squid_cleanup_tmp_outlist
unset squid_cleanup_tmp_dupe
unset squid_cleanup_tmp2
unset squid_cleanup_tmp
])

dnl check that all the modules supplied as a whitespace-separated list (second
dnl argument) exist as members of the basedir passed as first argument
dnl call AC_MESG_ERROR if any module does not exist. Also sets individual variables
dnl named $2_modulename to value "yes"
dnl e.g. SQUID_CHECK_EXISTING_MODULES([$srcdir/src/fs],[foo_module_candidates])
dnl where $foo_module_candidates is "foo bar gazonk"
dnl checks whether $srcdir/src/fs/{foo,bar,gazonk} exist and are all dirs
dnl AND sets $foo_module_candidates_foo, $foo_module_candidates_bar
dnl and $foo_module_candidates_gazonk to "yes"
AC_DEFUN([SQUID_CHECK_EXISTING_MODULES],[
  for squid_module_check_exist_tmp in $$2
  do
    AS_IF([test -d "$1/$squid_module_check_exist_tmp"],[
      eval "$2_$squid_module_check_exist_tmp='yes'"
      #echo "defining $2_$squid_module_check_exist_tmp"
    ],[
      AC_MSG_ERROR([$squid_module_check_exist_tmp not found in $1])
    ])
  done
])

dnl Check the requirements for a helper to be built.
dnl Requirements can be provided as an M4/autoconf script (required.m4)
dnl which sets a variable BUILD_HELPER to the name of the helper
dnl directory if the helper is to be added to the built SUBDIRS list.
dnl Or, a shell script (config.test) which returns 0 exit status if
dnl the helper is to be built.
AC_DEFUN([SQUID_CHECK_HELPER],[
  AS_IF([test "x$helper" = "x$1"],[
    AS_IF([test -d "$srcdir/src/$2/$1"],[
      dnl find helpers providing autoconf M4 requirement checks
      m4_include(m4_echo([src/$2/$1/required.m4]))
      dnl find helpers not yet converted to autoconf (or third party drop-in's)
      AS_IF([test -f "$srcdir/src/$2/$1/config.test" && sh "$srcdir/src/$2/$1/config.test" "$squid_host_os"],[
        BUILD_HELPER="$1"
      ])
      AS_IF(
        [test "x$BUILD_HELPER" = "x$1"],
          squid_cv_BUILD_HELPERS="$squid_cv_BUILD_HELPERS $BUILD_HELPER",
        [test "x$auto_helpers" = "xyes"],
          AC_MSG_NOTICE([helper $2/$1 ... found but cannot be built]),
        [AC_MSG_ERROR([required helper $2/$1 ... found but cannot be built])]
      )
    ],[
      AC_MSG_ERROR([helper $2/$1 ... not found])
    ])
    unset BUILD_HELPER
  ])
])

dnl macro to simplify and deduplicate logic in all helpers.m4 files
dnl Usage:
dnl SQUID_HELPER_FEATURE_CHECK(var_name, default, path, checks)
dnl
AC_DEFUN([SQUID_HELPER_FEATURE_CHECK],[
  auto_helpers=no
  squid_cv_BUILD_HELPERS=""
  AS_IF([test "x$enable_$1" = "x"],[enable_$1=$2],
    [test "x$enable_$1" = "xnone"],[enable_$1=""])
  AS_IF([test "x$enable_$1" = "xyes"],[
    SQUID_LOOK_FOR_MODULES([$srcdir/src/$3], enable_$1)
    auto_helpers=yes
  ])
  SQUID_CLEANUP_MODULES_LIST([enable_$1])
  AC_MSG_NOTICE([checking $3 helpers: $enable_$1])
  AS_IF([test "x$enable_$1" != "xno" -a "x$enable_$1" != "x"],[
    SQUID_CHECK_EXISTING_MODULES([$srcdir/src/$3],[enable_$1])
    for helper in $enable_$1 ; do
      $4
    done
  ])
  AC_MSG_NOTICE([$3 helpers to be built: $squid_cv_BUILD_HELPERS])
  unset auto_helpers
])

dnl lowercases the contents of the variable whose name is passed by argument
AC_DEFUN([SQUID_TOLOWER_VAR_CONTENTS],[
  $1=`echo $$1|tr ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz`
])

dnl uppercases the contents of the variable whose name is passed by argument
AC_DEFUN([SQUID_TOUPPER_VAR_CONTENTS],[
  $1=`echo $$1|tr abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ`
])

dnl like AC_DEFINE, but it defines the value to 0 or 1 using well-known textual
dnl conventions:
dnl 1: "yes", "true", 1
dnl 0: "no" , "false", 0, ""
dnl aborts with an error for unknown values
AC_DEFUN([SQUID_DEFINE_BOOL],[
squid_tmp_define=""
AS_CASE(["$2"],
  [yes|true|1],[squid_tmp_define="1"],
  [no|false|0|""],[squid_tmp_define="0"],
  [AC_MSG_ERROR([SQUID_DEFINE[]_BOOL: unrecognized value for $1: '$2'])]
)
ifelse([$#],3,
  [AC_DEFINE_UNQUOTED([$1], [$squid_tmp_define],[$3])],
  [AC_DEFINE_UNQUOTED([$1], [$squid_tmp_define])]
)
unset squid_tmp_define
])

dnl aborts with an error specified as the second argument if the first argument doesn't
dnl contain either "yes" or "no"
AC_DEFUN([SQUID_YESNO],[
  AS_IF([test "$1" != "yes" -a "$1" != "no"],[AC_MSG_ERROR([Bad argument for $2: "$1". Expecting "yes", "no", or no argument.])])
])

dnl check the build parameters for a library to auto-enable
dnl Parameters for this macro are:
dnl 1) binary library name (without 'lib' prefix)
dnl 2) name of the library for human reading
dnl 3) prefix used for pkg-check macros
AC_DEFUN([SQUID_AUTO_LIB],[
  AC_ARG_WITH([$1],AS_HELP_STRING([--without-$1],[Compile without the $2 library.]),[
    AS_CASE(["$withval"],[yes|no],,[
      AS_IF([test ! -d "$withval"],AC_MSG_ERROR([--with-$1 path does not point to a directory]))
      m4_translit([with_$1], [-+.], [___])=yes
      AS_IF([test -d "$withval/lib64"],[$3_PATH+="-L$withval/lib64"])
      AS_IF([test -d "$withval/lib"],[$3_PATH+="-L$withval/lib"])
      AS_IF([test -d "$withval/include"],[$3_CFLAGS+="-I$withval/include"])
    ])
  ])
])
dnl same as SQUID_AUTO_LIB but for default-disabled libraries
AC_DEFUN([SQUID_OPTIONAL_LIB],[
  AC_ARG_WITH([$1],AS_HELP_STRING([--with-$1],[Compile with the $2 library.]),[
    AS_CASE(["$withval"],[yes|no],,[
      AS_IF([test ! -d "$withval"],AC_MSG_ERROR([--with-$1 path does not point to a directory]))
      m4_translit([with_$1], [-+.], [___])=yes
      AS_IF([test -d "$withval/lib64"],[$3_PATH+="-L$withval/lib64"])
      AS_IF([test -d "$withval/lib"],[$3_PATH+="-L$withval/lib"])
      AS_IF([test -d "$withval/include"],[$3_CFLAGS+="-I$withval/include"])
    ])
  ])
  AS_IF([test "x$withval" = "x"],[m4_translit([with_$1], [-+.], [___])=no])
])

AC_DEFUN([SQUID_EMBED_BUILD_INFO],[
  AC_ARG_ENABLE([build-info],
    AS_HELP_STRING([--enable-build-info="build info string"],
      [Add an additional string in the output of "squid -v".
       Default is not to add anything. If the string is not specified,
       tries to determine nick and revision number of the current
       bazaar branch]),[
    AS_CASE(["$enableval"],
      [no],[:],
      [yes],[
        AS_IF([test -d "${srcdir}/.bzr"],[
          AC_PATH_PROG(BZR,bzr,$FALSE)
          squid_bzr_branch_nick=`cd ${srcdir} && ${BZR} nick 2>/dev/null`
          AS_IF([test $? -eq 0 -a "x$squid_bzr_branch_nick" != "x"],[
            squid_bzr_branch_revno=`cd ${srcdir} && ${BZR} revno 2>/dev/null | sed 's/\"//g'`
          ])
          AS_IF([test $? -eq 0 -a "x$squid_bzr_branch_revno" != "x"],[
            sh -c "cd ${srcdir} && ${BZR} diff 2>&1 >/dev/null"
            AS_IF([test $? -eq 1],[
              squid_bzr_branch_revno="$squid_bzr_branch_revno+changes"
            ])
          ])
          AS_IF([test "x$squid_bzr_branch_revno" != "x"],[
            squid_build_info="Built branch: ${squid_bzr_branch_nick}-r${squid_bzr_branch_revno}"
          ])
        ])
      ],
      [squid_build_info=$enableval]
    )
  ])
  AC_DEFINE_UNQUOTED([SQUID_BUILD_INFO],["$squid_build_info"],
     [Squid extended build info field for "squid -v" output])
])

dnl like AC_SEARCH_LIBS, with an extra argument which is
dnl a prefix to the test program
AC_DEFUN([SQUID_SEARCH_LIBS],
[AS_VAR_PUSHDEF([ac_Search], [ac_cv_search_$1])dnl
AC_CACHE_CHECK([for library containing $1], [ac_Search],
[ac_func_search_save_LIBS=$LIBS
AC_LANG_CONFTEST([AC_LANG_PROGRAM([$6], [$1()])])
for ac_lib in '' $2; do
  AS_IF([test -z "$ac_lib"],[
    ac_res="none required"
  ],[
    ac_res=-l$ac_lib
    LIBS="-l$ac_lib $5 $ac_func_search_save_LIBS"
  ])
  AC_LINK_IFELSE([AC_LANG_PROGRAM([],[])], [AS_VAR_SET([ac_Search], [$ac_res])])
  AS_VAR_SET_IF([ac_Search], [break])
done
AS_VAR_SET_IF([ac_Search], , [AS_VAR_SET([ac_Search], [no])])
rm conftest.$ac_ext
LIBS=$ac_func_search_save_LIBS])
ac_res=AS_VAR_GET([ac_Search])
AS_IF([test "$ac_res" != no],[
  AS_IF([test "$ac_res" != "none required"],[LIBS="$ac_res $LIBS"])
  $3],[$4])
AS_VAR_POPDEF([ac_Search])dnl
])

dnl Check for Cyrus SASL
AC_DEFUN([SQUID_CHECK_SASL],[
  squid_cv_check_sasl="auto"
  AC_CHECK_HEADERS([sasl/sasl.h sasl.h])
  AC_CHECK_LIB(sasl2,sasl_errstring,[LIBSASL="-lsasl2"],[
    AC_CHECK_LIB(sasl,sasl_errstring,[LIBSASL="-lsasl"], [
      squid_cv_check_sasl="no"
    ])
  ])
  AS_IF([test "$squid_host_os" = "darwin"],[
    AS_IF([test "$ac_cv_lib_sasl2_sasl_errstring" = "yes"],[
      AC_DEFINE(HAVE_SASL_DARWIN,1,[Define to 1 if Mac Darwin without sasl.h])
      echo "checking for MAC Darwin without sasl.h ... yes"
      squid_cv_check_sasl="yes"
    ],[
      echo "checking for MAC Darwin without sasl.h ... no"
      squid_cv_check_sasl="no"
    ])
  ])
  AS_IF([test "x$squid_cv_check_sasl" = "xno"],[
    AC_MSG_WARN([Neither SASL nor SASL2 found])
  ],[
    squid_cv_check_sasl="yes"
  ])
  AC_SUBST(LIBSASL)
])
