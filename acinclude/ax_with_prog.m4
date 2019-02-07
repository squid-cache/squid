## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

dnl ===========================================================================
dnl              http://autoconf-archive.cryp.to/ax_with_prog.html
dnl ===========================================================================
dnl
dnl SYNOPSIS
dnl
dnl   AX_WITH_PROG([VARIABLE],[program],[VALUE-IF-NOT-FOUND],[PATH])
dnl
dnl DESCRIPTION
dnl
dnl   Locates an installed program binary, placing the result in the precious
dnl   variable VARIABLE. Accepts a present VARIABLE, then --with-program, and
dnl   failing that searches for program in the given path (which defaults to
dnl   the system path). If program is found, VARIABLE is set to the full path
dnl   of the binary; if it is not found VARIABLE is set to VALUE-IF-NOT-FOUND
dnl   if provided, unchanged otherwise.
dnl
dnl   A typical example could be the following one:
dnl
dnl         AX_WITH_PROG(PERL,perl)
dnl
dnl   NOTE: This macro is based upon the original AX_WITH_PYTHON macro from
dnl   Dustin J. Mitchell <dustin@cs.uchicago.edu>.
dnl
dnl LAST MODIFICATION
dnl
dnl   2008-05-05
dnl
dnl COPYLEFT
dnl
dnl   Copyright (c) 2008 Francesco Salvestrini <salvestrini@users.sourceforge.net>
dnl   Copyright (c) 2008 Dustin J. Mitchell <dustin@cs.uchicago.edu>
dnl
dnl   Copying and distribution of this file, with or without modification, are
dnl   permitted in any medium without royalty provided the copyright notice
dnl   and this notice are preserved.
dnl
AC_DEFUN([AX_WITH_PROG],[
    AC_PREREQ([2.61])

    pushdef([VARIABLE],$1)
    pushdef([EXECUTABLE],$2)
    pushdef([VALUE_IF_NOT_FOUND],$3)
    pushdef([PATH_PROG],$4)

    AC_ARG_VAR(VARIABLE,Absolute path to EXECUTABLE executable)

    AS_IF(test -z "$VARIABLE",[
    	AC_MSG_CHECKING(whether EXECUTABLE executable path has been provided)
        AC_ARG_WITH(EXECUTABLE,AS_HELP_STRING([--with-EXECUTABLE=[[[[PATH]]]]],absolute path to EXECUTABLE executable), [
	    AS_IF([test "$withval" != "yes"],[
	        VARIABLE="$withval"
		AC_MSG_RESULT($VARIABLE)
	    ],[
		VARIABLE=""
	        AC_MSG_RESULT([no])
	    ])
	],[
	    AC_MSG_RESULT([no])
	])

        AS_IF(test -z "$VARIABLE",[
	    AC_PATH_PROG([]VARIABLE[],[]EXECUTABLE[],[]VALUE_IF_NOT_FOUND[],[]PATH_PROG[])
        ])
    ])

    popdef([PATH_PROG])
    popdef([VALUE_IF_NOT_FOUND])
    popdef([EXECUTABLE])
    popdef([VARIABLE])
])
