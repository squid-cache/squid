dnl @synopsis AC_CXX_RTTI
dnl
dnl If the compiler supports Run-Time Type Identification (typeinfo
dnl header and typeid keyword), define HAVE_RTTI.
dnl
dnl @version $Id: aclocal-cxx.m4,v 1.1 2004/09/27 17:30:14 hno Exp $
dnl @author Luc Maisonobe
dnl
AC_DEFUN([AC_CXX_RTTI],
[AC_CACHE_CHECK(whether the compiler supports Run-Time Type Identification,
ac_cv_cxx_rtti,
[AC_LANG_SAVE
 AC_LANG_CPLUSPLUS
 AC_TRY_COMPILE([#include <typeinfo>
class Base { public :
             Base () {}
             virtual int f () { return 0; }
           };
class Derived : public Base { public :
                              Derived () {}
                              virtual int f () { return 1; }
                            };
],[Derived d;
Base *ptr = &d;
return typeid (*ptr) == typeid (Derived);
],
 ac_cv_cxx_rtti=yes, ac_cv_cxx_rtti=no)
 AC_LANG_RESTORE
])
if test "$ac_cv_cxx_rtti" = yes; then
  AC_DEFINE(HAVE_RTTI,1,
            [define if the compiler supports Run-Time Type Identification])
fi
])

dnl @synopsis AX_CXX_GCC_ABI_DEMANGLE
dnl
dnl If the compiler supports GCC C++ ABI name demangling (has header cxxabi.h 
dnl and abi::__cxa_demangle() function), define HAVE_GCC_ABI_DEMANGLE
dnl
dnl Adapted from AC_CXX_RTTI by Luc Maisonobe
dnl
dnl @version $Id: aclocal-cxx.m4,v 1.1 2004/09/27 17:30:14 hno Exp $
dnl @author Neil Ferguson <nferguso@eso.org>
dnl
AC_DEFUN([AX_CXX_GCC_ABI_DEMANGLE],
[AC_CACHE_CHECK(whether the compiler supports GCC C++ ABI name demangling, 
ac_cv_cxx_gcc_abi_demangle,
[AC_LANG_SAVE
 AC_LANG_CPLUSPLUS
 AC_TRY_COMPILE([#include <typeinfo>
#include <cxxabi.h>
#include <string>

template<typename TYPE>
class A {};
],[A<int> instance;
int status = 0;
char* c_name = 0;

c_name = abi::__cxa_demangle(typeid(instance).name(), 0, 0, &status);
        
std::string name(c_name);
free(c_name);

return name == "A<int>";
],
 ac_cv_cxx_gcc_abi_demangle=yes, ac_cv_cxx_gcc_abi_demangle=no)
 AC_LANG_RESTORE
])
if test "$ac_cv_cxx_gcc_abi_demangle" = yes; then
  AC_DEFINE(HAVE_GCC_ABI_DEMANGLE,1,
            [define if the compiler supports GCC C++ ABI name demangling]) 
fi
])

dnl @synopsis AC_CXX_STRING_COMPARE_STRING_FIRST
dnl
dnl If the standard library string::compare() function takes the
dnl string as its first argument, define FUNC_STRING_COMPARE_STRING_FIRST to 1.
dnl
dnl @author Steven Robbins
dnl
AC_DEFUN([AC_CXX_STRING_COMPARE_STRING_FIRST],
[AC_CACHE_CHECK(whether std::string::compare takes a string in argument 1,
ac_cv_cxx_string_compare_string_first,
[AC_REQUIRE([AC_CXX_NAMESPACES])
 AC_LANG_SAVE
 AC_LANG_CPLUSPLUS
 AC_TRY_COMPILE([#include <string>
#ifdef HAVE_NAMESPACES
using namespace std;
#endif],[string x("hi"); string y("h");
return x.compare(y,0,1) == 0;],
 ac_cv_cxx_string_compare_string_first=yes, 
 ac_cv_cxx_string_compare_string_first=no)
 AC_LANG_RESTORE
])
if test "$ac_cv_cxx_string_compare_string_first" = yes; then
  AC_DEFINE(FUNC_STRING_COMPARE_STRING_FIRST,1,
            [define if library uses std::string::compare(string,pos,n)])
fi
])

dnl @synopsis AC_CXX_NAMESPACES
dnl
dnl If the compiler can prevent names clashes using namespaces, define
dnl HAVE_NAMESPACES.
dnl
dnl @version $Id: aclocal-cxx.m4,v 1.1 2004/09/27 17:30:14 hno Exp $
dnl @author Luc Maisonobe
dnl
AC_DEFUN([AC_CXX_NAMESPACES],
[AC_CACHE_CHECK(whether the compiler implements namespaces,
ac_cv_cxx_namespaces,
[AC_LANG_SAVE
 AC_LANG_CPLUSPLUS
 AC_TRY_COMPILE([namespace Outer { namespace Inner { int i = 0; }}],
                [using namespace Outer::Inner; return i;],
 ac_cv_cxx_namespaces=yes, ac_cv_cxx_namespaces=no)
 AC_LANG_RESTORE
])
if test "$ac_cv_cxx_namespaces" = yes; then
  AC_DEFINE(HAVE_NAMESPACES,1,[define to 1 if the compiler implements namespaces])
fi
])

dnl @synopsis AC_CXX_HAVE_SSTREAM
dnl
dnl If the C++ library has a working stringstream, define HAVE_SSTREAM.
dnl
dnl @author Ben Stanley
dnl @version $Id: aclocal-cxx.m4,v 1.1 2004/09/27 17:30:14 hno Exp $
dnl
AC_DEFUN([AC_CXX_HAVE_SSTREAM],
[AC_CACHE_CHECK(whether the compiler has stringstream,
ac_cv_cxx_have_sstream,
[AC_REQUIRE([AC_CXX_NAMESPACES])
 AC_LANG_SAVE
 AC_LANG_CPLUSPLUS
 AC_TRY_COMPILE([#include <sstream>
#ifdef HAVE_NAMESPACES
using namespace std;
#endif],[stringstream message; message << "Hello"; return 0;],
 ac_cv_cxx_have_sstream=yes, ac_cv_cxx_have_sstream=no)
 AC_LANG_RESTORE
])
if test "$ac_cv_cxx_have_sstream" = yes; then
  AC_DEFINE(HAVE_SSTREAM,1,[define if the compiler has stringstream])
fi
])

dnl @synopsis AC_CXX_HAVE_STRSTREAM
dnl
dnl If the C++ library has a working strstream, define HAVE_CLASS_STRSTREAM.
dnl
dnl Adapted from ac_cxx_have_sstream.m4 by Steve Robbins
dnl
AC_DEFUN([AC_CXX_HAVE_STRSTREAM],
[AC_CACHE_CHECK(whether the library defines class strstream,
ac_cv_cxx_have_class_strstream,
[AC_REQUIRE([AC_CXX_NAMESPACES])
 AC_LANG_SAVE
 AC_LANG_CPLUSPLUS
 AC_CHECK_HEADERS(strstream)
 AC_TRY_COMPILE([
#if HAVE_STRSTREAM
#  include <strstream>
#else
#  include <strstream.h>
#endif
#ifdef HAVE_NAMESPACES
using namespace std;
#endif],[ostrstream message; message << "Hello"; return 0;],
 ac_cv_cxx_have_class_strstream=yes, ac_cv_cxx_have_class_strstream=no)
 AC_LANG_RESTORE
])
if test "$ac_cv_cxx_have_class_strstream" = yes; then
  AC_DEFINE(HAVE_CLASS_STRSTREAM,1,[define if the library defines strstream])
fi
])

dnl @synopsis AC_CREATE_PREFIX_CONFIG_H [(OUTPUT-HEADER [,PREFIX [,ORIG-HEADER]])]
dnl
dnl this is a new variant from ac_prefix_config_
dnl   this one will use a lowercase-prefix if
dnl   the config-define was starting with a lowercase-char, e.g. 
dnl   #define const or #define restrict or #define off_t
dnl   (and this one can live in another directory, e.g. testpkg/config.h
dnl    therefore I decided to move the output-header to be the first arg)
dnl
dnl takes the usual config.h generated header file; looks for each of
dnl the generated "#define SOMEDEF" lines, and prefixes the defined name
dnl (ie. makes it "#define PREFIX_SOMEDEF". The result is written to
dnl the output config.header file. The PREFIX is converted to uppercase 
dnl for the conversions. 
dnl
dnl default OUTPUT-HEADER = $PACKAGE-config.h
dnl default PREFIX = $PACKAGE
dnl default ORIG-HEADER, derived from OUTPUT-HEADER
dnl         if OUTPUT-HEADER has a "/", use the basename
dnl         if OUTPUT-HEADER has a "-", use the section after it.
dnl         otherwise, just config.h
dnl
dnl In most cases, the configure.in will contain a line saying
dnl         AC_CONFIG_HEADER(config.h) 
dnl somewhere *before* AC_OUTPUT and a simple line saying
dnl        AC_PREFIX_CONFIG_HEADER
dnl somewhere *after* AC_OUTPUT.
dnl
dnl example:
dnl   AC_INIT(config.h.in)        # config.h.in as created by "autoheader"
dnl   AM_INIT_AUTOMAKE(testpkg, 0.1.1)   # "#undef VERSION" and "PACKAGE"
dnl   AM_CONFIG_HEADER(config.h)         #                in config.h.in
dnl   AC_MEMORY_H                        # "#undef NEED_MEMORY_H"
dnl   AC_C_CONST_H                       # "#undef const"
dnl   AC_OUTPUT(Makefile)                # creates the "config.h" now
dnl   AC_CREATE_PREFIX_CONFIG_H          # creates "testpkg-config.h"
dnl         and the resulting "testpkg-config.h" contains lines like
dnl   #ifndef TESTPKG_VERSION 
dnl   #define TESTPKG_VERSION "0.1.1"
dnl   #endif
dnl   #ifndef TESTPKG_NEED_MEMORY_H 
dnl   #define TESTPKG_NEED_MEMORY_H 1
dnl   #endif
dnl   #ifndef _testpkg_const 
dnl   #define _testpkg_const const
dnl   #endif
dnl
dnl   and this "testpkg-config.h" can be installed along with other
dnl   header-files, which is most convenient when creating a shared
dnl   library (that has some headers) where some functionality is
dnl   dependent on the OS-features detected at compile-time. No
dnl   need to invent some "testpkg-confdefs.h.in" manually. :-)
dnl
dnl @version $Id: aclocal-cxx.m4,v 1.1 2004/09/27 17:30:14 hno Exp $
dnl @author Guido Draheim <guidod@gmx.de>

AC_DEFUN([AC_CREATE_PREFIX_CONFIG_H],
[changequote({, })dnl 
ac_prefix_conf_OUT=`echo ifelse($1, , $PACKAGE-config.h, $1)`
ac_prefix_conf_DEF=`echo _$ac_prefix_conf_OUT | sed -e 'y:abcdefghijklmnopqrstuvwxyz./,-:ABCDEFGHIJKLMNOPQRSTUVWXYZ____:'`
ac_prefix_conf_PKG=`echo ifelse($2, , $PACKAGE, $2)`
ac_prefix_conf_LOW=`echo _$ac_prefix_conf_PKG | sed -e 'y:ABCDEFGHIJKLMNOPQRSTUVWXYZ-:abcdefghijklmnopqrstuvwxyz_:'`
ac_prefix_conf_UPP=`echo $ac_prefix_conf_PKG | sed -e 'y:abcdefghijklmnopqrstuvwxyz-:ABCDEFGHIJKLMNOPQRSTUVWXYZ_:'  -e '/^[0-9]/s/^/_/'`
ac_prefix_conf_INP=`echo ifelse($3, , _, $3)`
if test "$ac_prefix_conf_INP" = "_"; then
   case $ac_prefix_conf_OUT in
      */*) ac_prefix_conf_INP=`basename $ac_prefix_conf_OUT` 
      ;;
      *-*) ac_prefix_conf_INP=`echo $ac_prefix_conf_OUT | sed -e 's/[a-zA-Z0-9_]*-//'`
      ;;
      *) ac_prefix_conf_INP=config.h
      ;;
   esac
fi
changequote([, ])dnl
if test -z "$ac_prefix_conf_PKG" ; then
   AC_MSG_ERROR([no prefix for _PREFIX_PKG_CONFIG_H])
else
  AC_MSG_RESULT(creating $ac_prefix_conf_OUT - prefix $ac_prefix_conf_UPP for $ac_prefix_conf_INP defines)
  if test -f $ac_prefix_conf_INP ; then
    AS_DIRNAME([/* automatically generated */], $ac_prefix_conf_OUT)
changequote({, })dnl 
    echo '#ifndef '$ac_prefix_conf_DEF >$ac_prefix_conf_OUT
    echo '#define '$ac_prefix_conf_DEF' 1' >>$ac_prefix_conf_OUT
    echo ' ' >>$ac_prefix_conf_OUT
    echo /'*' $ac_prefix_conf_OUT. Generated automatically at end of configure. '*'/ >>$ac_prefix_conf_OUT

    echo 's/#undef  *\([A-Z_]\)/#undef '$ac_prefix_conf_UPP'_\1/' >conftest.sed
    echo 's/#undef  *\([a-z]\)/#undef '$ac_prefix_conf_LOW'_\1/' >>conftest.sed
    echo 's/#define  *\([A-Z_][A-Za-z0-9_]*\)\(.*\)/#ifndef '$ac_prefix_conf_UPP"_\\1 \\" >>conftest.sed
    echo '#define '$ac_prefix_conf_UPP"_\\1 \\2 \\" >>conftest.sed
    echo '#endif/' >>conftest.sed
    echo 's/#define  *\([a-z][A-Za-z0-9_]*\)\(.*\)/#ifndef '$ac_prefix_conf_LOW"_\\1 \\" >>conftest.sed
    echo '#define '$ac_prefix_conf_LOW"_\\1 \\2 \\" >>conftest.sed
    echo '#endif/' >>conftest.sed
    sed -f conftest.sed $ac_prefix_conf_INP >>$ac_prefix_conf_OUT
    echo ' ' >>$ac_prefix_conf_OUT
    echo '/*' $ac_prefix_conf_DEF '*/' >>$ac_prefix_conf_OUT
    echo '#endif' >>$ac_prefix_conf_OUT
changequote([, ])dnl
  else
    AC_MSG_ERROR([input file $ac_prefix_conf_IN does not exist, dnl
    skip generating $ac_prefix_conf_OUT])
  fi
  rm -f conftest.* 
fi])
           

