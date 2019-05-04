## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

AC_INIT([Squid Web Proxy],[5.0.0-VCS],[http://bugs.squid-cache.org/],[squid])
AC_PREREQ(2.61)
AC_CONFIG_HEADERS([include/autoconf.h])
AC_CONFIG_AUX_DIR(cfgaux)
AC_CONFIG_SRCDIR([src/main.cc])
AM_INIT_AUTOMAKE([tar-ustar nostdinc subdir-objects dist-xz])
AC_REVISION($Revision$)dnl
AC_PREFIX_DEFAULT(/usr/local/squid)
AM_MAINTAINER_MODE

m4_include([acinclude/ax_with_prog.m4])
m4_include([acinclude/init.m4])
m4_include([acinclude/squid-util.m4])
m4_include([acinclude/compiler-flags.m4])
m4_include([acinclude/os-deps.m4])
m4_include([acinclude/krb5.m4])
m4_include([acinclude/pam.m4])
m4_include([acinclude/pkg.m4])
m4_include([acinclude/tdb.m4])
m4_include([acinclude/lib-checks.m4])
m4_include([acinclude/ax_cxx_compile_stdcxx_11.m4])
m4_include([acinclude/ax_cxx_0x_types.m4])

PRESET_CFLAGS="$CFLAGS"
PRESET_CXXFLAGS="$CXXFLAGS"
PRESET_LDFLAGS="$LDFLAGS"

dnl Set default LDFLAGS
if test "x$LDFLAGS" = "x" ; then
  LDFLAGS="-g"
fi

# Check for GNU cc
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CXX
AC_LANG([C++])
AC_CANONICAL_HOST

# Clang 3.2 on some CPUs requires -march-native to detect correctly.
# GCC 4.3+ can also produce faster executables when its used.
# But building inside a virtual machine environment has been found to
# cause random Illegal Instruction errors due to mis-detection of CPU.
AC_ARG_ENABLE(arch-native,
  AS_HELP_STRING([--disable-arch-native],[Some compilers offer CPU-specific
                 optimizations with the -march=native parameter.
                 This flag disables the optimization. The default is to
                 auto-detect compiler support and use where available.]), [
  SQUID_YESNO([$enableval],
    [Unrecognized argument to --disable-arch-native: $enableval])
])
AC_MSG_NOTICE([CPU arch native optimization enabled: ${enable_arch_native:=auto}])
if test "x${enable_arch_native}" != "xno"; then
  SQUID_CC_CHECK_ARGUMENT([squid_cv_check_marchnative],[-march=native])
fi

# might be cross-compiling.
# NP: BUILDCXXFLAGS defined at the end of configure after CXXFLAGS fully known.
AC_ARG_VAR([BUILDCXX],[path to compiler for building compile-time tools. e.g. cf_gen])
if test "x$HOSTCXX" != "x" -a "x$BUILDCXX" = "x"; then
  AC_MSG_WARN([Cross-compiling with HOSTCXX is deprecated. Uses BUILDCXX instead.])
  BUILDCXX="$HOSTCXX"
fi
if test "x$BUILDCXX" = "x"; then
  BUILDCXX="$CXX"
  if test "x$squid_cv_check_marchnative" = "xyes"; then
    CXXFLAGS="$CXXFLAGS -march=native"
  fi
fi
AC_SUBST(BUILDCXX)

AC_MSG_CHECKING([simplified host os])
simple_host_os=`echo $host_os|sed 's/[0-9].*//g;s/-.*//g'`
squid_host_os_version=`echo $host_os|tr -d "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-"`
if test -n "$squid_host_os_version"; then
	squid_host_os="`echo $simple_host_os| sed s/$squid_host_os_version//g`"
else
	squid_host_os="$simple_host_os"
fi
AC_MSG_RESULT($squid_host_os (version $squid_host_os_version))
# on windows squid_host_os is either mingw or cygwin, version is 32

# this needs to be before any test is run, to have more standard
# functions available on some Unix sysems (e.g. Solaris)
if test "x$squid_host_os" = "solaris" -a "x$GCC" != "x" ; then
	AC_USE_SYSTEM_EXTENSIONS
fi

# If the user did not specify a C++ version.
user_cxx=`echo "$PRESET_CXXFLAGS" | grep -o -E "\-std="`
if test "x$user_cxx" = "x"; then
  # Check for C++11 compiler support
  AX_CXX_COMPILE_STDCXX_11([noext],[mandatory])
fi

# test for programs
AC_PROG_RANLIB
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_EGREP

AC_PATH_PROG(SH, sh, /bin/sh)
AC_PATH_PROG(FALSE, false, /usr/bin/false)
AC_PATH_PROG(TRUE, true, /usr/bin/true)
AC_PATH_PROG(MV, mv, $FALSE)
AC_PATH_PROG(MKDIR, mkdir, $FALSE)
AC_PATH_PROG(LN, ln, cp)
AC_PATH_PROG(CHMOD, chmod, $FALSE)
AC_PATH_PROG(TR, tr, $FALSE)
AC_PATH_PROG(RM, rm, $FALSE)
dnl Libtool 2.2.6 requires: rm -f
RM="$RM -f"

PKG_PROG_PKG_CONFIG

AC_PATH_PROG(PERL, perl, none)
if test "x$ac_cv_path_PERL" = "xnone"; then
  AC_MSG_FAILURE([Perl is required to compile Squid. Please install Perl and then re-run configure ])
fi
AC_PATH_PROG(POD2MAN, pod2man, $FALSE)
AM_CONDITIONAL(ENABLE_POD2MAN_DOC, test "x${ac_cv_path_POD2MAN}" != "x$FALSE")

dnl set $(AR) if not provided by the build environment
if test "x$AR" = "x"; then
  AC_PATH_PROG(AR, ar, $FALSE)
fi
AR_R="$AR r"
AC_SUBST(AR_R)

AC_PATH_PROG(LINUXDOC, linuxdoc, $FALSE)
AM_CONDITIONAL(ENABLE_RELEASE_DOCS, test "x${ac_cv_path_LINUXDOC}" != "x$FALSE")

# pre-define DEFAULT_PREFIX, some modules need it.
if test "${prefix}" = "NONE" ; then
  squid_prefix=$ac_default_prefix
else
  squid_prefix=$prefix
fi
AC_DEFINE_UNQUOTED(DEFAULT_PREFIX,[$squid_prefix],[The install prefix])

AC_ARG_ENABLE(strict-error-checking,
  AS_HELP_STRING([--disable-strict-error-checking],[By default squid is compiled
                 with all possible static compiler error-checks enabled.
                 This flag disables the behavior]), [
  SQUID_YESNO([$enableval],
    [Unrecognized argument to --disable-strict-error-checking: $enableval])
])
AC_MSG_NOTICE([strict error checking enabled: ${enable_strict_error_checking:=yes}])

AC_MSG_CHECKING(whether to use loadable modules)
AC_ARG_ENABLE(loadable-modules,
  AS_HELP_STRING([--disable-loadable-modules],[do not support loadable modules]) , [
  SQUID_YESNO([$enableval],
    [Unrecognized argument to --disable-loadable-modules: $enableval])
])
AM_CONDITIONAL(ENABLE_LOADABLE_MODULES, test "x${enable_loadable_modules:=yes}" = "xyes")
AC_MSG_RESULT([$enable_loadable_modules])

if test "x$enable_loadable_modules" = "xyes";
then
  AC_DEFINE(USE_LOADABLE_MODULES, 1, [Support Loadable Modules])
  AC_ENABLE_SHARED
else
  AC_DISABLE_SHARED
fi

# LT_INIT requires libtool v2, might as well state it loud
LT_PREREQ([2.2])
LT_INIT([dlopen],[disable-shared])
if ! test "${ac_top_build_prefix}" = "";
then
	# LTDL v3-v7 macros assume the autoconf 2.62 variable top_build_prefix is defined
	# But from autoconf 2.64 its called ac_top_build_prefix and not automatically added to the Makefile
	# This fixes Linux LTDLv3-v7, and BSD LTDL v2.2
	top_build_prefix=${ac_top_build_prefix}
	AC_SUBST(top_build_prefix)
fi
LTDL_INIT

dnl LibTool environment is now prepared for setup. Check that it is usable and initialize.
LT_LIB_DLLOAD

# Do we need these unconditionally for "make distcheck" to work?
AC_SUBST(INCLTDL)
AC_SUBST(LIBLTDL)

if test "x$enable_loadable_modules" = "xyes";
then
  # Why is this needed? Should not LT_INIT (or LT_LIB_DLLOAD) from libtool do that?
  LIBADD_DL=${lt_cv_dlopen_libs}
  AC_SUBST([LIBADD_DL])
fi

SQUID_CC_GUESS_VARIANT
SQUID_CC_GUESS_OPTIONS

dnl find out the exe extension for this platform.
dnl If it is not empty, use it for CGI as well.
AC_EXEEXT
AC_OBJEXT

if test "x$EXEEXT" = "x" ; then
  CGIEXT=".cgi"
else
  # automake automatically adds .exe when installing binaries
  CGIEXT=""
fi
AC_SUBST(CGIEXT)

AM_CONDITIONAL(ENABLE_WIN32SPECIFIC,[test "x$squid_host_os" = "xmingw"])
AM_CONDITIONAL(ENABLE_WIN32_IPC,[test "x$squid_host_os" = "xmingw"])

case "$squid_host_os" in
mingw)
  AC_PATH_PROG(WIN32_PSAPI, psapi.dll, none)
  CFLAGS="$CFLAGS -mthreads"
  CXXFLAGS="$CXXFLAGS -mthreads -static-libgcc -static-libstdc++"
  if test "x$ac_cv_path_WIN32_PSAPI" = "xnone"; then
    AC_MSG_NOTICE([PSAPI.DLL is recommended to run Squid on Windows NT Platform])
    AC_MSG_NOTICE([Please see PSAPI.DLL section on doc/win32-relnotes.html.])
  else
    AC_DEFINE(HAVE_WIN32_PSAPI,1,[Define if you have PSAPI.DLL on Windows systems])
    LIBS="$LIBS -lpsapi"
  fi
  MINGW_LIBS="-lmingwex"
  AC_SUBST(MINGW_LIBS)
  ;;
freebsd)
    # FreeBSD places local libraries and packages in /usr/local
    CFLAGS="$CFLAGS -I/usr/local/include"
    CXXFLAGS="$CXXFLAGS -I/usr/local/include"
    LDFLAGS="$LDFLAGS -L/usr/local/lib -Wl,-R/usr/local/lib"
    ;;
*)
    ;;
esac

dnl Substitutions
AC_DEFINE_UNQUOTED(CONFIG_HOST_TYPE, "$host",[Host type from configure])

AC_DEFINE_UNQUOTED(SQUID_CONFIGURE_OPTIONS, "$ac_configure_args", 
                       [configure command line used to configure Squid])

CACHE_EFFECTIVE_USER="nobody"
AC_ARG_WITH(default-user,
  AS_HELP_STRING([--with-default-user=USER],[System user account for squid permissions. Default: nobody]),
 [ CACHE_EFFECTIVE_USER="$withval" ]
)
AC_SUBST(CACHE_EFFECTIVE_USER)

DEFAULT_LOG_DIR="$localstatedir/logs"
AC_ARG_WITH(logdir,
  AS_HELP_STRING([--with-logdir=PATH],
    [Default location for squid logs. default: PREFIX/var/logs]), [
case $withval in
  yes|no)
    AC_MSG_ERROR( --with-logdir requires a directory PATH. --with-logdir=PATH )
    ;;
  *)
    DEFAULT_LOG_DIR="$withval"
    ;;
esac
 ]
)
AC_SUBST(DEFAULT_LOG_DIR)

DEFAULT_PID_FILE="$localstatedir/run/@SERVICE_NAME@.pid"
AC_ARG_WITH(pidfile,
  AS_HELP_STRING([--with-pidfile=PATH],
    [Default location for squid pid file. Default: PREFIX/var/run/squid.pid]), [
case $withval in
 yes|no)
   AC_MSG_ERROR( --with-pidfile requires a file PATH. --with-pidfile=PATH )
   ;;
 *)
   DEFAULT_PID_FILE="$withval"
   ;;
 esac
])
AC_SUBST(DEFAULT_PID_FILE)

DEFAULT_SWAP_DIR="$localstatedir/cache/squid"
AC_ARG_WITH(swapdir,
  AS_HELP_STRING([--with-swapdir=PATH],
    [Default location for squid cache directories. Default: PREFIX/var/cache/squid]), [
case $withval in
 yes|no)
   AC_MSG_ERROR( --with-swapdir requires a directory PATH. --with-swapdir=PATH )
   ;;
 *)
   DEFAULT_SWAP_DIR="$withval"
   ;;
 esac
])
AC_SUBST(DEFAULT_SWAP_DIR)

dnl Set Default CFLAGS
if test "x$PRESET_CFLAGS" = "x"; then
  if test "$squid_cv_compiler" = "gcc"; then
    case "$host" in
      *-sun-sunos*)
        # sunos has too many warnings for this to be useful
        # motorola too
        ;;
      *m88k*)
        # Motorola cc/ld does not like -02 but is ok on -O
        CFLAGS=`echo $CFLAGS | sed -e 's/-O[0-9]/-O/'`
        ;;
      *)
        CFLAGS="$squid_cv_cc_option_wall $CFLAGS"
        ;;
    esac
  else
    case "$host" in
      *mips-sgi-irix6.*)
        # suggested by Rafael Seidl <rafaels@cthulhu.engr.sgi.com>
        CFLAGS="$squid_cv_cc_option_optimize -OPT:Olimit=0:space=OFF \
                -woff 1009,1014,1110,1116,1183,1185,1188,1204,1230,1233,1355 \
                -Wl,-woff,85,-woff,84,-woff,134 \
                -nostdinc -I/usr/include -D_BSD_SIGNALS $CFLAGS"
        CXXFLAGS="$squid_cv_cc_option_optimize -OPT:Olimit=0:space=OFF \
                  -woff 1009,1014,1110,1116,1183,1185,1188,1204,1230,1233,1355 \
                  -Wl,-woff,85,-woff,84,-woff,134 \
                  -nostdinc -I/usr/include -D_BSD_SIGNALS $CXXFLAGS"
          ;;
        *)
          ;;
    esac
  fi
fi

dnl set squid required flags
if test "$squid_cv_compiler" = "gcc"; then
  case "$squid_host_os" in
  mingw)
dnl Guido Serassio (serassio@squid-cache.org) 20070811
dnl Using the latest MinGW (gcc 3.4.5 + mingw-runtime 3.13) cannot build with
dnl -Werror -Wmissing-prototypes -Wmissing-declarations
dnl TODO: check if the problem will be present in any other newer MinGW release.
    SQUID_CFLAGS="$squid_cv_cc_option_wall -Wpointer-arith -Wwrite-strings -Wcomments -Wshadow"
    ;;
  *)
    SQUID_CFLAGS="$squid_cv_cc_option_wall -Wpointer-arith -Wwrite-strings -Wmissing-prototypes -Wmissing-declarations -Wcomments -Wshadow"
    ;;
  esac
  SQUID_CXXFLAGS="$squid_cv_cc_option_wall -Wpointer-arith -Wwrite-strings -Wcomments -Wshadow -Woverloaded-virtual"
else
  SQUID_CFLAGS=
  SQUID_CXXFLAGS=
fi

dnl CentOS (and RHEL) still define ntohs() using deprecated C++ features
SQUID_CC_REQUIRE_ARGUMENT([ac_cv_require_wno_deprecated_register],[-Werror -Wno-deprecated-register],[[#include <arpa/inet.h>]],[[int fox=ntohs(1);]])

if test "x$enable_strict_error_checking" != "xno"; then
  SQUID_CFLAGS="$SQUID_CFLAGS $squid_cv_cc_option_werror"
  SQUID_CXXFLAGS="$SQUID_CXXFLAGS $squid_cv_cxx_option_werror"
fi

if test "x$ac_cv_require_wno_deprecated_register" = "xyes"; then
  SQUID_CXXFLAGS="$SQUID_CXXFLAGS -Wno-deprecated-register"
fi

# squid_cv_cc_arg_pipe is set by SQUID_CC_GUESS_OPTIONS
SQUID_CXXFLAGS="$SQUID_CXXFLAGS $squid_cv_cc_arg_pipe"
SQUID_CFLAGS="$SQUID_CFLAGS $squid_cv_cc_arg_pipe"

# possibly include some build info tag into squid -v
SQUID_EMBED_BUILD_INFO

AC_ARG_ENABLE(optimizations,
  AS_HELP_STRING([--disable-optimizations],
                 [Do not compile Squid with compiler optimizations enabled.
                  Optimization is good for production builds, but not
                  good for debugging. During development, use
                  --disable-optimizations to reduce compilation times
                  and allow easier debugging.]), [
if test "x$enableval" = "xno" ; then
  AC_MSG_NOTICE([Disabling compiler optimizations (-O flag)])
  CFLAGS="`echo $CFLAGS | sed -e 's/-O[[0-9g]]*//'`"
  CXXFLAGS="`echo $CXXFLAGS | sed -e 's/-O[[0-9g]]*//'`"
fi
])

AC_ARG_ENABLE(debug-cbdata,
  AS_HELP_STRING([--enable-debug-cbdata],
      [Provide some debug information in cbdata]), [ 
SQUID_YESNO([$enableval],
    [unrecognized argument to --enable-debug-cbdata: $enableval])
])
SQUID_DEFINE_BOOL(USE_CBDATA_DEBUG,${enable_debug_cbdata:=no},
    [Enable support for cbdata debug information])
AC_MSG_NOTICE([cbdata debugging enabled: $enable_debug_cbdata])


dnl Nasty hack to get autoconf 2.64 on Linux to run.
dnl all other uses of RUN_IFELSE are wrapped inside CACHE_CHECK which breaks on 2.64
AC_RUN_IFELSE([AC_LANG_SOURCE([[ int main(int argc, char **argv) { return 0; } ]])],[],[],[:])

AH_TEMPLATE(XMALLOC_STATISTICS,[Define to have malloc statistics])
AC_ARG_ENABLE(xmalloc-statistics,
  AS_HELP_STRING([--enable-xmalloc-statistics],
                 [Show malloc statistics in status page]), [
SQUID_YESNO([$enableval],
    [unrecognized argument to --enable-xmalloc-statistics: $enableval])
])
SQUID_DEFINE_BOOL(XMALLOC_STATISTICS,${enable_xmalloc_statistics:=no},
    [Show malloc statistics in status page])
AC_MSG_NOTICE([xmalloc stats display: $enable_xmalloc_statistics])

squid_opt_aufs_threads=""
AC_ARG_WITH(aufs-threads,
  AS_HELP_STRING([--with-aufs-threads=N_THREADS],
   [Tune the number of worker threads for the aufs object store.]), [ 
case $withval in
  [[0-9]]*)
    squid_opt_aufs_threads=$withval
    ;;
  *)
    AC_MSG_ERROR(--with-aufs-threads expects a numeric argument)
    ;;
  esac
])
if test "x$squid_opt_aufs_threads" != "x"; then
    AC_MSG_NOTICE([With $squid_opt_aufs_threads aufs threads])
    AC_DEFINE_UNQUOTED(AUFS_IO_THREADS,$squid_opt_aufs_threads,
                 [Defines how many threads aufs uses for I/O])
fi

AC_ARG_WITH(dl, AS_HELP_STRING([--with-dl],[Use dynamic linking]))
if test "x$with_dl" = "xyes"; then
  AC_MSG_NOTICE([With dl])
fi

## check for atomics library before anything that might need it
# AC_SEARCH_LIBS pollutes LIBS
SQUID_STATE_SAVE(LIBATOMIC)
AC_SEARCH_LIBS([__atomic_load_8],[atomic],[
  test "$ac_res" = "none required" || ATOMICLIB=$ac_res],[])
SQUID_STATE_ROLLBACK(LIBATOMIC)
AC_SUBST(ATOMICLIB)

AC_SEARCH_LIBS([shm_open], [rt])
if test "x$ac_cv_search_shm_open" != "xno" ; then
  AC_DEFINE(HAVE_SHM,1,[Support shared memory features])
fi

AC_MSG_CHECKING([for DiskIO modules to be enabled])
squid_disk_module_candidates=""
squid_opt_enable_diskio="auto"  #values: no, yes, "auto"(=yes+detect modules)
AC_ARG_ENABLE(disk-io,
  AS_HELP_STRING([--enable-disk-io="list of modules"],
    [Build support for the list of disk I/O modules.
     Set without a value or omitted, all available modules will be built.
     See src/DiskIO for a list of available modules, or
     Programmers Guide section on DiskIO
     for details on how to build your custom disk module]), [ 
case $enableval in
  yes)
    ${TRUE}
    #do nothing, "auto" is ok
    ;;
  no)
    squid_opt_enable_diskio="no"
    ;;
  *)
    squid_opt_enable_diskio="yes"
    squid_disk_module_candidates=" `echo $enableval| sed -e 's/,/ /g;s/  */ /g'` "
    SQUID_CLEANUP_MODULES_LIST([squid_disk_module_candidates])
    ;;
  esac
])

# if requested to autodetect, find out what we have
if test "x$squid_opt_enable_diskio" = "xauto"; then
    squid_opt_enable_diskio="yes"
    SQUID_LOOK_FOR_MODULES([$srcdir/src/DiskIO],[squid_disk_module_candidates])
    if test "x$ac_cv_search_shm_open" = "xno" ; then
        # disable IpcIo
        squid_disk_module_candidates=`echo $squid_disk_module_candidates|sed 's/IpcIo//'`
    fi
fi

AC_MSG_RESULT([${squid_disk_module_candidates:-none}])
SQUID_CHECK_EXISTING_MODULES([$srcdir/src/DiskIO],[squid_disk_module_candidates])
SQUID_DEFINE_BOOL(USE_DISKIO,$squid_opt_enable_diskio,
    [DiskIO modules are expected to be available.])



dnl Some autoconf.h defines we might enable later...
AC_ARG_WITH(pthreads,AS_HELP_STRING([--without-pthreads],[Disable POSIX Threads]))
AC_ARG_WITH(aio, AS_HELP_STRING([--without-aio],[Do not use POSIX AIO. Default: auto-detect]))
ENABLE_WIN32_AIOPS=0
squid_opt_use_aio=
squid_opt_use_diskthreads=
AIOLIB=

dnl Setup the module paths etc.
DISK_LIBS=
DISK_MODULES=
AH_TEMPLATE(HAVE_DISKIO_MODULE_AIO, [Whether POSIX AIO Disk I/O module is built])
AH_TEMPLATE(HAVE_DISKIO_MODULE_BLOCKING, [Whether Blocking Disk I/O module is built])
AH_TEMPLATE(HAVE_DISKIO_MODULE_DISKDAEMON, [Whether DiskDaemon Disk I/O module is built])
AH_TEMPLATE(HAVE_DISKIO_MODULE_DISKTHREADS, [Whether DiskThreads Disk I/O module is built])
AH_TEMPLATE(HAVE_DISKIO_MODULE_IPCIO, [Whether IpcIo Disk I/O module is built])
AH_TEMPLATE(HAVE_DISKIO_MODULE_MMAPPED, [Whether Mmapped Disk I/O module is built])
for module in $squid_disk_module_candidates none; do
  # maybe not needed
  if test "x$module" = "xnone"; then
    continue
  fi
  if ! test -d "$srcdir/src/DiskIO/$module"; then
    AC_MSG_ERROR(disk-io $module does not exist)
  fi
  case "$module" in

    AIO)
      dnl Check for POSIX AIO availability
      squid_opt_use_aio="yes"
      AIOLIB=
      if test "x$with_aio" != "xno"; then
        have_aio_header=no
        AC_CHECK_HEADERS(aio.h,[have_aio_header=yes])
        dnl On some systems POSIX AIO functions are in librt
        dnl On some systems POSIX AIO functions are in libaio
        AC_CHECK_LIB(rt,aio_read,[AIOLIB="-lrt"],AC_CHECK_LIB(aio,aio_read,[AIOLIB="-laio"],[]))
        dnl Enable AIO if the library and headers are found
        if test "x$AIOLIB" != "x" && test "x$have_aio_header" = "xyes"; then
          AC_MSG_NOTICE([Native POSIX AIO support detected.])
          squid_opt_use_aio="yes"
        else
          dnl Windows does things differently. We provide wrappers.
          dnl TODO: Windows really needs its own DiskIO module or its Overlaped IO
          case "$squid_host_os" in
            mingw)
              squid_opt_use_aio="yes"
              AC_MSG_NOTICE([Windows being built. Maybe-enable POSIX AIO.])
              ;;
            *)
              AC_MSG_NOTICE([Native POSIX AIO support not detected. AIO automatically disabled.])
              squid_opt_use_aio="no"
              ;;
          esac
        fi
      else
        AC_MSG_NOTICE([POSIX AIO support manually disabled.])
        squid_opt_use_aio="no"
      fi
      dnl Use the POSIX AIO pieces if we actually need them.
      if test "x$squid_opt_use_aio" = "xyes" ; then
        DISK_MODULES="$DISK_MODULES AIO"
        AC_DEFINE([HAVE_DISKIO_MODULE_AIO],1,[POSIX AIO Disk I/O module is built])
        case "$squid_host_os" in
          mingw)
            ENABLE_WIN32_AIO=1
            AC_MSG_NOTICE([Replacing AIO DiskIO module with: Windows overlapped I/O support])
            ;;
          *)
            AC_MSG_NOTICE([Enabling AIO DiskIO module])
            ;;
        esac
      else
        AC_MSG_NOTICE([AIO DiskIO Module disabled. Missing POSIX AIO support.])
        squid_disk_module_candidates_AIO=no
      fi
      ;;

    Blocking)
      AC_MSG_NOTICE([Enabling Blocking DiskIO module])
      DISK_MODULES="$DISK_MODULES Blocking"
      AC_DEFINE([HAVE_DISKIO_MODULE_BLOCKING],1,[Blocking Disk I/O module is built])
      ;;

    DiskDaemon)
      case "$squid_host_os" in
        mingw)
          AC_MSG_NOTICE(["DiskDaemon not supported on MinGW"])
          squid_disk_module_candidates_DiskDaemon=no
          ;;
        *)
          AC_MSG_NOTICE([Enabling DiskDaemon DiskIO module])
          DISK_MODULES="$DISK_MODULES DiskDaemon"
          AC_DEFINE([HAVE_DISKIO_MODULE_DISKDAEMON],1,[DiskDaemon Disk I/O module is built])
          ;;
        esac
      ;;

    DiskThreads)
      squid_opt_use_diskthreads="yes"
      LIBPTHREADS=
      SQUID_STATE_SAVE([diskthreads_state],[SQUID_CFLAGS SQUID_CXXFLAGS])
      if test "x$with_pthreads" != "xno"; then
      dnl TODO: this needs to be extended to handle more systems and better
      dnl REF: http://www.openldap.org/lists/openldap-bugs/200006/msg00070.html
      dnl REF: http://autoconf-archive.cryp.to/acx_pthread.html
        case "$squid_host_os" in
          mingw)
            ENABLE_WIN32_AIOPS=1
            AC_MSG_NOTICE([Windows threads support automatically enabled])
            ;;
          freebsd)
            if test `echo "$squid_host_os_version" | tr -d .` -lt 70 ; then
                AC_MSG_NOTICE(pthread library requires FreeBSD 7 or later)
                squid_opt_use_diskthreads="no"
            else
              SQUID_CFLAGS="$SQUID_CFLAGS -D_REENTRANT"
              SQUID_CXXFLAGS="$SQUID_CXXFLAGS -D_REENTRANT"
              if test "x$GCC" = "xyes" -a "x$PRESET_LDFLAGS" = "x" ; then
                LDFLAGS="$LDFLAGS -pthread"
              fi
            fi
            ;;
          openbsd)
            if test `echo "$squid_host_os_version" | tr -d .` -lt 52 ; then
                AC_MSG_NOTICE(pthread library requires OpenBSD 5.2 or later)
                squid_opt_use_diskthreads="no"
            else
              SQUID_CFLAGS="$SQUID_CFLAGS -D_REENTRANT"
              SQUID_CXXFLAGS="$SQUID_CXXFLAGS -D_REENTRANT"
              LDFLAGS="$LDFLAGS -lpthread"
            fi
            ;;
          solaris)
            if test "x$GCC" = "xyes" ; then
              SQUID_CFLAGS="$SQUID_CFLAGS -D_REENTRANT -pthreads"
              SQUID_CXXFLAGS="$SQUID_CXXFLAGS -D_REENTRANT -pthreads"
              AC_CHECK_LIB(pthread, pthread_create ,[LIBPTHREADS="-lpthread"], [
                AC_MSG_NOTICE(pthread library required but cannot be found.)
                squid_opt_use_diskthreads="no"
               ])
            else
              dnl test for -lpthread first. libc version is a stub apparently on Solaris.
              SQUID_CFLAGS="$SQUID_CFLAGS -D_REENTRANT -lpthread"
              SQUID_CXXFLAGS="$SQUID_CXXFLAGS -D_REENTRANT -lpthread"
              AC_SEARCH_LIBS([pthread_create],[pthread thread],[
                LIBPTHREADS="" #in LIBS 
              ],[
                AC_MSG_NOTICE(pthread library required but cannot be found.)
                squid_opt_use_diskthreads="no"
              ])
            fi
            ;;
          *)
            SQUID_CFLAGS="$SQUID_CFLAGS -D_REENTRANT"
            SQUID_CXXFLAGS="$SQUID_CXXFLAGS -D_REENTRANT"
            AC_CHECK_LIB(pthread, pthread_create ,[LIBPTHREADS="-lpthread"], [
              AC_MSG_NOTICE(pthread library required but cannot be found.)
              squid_opt_use_diskthreads="no"
            ])
            ;;
          esac
        else
          AC_MSG_NOTICE([Native pthreads support manually disabled.])
          squid_opt_use_diskthreads="no"
        fi
        if test "x$squid_opt_use_diskthreads" = "xyes" ; then
          AC_MSG_NOTICE([Enabling DiskThreads DiskIO module])
          DISK_MODULES="$DISK_MODULES DiskThreads"
          AC_DEFINE([HAVE_DISKIO_MODULE_DISKTHREADS],1,[DiskThreads Disk I/O module is built])
        else
          AC_MSG_NOTICE([Native pthreads support disabled. DiskThreads module automaticaly disabled.])
          SQUID_STATE_ROLLBACK([diskthreads_state])
          squid_disk_module_candidates_DiskThreads=no
        fi
      ;;

    IpcIo)
      if test "x$ac_cv_search_shm_open" = "xno" ; then
        AC_MSG_NOTICE([DiskIO IpcIo module requires shared memory support])
        squid_disk_module_candidates_IpcIo=no
      else
        AC_MSG_NOTICE([Enabling IpcIo DiskIO module])
        DISK_MODULES="$DISK_MODULES IpcIo"
        AC_DEFINE([HAVE_DISKIO_MODULE_IPCIO],1,[IpcIo Disk I/O module is built])
      fi
      ;;

    Mmapped)
      dnl TODO: use availability of sys/mman.h and/or mmap to define
      dnl  OR support windows mmap functions
      if test "x$squid_host_os" = "xmingw" ; then
        AC_MSG_NOTICE([Mmapped DiskIO is not available on Mingw])
        squid_disk_module_candidates_Mmapped=no
      else
        AC_MSG_NOTICE([Enabling Mmapped DiskIO module])
        DISK_MODULES="$DISK_MODULES Mmapped"
        AC_DEFINE([HAVE_DISKIO_MODULE_MMAPPED],1,[Mmapped Disk I/O module is built])
      fi
      ;;

    *)
      AC_MSG_NOTICE([Enabling $module DiskIO module])
      DISK_LIBS="$DISK_LIBS lib${module}.la"
      DISK_MODULES="$DISK_MODULES ${module}"
      ;;
    esac
done
AC_MSG_NOTICE([IO Modules built: $DISK_MODULES])
AC_SUBST(DISK_MODULES)
AC_SUBST(DISK_LIBS)
AM_CONDITIONAL(ENABLE_DISKIO_AIO, test "x$squid_disk_module_candidates_AIO" = "xyes")
AC_SUBST(AIOLIB)
AM_CONDITIONAL(ENABLE_WIN32_AIO, test "x$squid_disk_module_candidates_AIO" = "xyes" -a "x$ENABLE_WIN32_AIO" = "x1")
AM_CONDITIONAL(ENABLE_DISKIO_BLOCKING, test "x$squid_disk_module_candidates_Blocking" = "xyes")
AM_CONDITIONAL(ENABLE_DISKIO_DISKDAEMON, test "x$squid_disk_module_candidates_DiskDaemon" = "xyes")
AM_CONDITIONAL(ENABLE_DISKIO_DISKTHREADS, test "x$squid_disk_module_candidates_DiskThreads" = "xyes")
AC_SUBST(LIBPTHREADS)
AM_CONDITIONAL(ENABLE_WIN32_AIOPS, test "x$squid_disk_module_candidates_DiskThreads" = "xyes" -a "x$ENABLE_WIN32_AIOPS" = "x1")
AM_CONDITIONAL(ENABLE_DISKIO_IPCIO, test "x$squid_disk_module_candidates_IpcIo" = "xyes")
AM_CONDITIONAL(ENABLE_DISKIO_MMAPPED, test "x$squid_disk_module_candidates_Mmapped" = "xyes")

dnl Check what Storage formats are wanted.
dnl This version will error out with a message saying why if a required DiskIO is missing.
squid_opt_enable_storeio=auto
AC_ARG_ENABLE([storeio],
  AS_HELP_STRING([--enable-storeio="list of modules"],
                 [Build support for the list of store I/O modules.
                  The default is only to build the "ufs" module.
                  See src/fs for a list of available modules, or
                  Programmers Guide section <not yet written>
                  for details on how to build your custom store module]), [
case $enableval in
  yes)
    squid_opt_enable_storeio=auto
    ;;
  no)
    squid_opt_enable_storeio=no
    ;;
  *)
    squid_opt_enable_storeio=yes
    squid_storeio_module_candidates="`echo $enableval| sed -e 's/,/ /g;s/  */ /g'`"
    # ufs is really always needed as it has low-level routines
    # if it is a dupe it will be cleaned-up later
    squid_storeio_module_candidates="$squid_storeio_module_candidates ufs"
    ;;
  esac
])
if test "x$squid_opt_enable_storeio" = "xauto"; then
  squid_opt_enable_storeio=yes
  AC_MSG_CHECKING([for available StoreIO modules])
  SQUID_LOOK_FOR_MODULES([$srcdir/src/fs],[squid_storeio_module_candidates])
  AC_MSG_RESULT([$squid_storeio_module_candidates])
fi

SQUID_CLEANUP_MODULES_LIST([squid_storeio_module_candidates])
SQUID_CHECK_EXISTING_MODULES([$srcdir/src/fs],[squid_storeio_module_candidates])
AC_MSG_NOTICE([Store modules built: $squid_storeio_module_candidates])

for fs in $squid_storeio_module_candidates none; do
  case "$fs" in
    diskd)
      if test "x$squid_disk_module_candidates_Blocking" != "xyes" -a \
        "$squid_disk_module_candidates_DiskDaemon" != "yes" ; then
        AC_MSG_ERROR([Storage diskd module requires DiskIO module: Blocking or DiskDaemon])
      fi
      ;;
    aufs)
      if test "x$squid_disk_module_candidates_Blocking" != "xyes" -a \
        "$squid_disk_module_candidates_DiskThreads" != "yes" ; then
        AC_MSG_ERROR([Storage module aufs requires DiskIO module: Blocking or DiskThreads])
      fi
      ;;
    rock)
      if test "x$squid_disk_module_candidates_IpcIo" != "xyes" -a \
        "x$squid_disk_module_candidates_Blocking" != "xyes"; then
         AC_MSG_ERROR([Storage module Rock requires DiskIO module: Blocking or IpcIo])
      fi
      squid_do_build_rock=true
      ;;
    ufs)
      if test "x$squid_disk_module_candidates_Blocking" != "xyes"; then
        AC_MSG_ERROR([Storage module ufs requires DiskIO module: Blocking])
      fi
      squid_do_build_ufs=true
      ;;
    esac
done

AM_CONDITIONAL(ENABLE_FS_UFS, test "x$squid_do_build_ufs" = "xtrue")
AM_CONDITIONAL(ENABLE_FS_ROCK, test "x$squid_do_build_rock" = "xtrue")
dnl hack: need to define those even if not used in the build system to
dnl make sure that global FS objects are linked to the squid binary.
AH_TEMPLATE(HAVE_FS_UFS, "Define to 1 if ufs filesystem module is build")
AH_TEMPLATE(HAVE_FS_AUFS, "Define to 1 if aufs filesystem module is build")
AH_TEMPLATE(HAVE_FS_DISKD, "Define to 1 if diskd filesystem module is build")
AH_TEMPLATE(HAVE_FS_ROCK, "Define to 1 if rock filesystem module is build")


dnl got final squid_storeio_module_candidates, build library lists
dnl This list will not be needed when each fs library has its own Makefile
STORE_LIBS_TO_BUILD=
dnl File system libraries to link executables with.
dnl These are the same as STORE_LIBS_TO_BUILD, but with a path
STORE_LIBS_TO_ADD=
for fs in $squid_storeio_module_candidates; do
    STORE_LIBS_TO_BUILD="$STORE_LIBS_TO_BUILD lib${fs}.la"
    STORE_LIBS_TO_ADD="$STORE_LIBS_TO_ADD fs/lib${fs}.la"
    SQUID_TOUPPER_VAR_CONTENTS([fs])
    AC_DEFINE_UNQUOTED(HAVE_FS_${fs}, 1)
done

AC_SUBST(STORE_LIBS_TO_BUILD)
AC_SUBST(STORE_LIBS_TO_ADD)
AC_SUBST(STORE_TESTS)


dnl At lest one removal policy is always needed.
dnl 'lru' removal policy is currently hard-coded by name for tests
dnl so we must set it as default.
REPL_POLICIES="lru"
AC_ARG_ENABLE(removal-policies,
  AS_HELP_STRING([--enable-removal-policies="list of policies"],
                 [Build support for the list of removal policies.
                  The default is only to build the "lru" module.
                  See src/repl for a list of available modules, or
                  Programmers Guide section 9.9 for details on how
                  to build your custom policy]), [
case $enableval in
  yes)
    SQUID_LOOK_FOR_MODULES([$srcdir/src/repl],[REPL_POLICIES])
    ;;
  no)
    ;;
  *)
    REPL_POLICIES="`echo $enableval| sed -e 's/,/ /g;s/  */ /g'`"
    ;;
  esac
])
if test "x$REPL_POLICIES" != "x" ; then
    SQUID_CHECK_EXISTING_MODULES([$srcdir/src/repl],[REPL_POLICIES])
    AC_MSG_NOTICE([Removal policies to build: $REPL_POLICIES])
    REPL_OBJS="repl/lib`echo $REPL_POLICIES|sed -e 's% %.a repl/lib%g'`.a"
    REPL_LIBS="`echo $REPL_OBJS|sed -e 's%repl/%%g'`"
fi
AC_SUBST(REPL_POLICIES)
AC_SUBST(REPL_OBJS)
AC_SUBST(REPL_LIBS)

AM_CONDITIONAL(ENABLE_PINGER, false)
AC_ARG_ENABLE(icmp,
  AS_HELP_STRING([--enable-icmp],[Enable ICMP pinging and Network Measurement]),
[ if test "x$enableval" = "xyes" ; then
    AC_MSG_NOTICE([ICMP enabled])
    AC_DEFINE(USE_ICMP,1,[Define to use Squid ICMP and Network Measurement features (highly recommended!)])
    AM_CONDITIONAL(ENABLE_PINGER, true)
  fi
])

AM_CONDITIONAL(ENABLE_DELAY_POOLS, false)
AC_ARG_ENABLE(delay-pools,
  AS_HELP_STRING([--enable-delay-pools],[Enable delay pools to limit bandwidth usage]),
[ if test "x$enableval" = "xyes" ; then
    AC_MSG_NOTICE([Delay pools enabled])
    AC_DEFINE([USE_DELAY_POOLS],1,[Traffic management via "delay pools".])
    AM_CONDITIONAL(ENABLE_DELAY_POOLS, true)
  fi
])

dnl disable generic/common adaptation support by default
squid_opt_use_adaptation=no

squid_opt_use_esi=auto
AH_TEMPLATE([USE_SQUID_ESI],[Define to enable the ESI processor])
AC_ARG_ENABLE(esi,
  AS_HELP_STRING([--disable-esi],
                 [Disable ESI for accelerators. ESI requires expat or libxml2.
                  Enabling ESI will cause squid reverse proxies to be capable
                  of the Edge Acceleration Specification (www.esi.org).]),
                 [squid_opt_use_esi=$enableval],[])
HAVE_LIBEXPAT=0
EXPATLIB=
HAVE_LIBXML2=0
XMLLIB=

# ESI support libraries: expat
AC_ARG_WITH(expat, AS_HELP_STRING([--without-expat],[Do not use expat for ESI. Default: auto-detect]))
if test "x$squid_opt_use_esi" != "xno" -a "x$with_expat" != "xno" ; then
  AC_CHECK_LIB([expat], [main], [EXPATLIB="-lexpat"; HAVE_LIBEXPAT=1])
  AC_CHECK_HEADERS([expat.h])
  AC_DEFINE_UNQUOTED(HAVE_LIBEXPAT, $HAVE_LIBEXPAT, [Define to 1 if you have the expat library])
  AS_IF(test "x$HAVE_LIBEXPAT" = "x1",[
    squid_opt_use_esi=yes
  ],[
    AS_IF(test "x$with_expat" = "xyes",[
      AC_MSG_ERROR([Required library expat not found.])
    ],[
      AC_MSG_NOTICE([Library expat not found.])
    ])
  ])
fi

AC_ARG_WITH(libxml2, AS_HELP_STRING([--without-libxml2],[Do not use libxml2 for ESI. Default: auto-detect]))
if test "x$squid_opt_use_esi" != "xno" -a "x$with_libxml2" != "xno" ; then
  SQUID_STATE_SAVE([squid_libxml2_save])
  PKG_CHECK_MODULES([LIBXML2],[libxml-2.0],[],[
    AC_CHECK_LIB([xml2], [main], [LIBXML2_LIBS="$LIBXML2_LIBS -lxml2"])
    dnl Find the main header and include path...
    AC_CACHE_CHECK([location of libxml2 include files], [ac_cv_libxml2_include], [
      AC_CHECK_HEADERS([libxml/parser.h], [], [
        AC_MSG_NOTICE([Testing in /usr/include/libxml2])
        SAVED_CPPFLAGS="$CPPFLAGS"
        CPPFLAGS="-I/usr/include/libxml2 $CPPFLAGS"
        unset ac_cv_header_libxml_parser_h
        AC_CHECK_HEADERS([libxml/parser.h], [LIBXML2_CFLAGS="$LIBXML2_CFLAGS -I/usr/include/libxml2"], [
          AC_MSG_NOTICE([Testing in /usr/local/include/libxml2])
          CPPFLAGS="-I/usr/local/include/libxml2 $SAVED_CPPFLAGS"
          unset ac_cv_header_libxml_parser_h
          AC_CHECK_HEADERS([libxml/parser.h], [LIBXML2_CFLAGS="$LIBXML2_CFLAGS -I/usr/local/include/libxml2"], [
            AC_MSG_NOTICE([Failed to find libxml2 header file libxml/parser.h])
          ])
        ])
        CPPFLAGS="$SAVED_CPPFLAGS"
      ])
    ])
  ])
  CPPFLAGS="$CPPFLAGS $LIBXML2_CFLAGS"
  dnl Now that we know where to look find the headers...
  AC_CHECK_HEADERS(libxml/parser.h libxml/HTMLparser.h libxml/HTMLtree.h)
  SQUID_STATE_ROLLBACK([squid_libxml2_save])

  if test "x$LIBXML2_LIBS" != "x"; then
    HAVE_LIBXML2=1
    squid_opt_use_esi=yes
    SQUID_CXXFLAGS="$SQUID_CXXFLAGS $LIBXML2_CFLAGS"
    CPPFLAGS="$CPPFLAGS $LIBXML2_CFLAGS"
    XMLLIB="$LIBXML2_LIBS"
    AC_DEFINE_UNQUOTED(HAVE_LIBXML2, $HAVE_LIBXML2, [Define to 1 if you have the libxml2 library])
  elif test "x$with_libxml2" = "xyes"; then
    AC_MSG_ERROR([Required library libxml2 not found])
  else
    AC_MSG_NOTICE([Library libxml2 not found.])
  fi
fi

AS_IF([test "x$squid_opt_use_esi" = "xyes"],[
  AS_IF(test "x$HAVE_LIBXML2" = "x0" -a "x$HAVE_LIBEXPAT" = "x0",[
    AC_MSG_ERROR([ESI processor requires libxml2 or libexpat])
  ])
  AC_MSG_NOTICE([Enabling ESI processor: $EXPATLIB $XMLLIB])
  AC_DEFINE(USE_SQUID_ESI,1,[Compile the ESI processor])
],[
  AS_IF(test "x$squid_opt_use_esi" = "xno",[
    AC_MSG_NOTICE([Disabling ESI processor.])
  ],[
    AC_MSG_NOTICE([Disabling ESI processor. libxml2 and libexpat not found.])
  ])
])
AM_CONDITIONAL(ENABLE_ESI, test "x$squid_opt_use_esi" = "xyes")
AM_CONDITIONAL(ENABLE_LIBEXPAT, test "x$HAVE_LIBEXPAT" = "x1")
AC_SUBST(EXPATLIB)
AM_CONDITIONAL(ENABLE_LIBXML2, test "x$HAVE_LIBXML2" = "x1")
AC_SUBST(XMLLIB)

# icap argument handling
AC_ARG_ENABLE(icap-client,
  AS_HELP_STRING([--disable-icap-client],[Disable the ICAP client.]),[
  SQUID_YESNO([$enableval],[Unrecognized argument to --disable-icap-client: $enableval])
])
SQUID_DEFINE_BOOL(ICAP_CLIENT,${enable_icap_client:=yes}, [Enable ICAP client features in Squid])
AS_IF(test "x$enable_icap_client" != "xno", squid_opt_use_adaptation="yes")
AM_CONDITIONAL(ENABLE_ICAP_CLIENT, test "x$enable_icap_client" != "xno")

squid_opt_use_ecap=1
AC_MSG_CHECKING(whether to support eCAP)
AC_ARG_ENABLE(ecap,
  AS_HELP_STRING([--enable-ecap],[support loadable content adaptation modules]), [
    case "${enableval}" in
       yes|no) squid_opt_use_ecap=$enableval ;;
       *) AC_MSG_ERROR(bad value ${enableval} for --enable-ecap) ;;
    esac
AC_MSG_RESULT([$squid_opt_use_ecap, explicitly])
    ], [
        squid_opt_use_ecap=no;
        AC_MSG_RESULT([$squid_opt_use_ecap, implicitly])
    ]
)

dnl Perform configuration consistency checks for eCAP
if test "x$squid_opt_use_ecap" != "xno";
then
  dnl eCAP support requires loadable modules, which are enabled by default
  if test "x$enable_loadable_modules" != "xyes"
  then
    AC_MSG_ERROR([eCAP support requires loadable modules. Please do not use --disable-loadable-modules with --enable-ecap.])
  fi

  if test -n "$PKG_CONFIG"; then
    dnl eCAP support requires libecap.
    dnl This Squid supports libecap v1.0.x.
    dnl Use EXT_ prefix to distinguish external libecap (that we check for
    dnl here) from our own convenience ecap library in Makefiles.
    PKG_CHECK_MODULES([EXT_LIBECAP],[libecap >= 1.0 libecap < 1.1])
  else
    AC_MSG_NOTICE([eCAP support requires pkg-config to verify the correct library version. Trouble may follow.])
  fi

  SQUID_STATE_SAVE(squid_ecap_state)
  AC_MSG_CHECKING([whether -lecap will link])
  CXXFLAGS="$CXXFLAGS $EXT_LIBECAP_CFLAGS"
  LIBS="$LIBS $EXT_LIBECAP_LIBS"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <libecap/common/names.h>]],[[
    const libecap::Name test("test", libecap::Name::NextId());
  ]])],[
    AC_MSG_RESULT(yes)
    squid_opt_use_adaptation=yes
  ],[
    AC_MSG_RESULT(no)
    AS_IF(
      test "x$squid_opt_use_ecap" = "xyes", AC_MSG_ERROR([eCAP library will not link.
                  You may need to rebuild libecap using the same version of GCC as Squid.
                  There have been breaking ABI changes in the libstdc++ STL with GCC 5.]),

    [AC_MSG_NOTICE([eCAP library will not link.
                  You may need to rebuild libecap using the same version of GCC as Squid.
                  There have been breaking ABI changes in the libstdc++ STL with GCC 5.])
      squid_opt_use_ecap="no"
    ])
  ])
  SQUID_STATE_ROLLBACK(squid_ecap_state)
fi
SQUID_DEFINE_BOOL(USE_ECAP,${squid_opt_use_ecap:=no},[Whether to use eCAP support])
AM_CONDITIONAL(ENABLE_ECAP, test "x$squid_opt_use_ecap" = "xyes")

dnl enable adaptation if requested by specific adaptation mechanisms
ADAPTATION_LIBS=""
if test "x$squid_opt_use_adaptation" = "xyes"; then
    ADAPTATION_LIBS="adaptation/libadaptation.la"
fi
SQUID_DEFINE_BOOL(USE_ADAPTATION,${squid_opt_use_adaptation:=no}, [common adaptation support])
AM_CONDITIONAL(ENABLE_ADAPTATION, test "x$squid_opt_use_adaptation" = "xyes")
AC_SUBST(ADAPTATION_LIBS)

test "x$squid_host_os" = "xmingw" && enable_wccp=no
AC_ARG_ENABLE(wccp,
  AS_HELP_STRING([--disable-wccp],[Disable Web Cache Coordination Protocol]), [
SQUID_YESNO([$enableval],[unrecognized argument to --disable-wccp: $enableval])
])
SQUID_DEFINE_BOOL(USE_WCCP, ${enable_wccp:=yes}, [Define to enable WCCP])
AC_MSG_NOTICE([Web Cache Coordination Protocol enabled: $enable_wccp])

test "x$squid_host_os" = "xmingw" && enable_wccpv2=no
AC_ARG_ENABLE(wccpv2,
  AS_HELP_STRING([--disable-wccpv2],
                 [Disable Web Cache Coordination V2 Protocol]), [ 
SQUID_YESNO([$enableval],
            [unrecognized argument to --disable-wccpv2: $enableval])
])
SQUID_DEFINE_BOOL(USE_WCCPv2,${enable_wccpv2:=yes},
            [Define to enable WCCP V2])
AC_MSG_NOTICE([Web Cache Coordination V2 Protocol enabled: $enable_wccpv2])

AC_ARG_ENABLE(kill-parent-hack,
  AS_HELP_STRING([--enable-kill-parent-hack],[Kill parent on shutdown]), [ 
SQUID_YESNO([$enableval],
            [unrecognized argument to --enable-kill-parent-hack: $enableval])
])
SQUID_DEFINE_BOOL(KILL_PARENT_OPT,${enable_kill_parent_hack:=no},
                   [A dangerous feature which causes Squid to kill its parent 
                    process (presumably the RunCache script) upon receipt 
                    of SIGTERM or SIGINT. Deprecated, Use with caution.])
AC_MSG_NOTICE([Kill parent on shutdown hack enabled: $enable_kill_parent_hack])

AC_ARG_ENABLE(snmp,
  AS_HELP_STRING([--disable-snmp],[Disable SNMP monitoring support]), [
  SQUID_YESNO([$enableval],
              [unrecognized argument to --disable-snmp: $enableval])
])
SQUID_DEFINE_BOOL(SQUID_SNMP,${enable_snmp:=yes},
   [Define to enable SNMP monitoring of Squid])
AM_CONDITIONAL(ENABLE_SNMP, [test "x$enable_snmp" = "xyes"])
if test "x$enable_snmp" = "xyes"; then
    SNMPLIB='../lib/snmplib/libsnmplib.la'
fi
AC_MSG_NOTICE([SNMP support enabled: $enable_snmp])
AC_SUBST(SNMPLIB)

AC_ARG_ENABLE(cachemgr-hostname,
  AS_HELP_STRING([--enable-cachemgr-hostname=hostname],
                 [Make cachemgr.cgi default to this host.
                  If unspecified, uses the name of the build-host]), [
  case $enableval in
  yes)
    AC_DEFINE(CACHEMGR_HOSTNAME,[getfullhostname()],
    [If you are upset that the cachemgr.cgi form comes up with the hostname field blank, then define this to getfullhostname()])
    AC_MSG_NOTICE([Cachemgr default hostname == host where cachemgr runs])
    ;;
  no)
    : # Nothing to do..
   ;;
  *)
    AC_DEFINE_UNQUOTED(CACHEMGR_HOSTNAME,"${enableval}")
    AC_MSG_NOTICE([Cachemgr default hostname set to ${enableval}])
    ;;
  esac
])

AC_ARG_ENABLE(eui,
  AS_HELP_STRING([--disable-eui],
                 [Disable use of ARP / MAC/ EUI (ether address)]), [
SQUID_YESNO([$enableval],[--disable-eui expects no arguments])
])
if test "x${enable_eui:=yes}" = "xyes" ; then
  case "$squid_host_os" in
    linux|solaris|freebsd|openbsd|netbsd|cygwin)
      ${TRUE}
      ;;
    mingw)
      EUILIB="-liphlpapi"
      ;;
    *)
      AC_MSG_WARN([EUI support probably will not work on host $host.])
      ;;
  esac
  # iphlpapi.h check delayed after winsock2.h
  AC_CHECK_HEADERS( \
    windows.h \
    sys/sockio.h \
    sys/param.h,
  [], [], [[
#if HAVE_WINDOWS_H
include <windows.h>
#endif
]]
  )
  AC_CHECK_HEADERS( \
    net/if_arp.h \
    net/route.h, 
  [], [], [[
#include <sys/types.h>
#include <sys/socket.h>
]])

  # OpenBSD, FreeBSD and NetBSD requires sys/param.h to be included before sysctl.h and net/if_dl.h
  AC_CHECK_HEADERS( \
    net/if_dl.h \
    sys/sysctl.h,
  [], [], [[
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
  ]])
fi
AC_SUBST(EUILIB)
AC_MSG_NOTICE([EUI (MAC address) controls enabled: $enable_eui])
SQUID_DEFINE_BOOL(USE_SQUID_EUI,$enable_eui,
   [Define this to include code which lets you use ethernet addresses. This code uses API initially defined in 4.4-BSD.])
AM_CONDITIONAL(ENABLE_EUI, [test "x$enable_eui" = "xyes" ])


AC_ARG_ENABLE(htcp,
  AS_HELP_STRING([--disable-htcp],[Disable HTCP protocol support]), [
SQUID_YESNO([$enableval],
            [unrecognized argument to --disable-htcp: $enableval])
])
SQUID_DEFINE_BOOL(USE_HTCP,${enable_htcp:=yes},
   [Define this to include code for the Hypertext Cache Protocol (HTCP)])
AM_CONDITIONAL(ENABLE_HTCP, [test "x$enable_htcp" = "xyes"])
AC_MSG_NOTICE([HTCP support enabled: $enable_htcp])

# Cryptograhic libraries
AC_ARG_WITH(nettle,
  AS_HELP_STRING([--without-nettle],[Compile without the Nettle crypto library.]),[
case "$with_nettle" in
  yes|no)
    : # Nothing special to do here
    ;;
  *)
    if test ! -d "$withval" ; then
      AC_MSG_ERROR([--with-nettle path does not point to a directory])
    fi
    NETTLELIBDIR="-L$with_nettle/lib"
    CPPFLAGS="-I$with_nettle/include $CPPFLAGS"
    with_nettle=yes
  esac
])
if test "x$with_nettle" != "xno" ; then
  AC_CHECK_LIB(nettle, nettle_md5_init,[
    NETTLELIB="$NETTLELIBDIR -lnettle"
    AC_CHECK_HEADERS(nettle/md5.h)
  ],[with_nettle=no])
  if test "x$with_nettle" != "xno" ; then
    # Base64 uses the nettle 3.4 API
    # which matters on 64-bit systems
    AC_CHECK_HEADERS(nettle/base64.h)
    AC_MSG_CHECKING([for Nettle 3.4 API compatibility])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#     include <cstddef>
#     include <cstdint>
#     include <nettle/base64.h>
    ]],[[
      char inData[10]; inData[0] = '\0';
      size_t srcLen = 0;
      struct base64_decode_ctx ctx;
      base64_decode_init(&ctx);
      uint8_t outData[10];
      size_t dstLen = 0;
      if (!base64_decode_update(&ctx, &dstLen, outData, srcLen, inData) ||
              !base64_decode_final(&ctx)) {
          return 1;
      }
    ]])],[AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_NETTLE34_BASE64,1,[set to 1 if Nettle 3.4 API will link])
    ],[AC_MSG_RESULT(no)])
  fi
fi
AC_MSG_NOTICE([Using Nettle cryptographic library: ${with_nettle:=yes}])
AC_SUBST(NETTLELIB)

dnl Check for libcrypt
CRYPTLIB=
dnl Some of our helpers use crypt(3) which may be in libc, or in
dnl libcrypt (eg FreeBSD)
AC_CHECK_LIB(crypt, crypt, [CRYPTLIB="-lcrypt"])
dnl Solaris10 provides MD5 natively through libmd5
AC_CHECK_LIB(md5, MD5Init, [CRYPTLIB="$CRYPTLIB -lmd5"])
AC_SUBST(CRYPTLIB)

SSLLIB=""

dnl User may want to disable GnuTLS
AC_ARG_WITH(gnutls,
  AS_HELP_STRING([--without-gnutls],
                 [Do not use GnuTLS for SSL. Default: auto-detect]), [ 
case "$with_gnutls" in
  yes|no)
    : # Nothing special to do here
    ;;
  *)
    if test ! -d "$withval" ; then
      AC_MSG_ERROR([--with-gnutls path does not point to a directory])
    fi
    LIBGNUTLS_PATH="-L$with_gnutls/lib"
    CPPFLAGS="-I$with_gnutls/include $CPPFLAGS"
  esac
])
AH_TEMPLATE(USE_GNUTLS,[GnuTLS support is available])
if test "x$with_gnutls" != "xno"; then
  SQUID_STATE_SAVE(squid_gnutls_state)

  # User may have provided a custom location for GnuTLS. Otherwise...
  LIBS="$LIBS $LIBGNUTLS_PATH"

  # auto-detect using pkg-config
  PKG_CHECK_MODULES([LIBGNUTLS],[gnutls >= 3.4.0],[
    CPPFLAGS="$CPPFLAGS $LIBGNUTLS_CFLAGS"
    ],[
    ## find the package without pkg-config
    ## check that the library is actually new enough.
    ## by testing for a 3.4.0+ function which we use
    AC_CHECK_LIB(gnutls,gnutls_pcert_export_x509,[LIBGNUTLS_LIBS="-lgnutls"])
  ])
  AC_CHECK_HEADERS(gnutls/gnutls.h gnutls/x509.h gnutls/abstract.h)

  SQUID_STATE_ROLLBACK(squid_gnutls_state) #de-pollute LIBS

  if test "x$with_gnutls" = "xyes" -a "x$LIBGNUTLS_LIBS" = "x"; then
    AC_MSG_ERROR([Required GnuTLS library not found])
  fi
  if test "x$LIBGNUTLS_LIBS" != "x" ; then
    CXXFLAGS="$LIBGNUTLS_CFLAGS $CXXFLAGS"
    SSLLIB="$LIBGNUTLS_PATH $LIBGNUTLS_LIBS $SSLLIB"
    AC_DEFINE(USE_GNUTLS,1,[GnuTLS support is available])
  else
    with_gnutls=no
  fi
fi
AC_MSG_NOTICE([GnuTLS library support: ${with_gnutls:=auto} ${LIBGNUTLS_PATH} ${LIBGNUTLS_LIBS}])

dnl User may specify OpenSSL is needed from a non-standard location
AC_ARG_WITH(openssl,
  AS_HELP_STRING([--with-openssl=PATH],
                 [Compile with the OpenSSL libraries. The path to
                  the OpenSSL development libraries and headers
                  installation can be specified if outside of the
                  system standard directories]), [ 
case "$with_openssl" in
  yes|no)
    : # Nothing special to do here
    ;;
  *)
    if test ! -d "$withval" ; then
      AC_MSG_ERROR([--with-openssl path does not point to a directory])
    fi
    LIBOPENSSL_PATH="-L$with_openssl/lib"
    CPPFLAGS="-I$with_openssl/include $CPPFLAGS"
    with_openssl=yes
  esac
])
AH_TEMPLATE(USE_OPENSSL,[OpenSSL support is available])
## OpenSSL is default disable due to licensing issues on some OS
if test "x$with_openssl" = "xyes"; then
  AC_CHECK_HEADERS( \
    openssl/asn1.h \
    openssl/bio.h \
    openssl/bn.h \
    openssl/crypto.h \
    openssl/dh.h \
    openssl/err.h \
    openssl/evp.h \
    openssl/lhash.h \
    openssl/md5.h \
    openssl/opensslv.h \
    openssl/rsa.h \
    openssl/ssl.h \
    openssl/x509.h \
    openssl/x509v3.h \
    openssl/engine.h \
    openssl/txt_db.h \
  )

  # User may have provided a custom location for OpenSSL. Otherwise...
  SQUID_STATE_SAVE(squid_openssl_state)
  LIBS="$LIBS $LIBOPENSSL_PATH"

  # auto-detect using pkg-config
  PKG_CHECK_MODULES([LIBOPENSSL],[openssl],,[
    ## For some OS pkg-config is broken or unavailable.
    ## Detect libraries the hard way.

    # Windows MinGW has some special libraries ...
    if test "x$squid_host_os" = "xmingw" ; then
      LIBOPENSSL_LIBS='-lssleay32 -leay32 -lgdi32 $LIBOPENSSL_LIBS'
      AC_MSG_NOTICE([Windows OpenSSL library support: yes -lssleay32 -leay32 -lgdi32])
    fi

    AC_CHECK_LIB(crypto,[CRYPTO_new_ex_data],[LIBOPENSSL_LIBS="-lcrypto $LIBOPENSSL_LIBS"],[
      AC_MSG_ERROR([library 'crypto' is required for OpenSSL])
    ],$LIBOPENSSL_LIBS)
    AC_CHECK_LIB(ssl,[SSL_library_init],[LIBOPENSSL_LIBS="-lssl $LIBOPENSSL_LIBS"],[
      AC_MSG_ERROR([library 'ssl' is required for OpenSSL])
    ],$LIBOPENSSL_LIBS)
  ])

  # This is a workaround for RedHat 9 brain damage..
  if test -d /usr/kerberos/include -a -f /usr/include/openssl/kssl.h; then
    AC_MSG_NOTICE([OpenSSL depends on Kerberos])
    LIBOPENSSL_LIBS="-L/usr/kerberos/lib $LIBOPENSSL_LIBS"
    CPPFLAGS="$CPPFLAGS -I/usr/kerberos/include"
  fi
  SQUID_STATE_ROLLBACK(squid_openssl_state) #de-pollute LIBS

  if test "x$LIBOPENSSL_LIBS" != "x"; then
    CXXFLAGS="$LIBOPENSSL_CFLAGS $CXXFLAGS"
    SSLLIB="$LIBOPENSSL_PATH $LIBOPENSSL_LIBS $SSLLIB"
    AC_DEFINE(USE_OPENSSL,1,[OpenSSL support is available])

    # check for API functions
    SQUID_CHECK_LIBCRYPTO_API
    SQUID_CHECK_LIBSSL_API
    SQUID_CHECK_OPENSSL_TLS_METHODS
    SQUID_STATE_SAVE(check_SSL_CTX_get0_certificate)
    LIBS="$LIBS $SSLLIB"
    AC_CHECK_LIB(ssl, SSL_CTX_get0_certificate, [
      AC_DEFINE(HAVE_SSL_CTX_GET0_CERTIFICATE, 1, [SSL_CTX_get0_certificate is available])
      ], [
          missing_SSL_CTX_get0_certificate=yes
      ])
    SQUID_STATE_ROLLBACK(check_SSL_CTX_get0_certificate)

    # check for other specific broken implementations
    if test "x$missing_SSL_CTX_get0_certificate" = "xyes"; then
      SQUID_CHECK_OPENSSL_GETCERTIFICATE_WORKS
    fi
    SQUID_CHECK_OPENSSL_CONST_SSL_METHOD
    SQUID_CHECK_OPENSSL_CONST_CRYPTO_EX_DATA
    SQUID_CHECK_OPENSSL_CONST_SSL_SESSION_CB_ARG
    SQUID_CHECK_OPENSSL_CONST_X509_GET0_SIGNATURE_ARGS
    SQUID_CHECK_OPENSSL_TXTDB
    SQUID_CHECK_OPENSSL_HELLO_OVERWRITE_HACK
  fi
  if test "x$SSLLIB" = "x"; then
    AC_MSG_ERROR([Required OpenSSL library not found])
  fi
fi
AC_MSG_NOTICE([OpenSSL library support: ${with_openssl:=no} ${LIBOPENSSL_PATH} ${LIBOPENSSL_LIBS}])
AM_CONDITIONAL(ENABLE_SSL,[ test "x$with_openssl" = "xyes" ])
AC_SUBST(SSLLIB)

dnl User may specify MIT Kerberos is needed from a non-standard location
AC_ARG_WITH(mit-krb5,
  AS_HELP_STRING([--without-mit-krb5],
		 [Compile without MIT Kerberos support.]), [
case "$with_mit_krb5" in
  yes|no)
    : # Nothing special to do here
    ;;
  *)
    if test ! -d "$withval" ; then
      AC_MSG_ERROR([--with-mit-krb5 path does not point to a directory])
    fi
    if test -d "$with_mit_krb5/lib64" ; then
      LIB_KRB5_PATH="-L$with_mit_krb5/lib64 -L$with_mit_krb5/lib"
    else
      LIB_KRB5_PATH="-L$with_mit_krb5/lib"
    fi
    CXXFLAGS="-I$with_mit_krb5/include $CXXFLAGS"
    krb5confpath="$with_mit_krb5/bin"
    with_mit_krb5=yes
esac
])
AH_TEMPLATE(USE_APPLE_KRB5,[Apple Kerberos support is available])
AH_TEMPLATE(USE_MIT_KRB5,[MIT Kerberos support is available])
AH_TEMPLATE(USE_SOLARIS_KRB5,[Solaris Kerberos support is available])

## find out if pkg-config or krb5-config will work
if test "x$with_mit_krb5" != "xno"; then
  # find installed libs via pkg-config or krb5-config
  squid_pc_krb5_name=
  PKG_CHECK_EXISTS(mit-krb5-gssapi mit-krb5, [squid_pc_krb5_name="mit-krb5-gssapi mit-krb5"],[
    PKG_CHECK_EXISTS(gssapi-krb5 krb5, [squid_pc_krb5_name="gssapi-krb5 krb5"])
  ])
  if test "x$squid_pc_krb5_name" = "x" -a "$cross_compiling" = "no"; then
    # Look for krb5-config (unless cross-compiling)
    AC_PATH_PROG(krb5_config,krb5-config,no,$krb5confpath)
    if test "x$ac_cv_path_krb5_config" != "xno" ; then
      krb5confpath="`dirname $ac_cv_path_krb5_config`"
      ac_heimdal="`$ac_cv_path_krb5_config --version 2>/dev/null | grep -c -i heimdal`"
      ac_solaris="`$ac_cv_path_krb5_config --version 2>/dev/null | grep -c -i solaris`"
      ac_apple="`$ac_cv_path_krb5_config --vendor 2>/dev/null | grep -c -i apple`"
      if test $ac_solaris -gt 0 ; then
	with_solaris_krb5=yes
      elif test $ac_apple -gt 0 ; then
	with_apple_krb5=yes
      elif test $ac_heimdal -gt 0; then
	with_mit_krb5=no
        if test "x$with_mit_krb5" = "xyes"; then
          AC_MSG_ERROR([Could not find pkg-config or krb5-config for MIT Kerberos])
        fi
      fi
    else
      if test "x$with_mit_krb5" = "xyes"; then
        AC_MSG_ERROR([Could not find krb5-config in path])
      else
        with_mit_krb5=no
      fi
    fi
  fi
fi

# detect MIT Kerberos dependencies (except on Solaris)
if test "x$with_mit_krb5" != "xno" -a "x$with_solaris_krb5" != "xyes"; then
  SQUID_STATE_SAVE([squid_krb5_save])
  LIBS="$LIBS $LIB_KRB5_PATH"

  # auto-detect using pkg-config
  PKG_CHECK_MODULES([LIB_KRB5], $squid_pc_krb5_name,,[
    # look for krb5-config (unless cross-compiling)
    if test "$cross_compiling" = "no"; then
      if test "x$krb5confpath" = "x" ; then
        AC_PATH_PROG(krb5_config,krb5-config,no)
        if test "x$ac_cv_path_krb5_config" != "xno" ; then
          ac_krb5_config="$ac_cv_path_krb5_config"
        fi
      else
        ac_krb5_config="$krb5confpath/krb5-config"
      fi
    fi
    if test "x$ac_krb5_config" != "x" && test -x "$ac_krb5_config"; then
      # Get libs, etc
      AC_MSG_NOTICE([Use krb5-config to get CXXFLAGS and LIBS])
      LIB_KRB5_CFLAGS="`$ac_krb5_config --cflags krb5 2>/dev/null`"
      LIB_KRB5_LIBS="`$ac_krb5_config --libs krb5 2>/dev/null`"
      LIB_KRB5_CFLAGS="`$ac_krb5_config --cflags gssapi 2>/dev/null` $LIB_KRB5_CFLAGS"
      LIB_KRB5_LIBS="`$ac_krb5_config --libs gssapi 2>/dev/null` $LIB_KRB5_LIBS"
    else
      ## For some OS pkg-config is broken or unavailable.
      ## Detect libraries the hard way.

      SQUID_STATE_SAVE([squid_mit_save])
      missing_required=
      AC_MSG_NOTICE([Try to find Kerberos libraries in given path])
      AC_CHECK_LIB(com_err, [main], [LIB_KRB5_LIBS="-lcom_err $LIB_KRB5_LIBS"],[
        AC_MSG_WARN([library 'com_err' is required for MIT Kerberos])
        missing_required=yes
      ])
      LIBS=$LIB_KRB5_LIBS
      AC_CHECK_LIB(k5crypto, [main], [LIB_KRB5_LIBS="-lk5crypto $LIB_KRB5_LIBS"],[
        AC_MSG_WARN([library 'k5crypto' is required for MIT Kerberos])
        missing_required=yes
      ])
      LIBS=$LIB_KRB5_LIBS
      AC_CHECK_LIB(krb5, [main], [LIB_KRB5_LIBS="-lkrb5 $LIB_KRB5_LIBS"],[
        AC_MSG_WARN([library 'krb5' is required for MIT Kerberos])
        missing_required=yes
      ])
      LIBS=$LIB_KRB5_LIBS
      AC_CHECK_LIB(gssapi_krb5, [main], [LIB_KRB5_LIBS="-lgssapi_krb5 $LIB_KRB5_LIBS"],[
        AC_MSG_WARN([library 'gssapi_krb5' is required for MIT Kerberos])
        missing_required=yes
      ])
      SQUID_STATE_ROLLBACK([squid_mit_save])
      if test "x$missing_required" = "xyes"; then
        LIB_KRB5_LIBS=""
      fi
    fi
  ])

  if test "x$LIB_KRB5_LIBS" != "x"; then
    if test "x$with_apple_krb5" = "xyes" ; then
      AC_DEFINE(USE_APPLE_KRB5,1,[Apple Kerberos support is available])
      KRB5_FLAVOUR="Apple" 
    else
      AC_DEFINE(USE_MIT_KRB5,1,[MIT Kerberos support is available])
      KRB5_FLAVOUR="MIT" 
    fi
    KRB5LIBS="$LIB_KRB5_PATH $LIB_KRB5_LIBS $KRB5LIBS"
    KRB5INCS="$LIB_KRB5_CFLAGS"
    
    # check for other specific broken implementations
    CXXFLAGS="$CXXFLAGS $KRB5INCS"
    LIBS="$LIBS $KRB5LIBS"

    AC_MSG_NOTICE([Try to find Kerberos headers in given path])
    AC_CHECK_HEADERS(gssapi.h gssapi/gssapi.h gssapi/gssapi_krb5.h)
    AC_CHECK_HEADERS(gssapi/gssapi_generic.h)
    AC_CHECK_HEADERS(krb5.h com_err.h et/com_err.h)
    AC_CHECK_HEADERS(profile.h)

    SQUID_CHECK_KRB5_FUNCS
  fi
  if test "x$with_mit_krb5" = "xyes" -a "x$KRB5LIBS" = "x"; then
    AC_MSG_ERROR([Required Kerberos library not found])
  elif test "x$KRB5LIBS" = "x"; then
    with_mit_krb5=no
    with_apple_krb5=no
  fi
  SQUID_STATE_ROLLBACK([squid_krb5_save])
fi

# detect Solaris Kerberos dependencies
if test "x$with_solaris_krb5" = "xyes" -a "x$KRB5LIBS" = "x"; then
  SQUID_STATE_SAVE([squid_krb5_save])
  LIBS="$LIBS $LIB_KRB5_PATH"

  # no pkg-config for solaris native Kerberos
  # look for krb5-config (unless cross-compiling)
  if test "$cross_compiling" = "no"; then
    if test "x$krb5confpath" = "x" ; then
      AC_PATH_PROG(krb5_config,krb5-config,no)
      if test "x$ac_cv_path_krb5_config" != "xno" ; then
        ac_krb5_config="$ac_cv_path_krb5_config"
      fi
    else
      ac_krb5_config="$krb5confpath/krb5-config"
    fi
  fi
  if test "x$ac_krb5_config" != "x" && test -x "$ac_krb5_config"; then
    # Get libs, etc
    AC_MSG_NOTICE([Use krb5-config to get CXXFLAGS and LIBS])
    LIB_KRB5_CFLAGS="`$ac_krb5_config --cflags krb5 2>/dev/null`"
    LIB_KRB5_LIBS="`$ac_krb5_config --libs krb5 2>/dev/null`"
    # Solaris 10 Update 11 patches the krb5-config tool to produce stderr messages on stdout.
    SOLARIS_BROKEN_KRB5CONFIG_GSSAPI="`$ac_krb5_config --libs gssapi 2>/dev/null | grep "krb5-config"`"
    if test "x$SOLARIS_BROKEN_KRB5CONFIG_GSSAPI" = "x"; then
      LIB_KRB5_CFLAGS="`$ac_krb5_config --cflags gssapi 2>/dev/null` $LIB_KRB5_CFLAGS"
      LIB_KRB5_LIBS="`$ac_krb5_config --libs gssapi 2>/dev/null` $LIB_KRB5_LIBS"
    fi
  else
    ## For some OS pkg-config is broken or unavailable.
    ## Detect libraries the hard way.

    CXXFLAGS="-I/usr/include/kerberosv5 $CXXFLAGS"

    SQUID_STATE_SAVE([squid_solaris_save])
    missing_required=
    AC_MSG_NOTICE([Try to find Kerberos libraries in given path])
    AC_CHECK_LIB(krb5, [main], [LIB_KRB5_LIBS="-lkrb5 $LIB_KRB5_LIBS"],[
      AC_MSG_WARN([library 'krb5' is required for Solaris Kerberos])
        missing_required=yes
    ])
    LIBS=$LIB_KRB5_LIBS
    AC_CHECK_LIB(gss, [main], [LIB_KRB5_LIBS="-lgss $LIB_KRB5_LIBS"],[
      AC_MSG_WARN([library 'gss' is required for Solaris Kerberos])
        missing_required=yes
    ])
    SQUID_STATE_ROLLBACK([squid_solaris_save])
    if test "x$missing_required" = "xyes"; then
      LIB_KRB5_LIBS=""
    fi
  fi

  if test "x$LIB_KRB5_LIBS" != "x"; then
    KRB5LIBS="$LIB_KRB5_PATH $LIB_KRB5_LIBS $KRB5LIBS"
    KRB5INCS="$LIB_KRB5_CFLAGS"
    AC_DEFINE(USE_SOLARIS_KRB5,1,[Solaris Kerberos support is available])
    KRB5_FLAVOUR="Solaris" 
    
    # check for other specific broken implementations
    CXXFLAGS="$CXXFLAGS $KRB5INCS"
    LIBS="$LIBS $KRB5LIBS"

    AC_MSG_NOTICE([Try to find Kerberos headers in given path])
    AC_CHECK_HEADERS(gssapi/gssapi.h gssapi/gssapi_ext.h)
    AC_CHECK_HEADERS(krb5.h com_err.h)

    SQUID_CHECK_KRB5_SOLARIS_BROKEN_KRB5_H
    if test "x$squid_cv_broken_krb5_h" = "xyes"; then
      AC_DEFINE(HAVE_BROKEN_SOLARIS_KRB5_H, 1, [Define to 1 if Solaris krb5.h is broken for C++])
      AC_MSG_WARN([You have a broken Solaris <krb5.h> system include.])
      AC_MSG_WARN([Please see http://bugs.opensolaris.org/bugdatabase/view_bug.do?bug_id=6837512])
      AC_MSG_WARN([If you need Kerberos support you will have to patch])
      AC_MSG_WARN([your system. See contrib/solaris/solaris-krb5-include.patch])
    fi
    SQUID_CHECK_KRB5_FUNCS
  fi
  if test "x$with_mit_krb5" = "xyes" -a "x$KRB5LIBS" = "x"; then
    # Error only if Solaris flavour was detected while looking for required MIT Kerberos
    AC_MSG_ERROR([Required Kerberos library not found])
  elif test "x$KRB5LIBS" = "x"; then
    with_solaris_krb5=no
    with_mit_krb5=no
  fi
  SQUID_STATE_ROLLBACK([squid_krb5_save])
fi

dnl User may specify Heimdal Kerberos is needed from a non-standard location
AC_ARG_WITH(heimdal-krb5,
  AS_HELP_STRING([--without-heimdal-krb5],
		 [Compile without Heimdal Kerberos support.]), [
case "$with_heimdal_krb5" in
  yes|no)
    : # Nothing special to do here
    ;;
  *)
    if test ! -d "$withval" ; then
      AC_MSG_ERROR([--with-heimdal-krb5 path does not point to a directory])
    fi
    if test -d "$with_heimdal_krb5/lib64" ; then
      LIB_KRB5_PATH="-L$with_heimdal_krb5/lib64 -L$with_heimdal_krb5/lib"
    else 
      LIB_KRB5_PATH="-L$with_heimdal_krb5/lib"
    fi
    CXXFLAGS="-I$with_heimdal_krb5/include $CXXFLAGS"
    krb5confpath="$with_heimdal_krb5/bin"
    with_heimdal_krb5=yes
esac
])
AH_TEMPLATE(USE_HEIMDAL_KRB5,[Heimdal Kerberos support is available])
if test "x$with_heimdal_krb5" != "xno" -a "x$KRB5LIBS" = "x"; then
  # find installed libs via pkg-config or krb5-config
  PKG_CHECK_EXISTS(heimdal-krb5, [squid_pc_krb5_name="heimdal-krb5"])
  if test "x$squid_pc_krb5_name" = "x"; then
    PKG_CHECK_EXISTS(heimdal-gssapi, [squid_pc_krb5_name="heimdal-gssapi"])
  fi
  if test "x$squid_pc_krb5_name" = "x" -a "$cross_compiling" = "no"; then
    # Look for krb5-config (unless cross-compiling)
    AC_PATH_PROG(krb5_config,krb5-config,no,$krb5confpath)
    if test "x$ac_cv_path_krb5_config" != "xno" ; then
      krb5confpath="`dirname $ac_cv_path_krb5_config`"
      ac_heimdal="`$ac_cv_path_krb5_config --version 2>/dev/null | grep -c -i heimdal`"
      if test "x$with_heimdal_krb5" = "xyes" -a $ac_heimdal = 0; then
        AC_MSG_ERROR([Could not find pkg-config or krb5-config for Heimdal Kerberos])
      fi
    else
      if test "x$with_heimdal_krb5" = "xyes"; then
        AC_MSG_ERROR([Could not find krb5-config in path])
      else
        AC_MSG_WARN([Could not find krb5-config in path])
        with_heimdal_krb5=no
      fi
    fi
  fi
fi
if test "x$with_heimdal_krb5" != "xno" -a "x$KRB5LIBS" = "x"; then
  SQUID_STATE_SAVE([squid_krb5_save])
  LIBS="$LIBS $LIB_KRB5_PATH"

  # auto-detect using pkg-config
  PKG_CHECK_MODULES([LIB_KRB5], $squid_pc_krb5_name,,[
    # look for krb5-config (unless cross-compiling)
    if test "$cross_compiling" = "no"; then
      if test "x$krb5confpath" = "x" ; then
        AC_PATH_PROG(krb5_config,krb5-config,no)
        if test "x$ac_cv_path_krb5_config" != "xno" ; then
          ac_krb5_config="$ac_cv_path_krb5_config"
        fi
      else
        ac_krb5_config="$krb5confpath/krb5-config"
      fi
    fi
    if test "x$ac_krb5_config" != "x" -a -x "$ac_krb5_config"; then
      # Get libs, etc
      AC_MSG_NOTICE([Use krb5-config to get CXXFLAGS and LIBS])
      LIB_KRB5_CFLAGS="`$ac_krb5_config --cflags krb5 2>/dev/null`"
      LIB_KRB5_LIBS="`$ac_krb5_config --libs krb5 2>/dev/null`"
      LIB_KRB5_CFLAGS="`$ac_krb5_config --cflags gssapi 2>/dev/null` $LIB_KRB5_CFLAGS"
      LIB_KRB5_LIBS="`$ac_krb5_config --libs gssapi 2>/dev/null` $LIB_KRB5_LIBS"
    else
      ## For some OS pkg-config is broken or unavailable.
      ## Detect libraries the hard way.
      SQUID_STATE_SAVE([squid_heimdal_save])
      missing_required=
      AC_MSG_NOTICE([Try to find Kerberos libraries in given path])
      AC_CHECK_LIB(resolv, [main], [LIB_KRB5_LIBS="-lresolv $LIB_KRB5_LIBS"],[
        AC_MSG_WARN([library 'resolv' is required for Heimdal Kerberos])
        missing_required=yes
      ])
      LIBS=$LIB_KRB5_LIBS
      AC_CHECK_LIB(crypt, [main], [LIB_KRB5_LIBS="-lcrypt $LIB_KRB5_LIBS"],[
        AC_MSG_WARN([library 'crypt' is required for Heimdal Kerberos])
        missing_required=yes
      ])
      LIBS=$LIB_KRB5_LIBS
      AC_CHECK_LIB(roken, [main], [LIB_KRB5_LIBS="-lroken $LIB_KRB5_LIBS"],[
        AC_MSG_WARN([library 'roken' is required for Heimdal Kerberos])
        missing_required=yes
      ])
      LIBS=$LIB_KRB5_LIBS
      AC_CHECK_LIB(heimbase, [main], [LIB_KRB5_LIBS="-lheimbase $LIB_KRB5_LIBS"],[
        AC_MSG_WARN([library 'heimbase' may be required for Heimdal Kerberos])
      ])
      LIBS=$LIB_KRB5_LIBS
      AC_CHECK_LIB(wind, [main], [LIB_KRB5_LIBS="-lwind $LIB_KRB5_LIBS"],[
        AC_MSG_WARN([library 'wind' may be required for Heimdal Kerberos])
      ])
      LIBS=$LIB_KRB5_LIBS
      AC_CHECK_LIB(crypto, [main], [LIB_KRB5_LIBS="-lcrypto $LIB_KRB5_LIBS"],[
        AC_MSG_WARN([library 'crypto' is required for Heimdal Kerberos])
        missing_required=yes
      ])
      LIBS=$LIB_KRB5_LIBS
      AC_CHECK_LIB(com_err, [main], [LIB_KRB5_LIBS="-lcom_err $LIB_KRB5_LIBS"],[
        AC_MSG_WARN([library 'com_err' is required for Heimdal Kerberos])
        missing_required=yes
      ])
      LIBS=$LIB_KRB5_LIBS
      AC_CHECK_LIB(hx509, [main], [LIB_KRB5_LIBS="-lhx509 $LIB_KRB5_LIBS"],[
        AC_MSG_WARN([library 'hx509' may be required for Heimdal Kerberos])
      ])
      LIBS=$LIB_KRB5_LIBS
      AC_CHECK_LIB(asn1, [main], [LIB_KRB5_LIBS="-lasn1 $LIB_KRB5_LIBS"],[
        AC_MSG_WARN([library 'asn1' is required for Heimdal Kerberos])
        missing_required=yes
      ])
      LIBS=$LIB_KRB5_LIBS
      AC_CHECK_LIB(krb5, [main], [LIB_KRB5_LIBS="-lkrb5 $LIB_KRB5_LIBS"],[
        AC_MSG_WARN([library 'krb5' is required for Heimdal Kerberos])
        missing_required=yes
      ])
      LIBS=$LIB_KRB5_LIBS
      AC_CHECK_LIB(heimntlm, [main], [LIB_KRB5_LIBS="-lheimntlm $LIB_KRB5_LIBS"],[
        AC_MSG_WARN([library 'heimntlm' may be required for Heimdal Kerberos])
      ])
      LIBS=$LIB_KRB5_LIBS
      AC_CHECK_LIB(gssapi, [main], [LIB_KRB5_LIBS="-lgssapi $LIB_KRB5_LIBS"],[
        AC_MSG_WARN([library 'gssapi' is required for Heimdal Kerberos])
        missing_required=yes
      ])
      SQUID_STATE_ROLLBACK([squid_heimdal_save])
      if test "x$missing_required" = "xyes"; then
        LIB_KRB5_LIBS=""
      fi
    fi
  ])
  if test "x$LIB_KRB5_LIBS" != "x"; then
    KRB5LIBS="$LIB_KRB5_PATH $LIB_KRB5_LIBS $KRB5LIBS"
    KRB5INCS="$LIB_KRB5_CFLAGS"
    AC_DEFINE(USE_HEIMDAL_KRB5,1,[Heimdal Kerberos support is available])
    KRB5_FLAVOUR="Heimdal" 
    
    # check for other specific broken implementations
    CXXFLAGS="$CXXFLAGS $KRB5INCS"
    LIBS="$LIBS $KRB5LIBS"

    AC_MSG_NOTICE([Try to find Kerberos headers in given path])
    AC_CHECK_HEADERS(gssapi.h gssapi/gssapi.h gssapi/gssapi_krb5.h)
    AC_CHECK_HEADERS(krb5.h com_err.h et/com_err.h)

    SQUID_CHECK_KRB5_HEIMDAL_BROKEN_KRB5_H
    if test "x$squid_cv_broken_heimdal_krb5_h" = "xyes"; then
      AC_DEFINE(HAVE_BROKEN_HEIMDAL_KRB5_H, 1, [Define to 1 if Heimdal krb5.h is broken for C++])
    fi
    SQUID_CHECK_KRB5_FUNCS
  fi
  if test "x$KRB5LIBS" = "x"; then
    if test "x$with_heimdal_krb5" = "xyes"; then
      AC_MSG_ERROR([Required Heimdal Kerberos library not found])
    else
      AC_MSG_WARN([Heimdal Kerberos library not found])
    fi
  fi
  SQUID_STATE_ROLLBACK([squid_krb5_save])
fi

dnl User may specify GNU gss is needed from a non-standard location
AC_ARG_WITH(gnugss,
  AS_HELP_STRING([--without-gnugss],
		 [Compile without the GNU gss libraries.]), [
case "$with_gnugss" in
  yes|no)
    : # Nothing special to do here
    ;;
  *)
    if test ! -d "$withval" ; then
      AC_MSG_ERROR([--with-gnugss path does not point to a directory])
    fi
    if test ! -d "$with_gnugss/lib64" ; then
      LIB_KRB5_PATH="-L$with_gnugss/lib64 -L$with_gnugss/lib"
    else
      LIB_KRB5_PATH="-L$with_gnugss/lib"
    fi
    CXXFLAGS="-I$with_gnugss/include $CXXFLAGS"
    krb5confpath=
    with_gnugss=yes
esac
])
AH_TEMPLATE(USE_GNUGSS,[GNU gss support is available])
if test "x$with_gnugss" != "xno" -a "x$KRB5LIBS" = "x"; then
  SQUID_STATE_SAVE([squid_krb5_save])
  LIBS="$LIBS $LIB_KRB5_PATH"

  # auto-detect using pkg-config
  PKG_CHECK_MODULES([LIB_KRB5],[gss],,[
    ## For some OS pkg-config is broken or unavailable.
    ## Detect libraries the hard way.

    AC_MSG_NOTICE([Try to find Kerberos libraries in given path])
    AC_CHECK_LIB(gss, [main], [LIB_KRB5_LIBS="-lgss $LIB_KRB5_LIBS"],[
      AC_MSG_WARN([library 'com_err' is required for GNU Kerberos])
    ])
  ])

  if test "x$LIB_KRB5_LIBS" != "x"; then
    KRB5LIBS="$LIB_KRB5_PATH $LIB_KRB5_LIBS $KRB5LIBS"
    KRB5INCS="$LIB_KRB5_CFLAGS"
    AC_DEFINE(USE_GNUGSS,1,[GNU Kerberos support is available])
    KRB5_FLAVOUR="GNU GSS" 

    # check for other specific broken implementations
    CXXFLAGS="$CXXFLAGS $KRB5INCS"
    LIBS="$LIBS $KRB5LIBS"

    AC_MSG_NOTICE([Try to find Kerbeors headers in given path])
    AC_CHECK_HEADERS(gss.h)

    SQUID_CHECK_WORKING_GSSAPI
    SQUID_DEFINE_BOOL(HAVE_GSSAPI,$squid_cv_working_gssapi,[GSSAPI support])

    SQUID_CHECK_SPNEGO_SUPPORT
    SQUID_DEFINE_BOOL(HAVE_SPNEGO,$squid_cv_have_spnego,[SPNEGO support])

    SQUID_CHECK_WORKING_KRB5
    SQUID_DEFINE_BOOL(HAVE_KRB5,$squid_cv_working_krb5,[KRB5 support])
  fi
  if test "x$KRB5LIBS" = "x"; then
    if test "x$with_gnugss" = "xyes"; then
      AC_MSG_ERROR([Required GNU GSS Kerberos library not found])
    else
      AC_MSG_WARN([GNU GSS Kerberos library not found])
    fi
  fi
  SQUID_STATE_ROLLBACK([squid_krb5_save])
fi

if test "x$KRB5LIBS" != "x"; then
  with_krb5=yes
fi
AC_MSG_NOTICE([$KRB5_FLAVOUR Kerberos library support: ${with_krb5:=no} ${LIB_KRB5_PATH} ${LIB_KRB5_LIBS}])
AC_SUBST(KRB5INCS)
AC_SUBST(KRB5LIBS)

dnl On MinGW OpenLDAP is not available, so LDAP helpers can be linked
dnl only with Windows LDAP libraries using -lwldap32
case "$squid_host_os" in
	mingw)
		LDAPLIB="-lwldap32"
		LBERLIB=""
		;;
	*)
		AC_CHECK_LIB(ldap, ldap_init, [LDAPLIB="-lldap"])
		dnl LDAP helpers need to know if -llber is needed or not
		AC_CHECK_LIB(lber, ber_init, [LBERLIB="-llber"])
		dnl if no ldap lib found check for mozilla version
		if test "x$ac_cv_lib_ldap_ldap_init" != x""yes; then
		        oLIBS=$LIBS
		        LIBS="$LIBPTHREADS"
			AC_CHECK_LIB(ldap60, ldap_init, [LDAPLIB="-lldap60"])
		        LIBS="$LDAPLIB $LIBPTHREADS"
			AC_CHECK_LIB(prldap60, prldap_init, [LDAPLIB="-lprldap60 $LDAPLIB"])
		        LIBS="$LDAPLIB $LIBPTHREADS"
			AC_CHECK_LIB(ssldap60, ldapssl_init, [LDAPLIB="-lssldap60 $LDAPLIB"])
		        LIBS=$oLIBS
		fi

		AC_CHECK_HEADERS(ldap.h lber.h)
		AC_CHECK_HEADERS(mozldap/ldap.h)

		dnl
		dnl Check for LDAP_OPT_DEBUG_LEVEL
		dnl
		AC_MSG_CHECKING([for LDAP_OPT_DEBUG_LEVEL])
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#                   include <ldap.h>
		]],[[
                    int i=LDAP_OPT_DEBUG_LEVEL
		]])],
		[ AC_MSG_RESULT(yes) ],
		[ AC_MSG_RESULT(no) ])

		dnl
		dnl Check for working ldap
		dnl
		oLIBS=$LIBS
		LIBS="$LDAPLIB $LBERLIB $LIBPTHREADS"
		AC_MSG_CHECKING([for working ldap])
		AC_RUN_IFELSE([AC_LANG_SOURCE([[
#                   define  LDAP_DEPRECATED 1
#                   if HAVE_LDAP_H
#                   include <ldap.h>
#                   elif HAVE_MOZLDAP_LDAP_H
#                   include <mozldap/ldap.h>
#                   endif
                    int
                    main(void)
                    {
                        char host[]="";
                        int port;

                        ldap_init((const char *)&host, port);

                        return 0;
                    }
		]])], 
		[ AC_DEFINE(HAVE_LDAP, 1, [LDAP support]) 
		  AC_MSG_RESULT(yes) ],
		[ AC_MSG_RESULT(no) ],
		[ AC_MSG_RESULT(cross-compiler cant tell) ])
		LIBS=$oLIBS

		dnl
		dnl Check for ldap vendor
		dnl
		AC_MSG_CHECKING([for OpenLDAP])
		AC_RUN_IFELSE([AC_LANG_SOURCE([[
#                   if HAVE_LDAP_H
#                   include <ldap.h>
#                   endif
#                   include <string.h>
                    int
                    main(void)
                    {
                        return strcmp(LDAP_VENDOR_NAME,"OpenLDAP");
                    }
		]])], 
		[ AC_DEFINE(HAVE_OPENLDAP, 1, [OpenLDAP support]) 
		  AC_MSG_RESULT(yes) ],
		[ AC_MSG_RESULT(no) ],
		[ AC_MSG_RESULT(cross-compiler cant tell) ])

		AC_MSG_CHECKING([for Sun LDAP SDK])
		AC_RUN_IFELSE([AC_LANG_SOURCE([[
#                   if HAVE_LDAP_H
#                   include <ldap.h>
#                   endif
#                   include <string.h>
                    int
                    main(void)
                    {
                        return strcmp(LDAP_VENDOR_NAME,"Sun Microsystems Inc.");
                    }
		]])], 
		[ AC_DEFINE(HAVE_SUN_LDAP_SDK, 1, [Sun LDAP SDK support])
		  AC_MSG_RESULT(yes) ],
		[ AC_MSG_RESULT(no) ],
		[ AC_MSG_RESULT(cross-compiler cant tell) ])

		AC_MSG_CHECKING([for Mozilla LDAP SDK])
		AC_RUN_IFELSE([AC_LANG_SOURCE([[
#                   if HAVE_LDAP_H
#                   include <ldap.h>
#                   elif HAVE_MOZLDAP_LDAP_H
#                   include <mozldap/ldap.h>
#                   endif
#                   include <string.h>
                    int
                    main(void)
                    {
                        return strcmp(LDAP_VENDOR_NAME,"mozilla.org");
                    }
		]])], 
		[ AC_DEFINE(HAVE_MOZILLA_LDAP_SDK, 1, [Mozilla LDAP SDK support])
		  AC_MSG_RESULT(yes) ],
		[ AC_MSG_RESULT(no)],
		[ AC_MSG_RESULT(cross-compiler cant tell) ])

		dnl
		dnl Check for LDAP_REBINDPROC_CALLBACK
		dnl
                AC_MSG_CHECKING([for LDAP_REBINDPROC_CALLBACK])
                AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#                   if HAVE_LDAP_H
#                   include <ldap.h>
#                   elif HAVE_MOZLDAP_LDAP_H
#                   include <mozldap/ldap.h>
#                   endif
                ]],[[
                    LDAP_REBINDPROC_CALLBACK ldap_rebind;
                ]])],
                [ AC_DEFINE(HAVE_LDAP_REBINDPROC_CALLBACK,1,[Define to 1 if you have LDAP_REBINDPROC_CALLBACK])
                  AC_MSG_RESULT(yes) ],
                [ AC_MSG_RESULT(no) ])

		dnl
		dnl Check for LDAP_REBIND_PROC
		dnl
                AC_MSG_CHECKING([for LDAP_REBIND_PROC])
                AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#                   if HAVE_LDAP_H
#                   include <ldap.h>
#                   elif HAVE_MOZLDAP_LDAP_H
#                   include <mozldap/ldap.h>
#                   endif
                ]],[[
                    LDAP_REBIND_PROC ldap_rebind;
                ]])],
                [ AC_DEFINE(HAVE_LDAP_REBIND_PROC,1,[Define to 1 if you have LDAP_REBIND_PROC])
                  AC_MSG_RESULT(yes) ],
                [ AC_MSG_RESULT(no) ])

		dnl
		dnl Check for LDAP_REBIND_FUNCTION
		dnl
                AC_MSG_CHECKING([for LDAP_REBIND_FUNCTION])
                AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#                   define LDAP_REFERRALS
#                   if HAVE_LDAP_H
#                   include <ldap.h>
#                   elif HAVE_MOZLDAP_LDAP_H
#                   include <mozldap/ldap.h>
#                   endif
                ]],[[
                    LDAP_REBIND_FUNCTION ldap_rebind;
                ]])],
                [ AC_DEFINE(HAVE_LDAP_REBIND_FUNCTION,1,[Define to 1 if you have LDAP_REBIND_FUNCTION])
                  AC_MSG_RESULT(yes) ],
                [ AC_MSG_RESULT(no) ])

		dnl
		dnl Check for LDAP_SCOPE_DEFAULT
		dnl
                AC_MSG_CHECKING([for LDAP_SCOPE_DEFAULT])
                AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#                   if HAVE_LDAP_H
#                   include <ldap.h>
#                   elif HAVE_MOZLDAP_LDAP_H
#                   include <mozldap/ldap.h>
#                   endif
                ]],[[
                    int i=LDAP_SCOPE_DEFAULT;
                ]])],
                [ AC_DEFINE(HAVE_LDAP_SCOPE_DEFAULT,1,[Define to 1 if you have LDAP_SCOPE_DEFAULT])
                  AC_MSG_RESULT(yes) ],
                [ AC_MSG_RESULT(no) ])

		dnl
		dnl Check for ldap_url_desc.lud_scheme
		dnl
		AC_CHECK_MEMBER(struct ldap_url_desc.lud_scheme,
		  AC_DEFINE(HAVE_LDAP_URL_LUD_SCHEME,1,
		    [Define to 1 if you have LDAPURLDesc.lud_scheme]),,[#include <ldap.h>])

		dnl
		dnl Check for ldapssl_client_init
		dnl
		AC_CHECK_LIB(ldap,ldapssl_client_init,
		  AC_DEFINE(HAVE_LDAPSSL_CLIENT_INIT,1,[Define to 1 if you have ldapssl_client_init]),)

		dnl
		dnl Check for ldap_url_desc2str
		dnl
		AC_CHECK_LIB(ldap,ldap_url_desc2str,
		  AC_DEFINE(HAVE_LDAP_URL_DESC2STR,1,[Define to 1 if you have ldap_url_desc2str]),)

		dnl
		dnl Check for ldap_url_parse
		dnl
		AC_CHECK_LIB(ldap,ldap_url_parse,
		  AC_DEFINE(HAVE_LDAP_URL_PARSE,1,[Define to 1 if you have ldap_url_parse]),)

		dnl
		dnl Check for ldap_start_tls_s
		dnl
		AC_CHECK_LIB(ldap,ldap_start_tls_s,
		  AC_DEFINE(HAVE_LDAP_START_TLS_S,1,[Define to 1 if you have ldap_start_tls_s]),)
		;;
esac

AC_SUBST(LDAPLIB)
AC_SUBST(LBERLIB)

AC_ARG_ENABLE(forw-via-db,
  AS_HELP_STRING([--enable-forw-via-db],[Enable Forw/Via database]), [
  SQUID_YESNO([$enableval],[unrecognized argument to --enable-forw-via-db: $enableval])
])
SQUID_DEFINE_BOOL(USE_FORW_VIA_DB,${enable_forw_via_db:=no},
                      [Enable Forw/Via database])
AC_MSG_NOTICE([Forw/Via database enabled: $enable_forw_via_db])

AC_ARG_ENABLE(cache-digests,
  AS_HELP_STRING([--enable-cache-digests],
   [Use Cache Digests. See http://wiki.squid-cache.org/SquidFaq/CacheDigests]),
[
 SQUID_YESNO($enableval,
   [unrecognized argument to --enable-cache-digests: $enableval])
])
SQUID_DEFINE_BOOL(USE_CACHE_DIGESTS,${enable_cache_digests:=no},
  [Use Cache Digests for locating objects in neighbor caches.])
AC_MSG_NOTICE([Cache Digests enabled: $enable_cache_digests])


################################
# check for netio plugin stuff #
################################
dnl order of these options handling is relevant in case the user
dnl supplies more than one --enable option. Options handled later
dnl override those handled earlier for io loop method manual override
AC_ARG_ENABLE(select,
  AS_HELP_STRING([--disable-select],[Disable select(2) support.]),
[
SQUID_YESNO($enableval,[--disable-select takes no extra argument])
if test "x$enableval" = "xyes"; then
  if test "x$squid_host_os" = "xmingw"; then
    squid_opt_io_loop_engine="select_win32"
  else
    squid_opt_io_loop_engine="select"
  fi
fi
])
AC_MSG_NOTICE([enabling select syscall for net I/O: ${enable_select:=auto}])

AC_ARG_ENABLE(poll,
  AS_HELP_STRING([--disable-poll],[Disable poll(2) support.]),
[
SQUID_YESNO($enableval,[--disable-poll takes no extra argument])
test "x$enableval" = "xyes" && squid_opt_io_loop_engine="poll"
])
AC_MSG_NOTICE([enabling poll syscall for net I/O: ${enable_poll:=auto}])

AC_ARG_ENABLE(kqueue,
  AS_HELP_STRING([--disable-kqueue],
                 [Disable kqueue(2) support.]), [
SQUID_YESNO($enableval,[--enable-kqueue takes no extra argument])
])
if test "x${enable_kqueue:=auto}" != "xno" ; then
  AC_CHECK_HEADERS([sys/event.h],[],[
    if test "x${enable_kqueue}" = "xyes" ; then
      AC_MSG_ERROR([kqueue support requires sys/event.h header file.])
    fi
  ])
  AC_CHECK_FUNCS(kqueue,[],[
    if test "x${enable_kqueue}" = "xyes" ; then
      AC_MSG_ERROR([kqueue support missing in libc library.])
    fi
  ])
  if test "x$ac_cv_func_kqueue" = "xyes" -a "x$ac_cv_header_sys_event_h" = "xyes" ; then
    squid_opt_io_loop_engine="kqueue"
  else
    enable_kqueue="no"
  fi
fi
AC_MSG_NOTICE([enabling kqueue for net I/O: ${enable_kqueue:=auto}])

dnl Enable epoll()
AC_ARG_ENABLE(epoll,
  AS_HELP_STRING([--disable-epoll],[Disable Linux epoll(2) support.]),
[
SQUID_YESNO($enableval,[--disable-epoll takes no extra argument])
test "x$enableval" = "xyes" && squid_opt_io_loop_engine="epoll"
])
AC_MSG_NOTICE([enabling epoll syscall for net I/O: ${enable_epoll:=auto}])

# auto-detect and verify epoll header and library present and working
# logic mapping and loop method selection are performed later
if test "x$enable_epoll" != "xno" ; then

  # check if libs are needed to support epoll
  # note: this code block seems quite generic. Could it be extracted
  #   into a squid specific configure function?
  SQUID_STATE_SAVE(squid_epoll_state)
  AC_SEARCH_LIBS(epoll_ctl,[epoll])
  if test "x$ac_cv_search_epoll_ctl" = "xno" ; then
    enable_epoll=no #disable. Needed code not found
  elif test "x$ac_cv_search_epoll_ctl" = "xnone required" ; then
    EPOLL_LIBS=""
  else
    EPOLL_LIBS=$ac_cv_search_epoll_ctl
  fi
  AC_SUBST(EPOLL_LIBS)
  SQUID_STATE_ROLLBACK(squid_epoll_state) #de-pollute LIBS

  # epoll requires sys/epoll.h
  AC_CHECK_HEADERS([sys/epoll.h])

  dnl Verify that epoll really works
  if test "x$ac_cv_search_epoll_ctl" != 'xno' ; then
    SQUID_CHECK_EPOLL
  fi

  if test "x$enable_epoll" = "xyes" -a "x$squid_cv_epoll_works" = "xno" ; then
    AC_MSG_ERROR([Epoll does not work. Force-enabling it is not going to help.])
  fi
fi

dnl Enable /dev/poll
AC_ARG_ENABLE(devpoll,
  AS_HELP_STRING([--disable-devpoll],[Disable Solaris /dev/poll support.]),
[
SQUID_YESNO($enableval,[--disable-devpoll takes no extra argument])
test "x$enableval" = "xyes" && squid_opt_io_loop_engine="devpoll"
])
AC_MSG_NOTICE([enabling /dev/poll for net I/O: ${enable_devpoll:=auto}])

## auto-detect and verify devpoll header and library present and working
if test "x$enable_devpoll" != "xno"; then

  # /dev/poll requires ioctl() and write()
  AC_CHECK_FUNCS(ioctl)
  AC_CHECK_FUNCS(write)

  # /dev/poll requires sys/devpoll.h
  AC_CHECK_HEADERS([sys/devpoll.h],,[
        if test "x$enable_devpoll" = "xyes"; then
            AC_MSG_ERROR([--enable-devpoll specified but /dev/poll headers not found])
        fi
        enable_devpoll=no])

  # Verify that /dev/poll really works
  if test "x$enable_devpoll" != 'xno' ; then
    SQUID_CHECK_DEVPOLL
  fi

  if test "x$enable_devpoll" = "xyes" -a "x$squid_cv_devpoll_works" = "xno" ; then
    AC_MSG_ERROR([/dev/poll does not work. Force-enabling it is not going to help.])
  fi
fi


AC_ARG_ENABLE(http-violations,
  AS_HELP_STRING([--disable-http-violations],
                 [This allows you to remove code which is known to
                  violate the HTTP protocol specification.]), [
  SQUID_YESNO([$enableval],
         [unrecognized argument to --disable-http-violations: $enableval])
])
SQUID_DEFINE_BOOL(USE_HTTP_VIOLATIONS, ${enable_http_violations:=yes},
  [Define to enable code which volates the HTTP standard specification])
AC_MSG_NOTICE([HTTP violations support enabled: $enable_http_violations])

# IPFW Transparent Proxy
AC_ARG_ENABLE(ipfw-transparent,
  AS_HELP_STRING([--enable-ipfw-transparent],
                 [Enable Transparent Proxy support for systems
                  using FreeBSD IPFW-style firewalling.]), [
  SQUID_YESNO([$enableval],
      [unrecognized argument to --enable-ipfw-transparent: $enableval])
])
SQUID_DEFINE_BOOL(IPFW_TRANSPARENT,${enable_ipfw_transparent:=no},
  [Enable support for Transparent Proxy on systems using FreeBSD IPFW-style firewalling.])
AC_MSG_NOTICE([FreeBSD IPFW-based transparent proxying enabled: $enable_ipfw_transparent])

# IP-Filter Transparent Proxy
AC_ARG_ENABLE(ipf-transparent,
  AS_HELP_STRING([--enable-ipf-transparent],
     [Enable Transparent Proxy support using IPFilter-style firewalling]), [
  SQUID_YESNO([$enableval],
      [unrecognized argument to --enable-ipf-transparent: $enableval])
])
#will be AC_DEFINEd later, after checking for appropriate infrastructure
#IPF currently broken. Default-disabled for now.
AC_MSG_NOTICE([IPF-based transparent proxying requested: ${enable_ipf_transparent:=no}])

dnl Enable PF Transparent Proxy
AC_ARG_ENABLE(pf-transparent,
  AS_HELP_STRING([--enable-pf-transparent],
    [Enable Transparent Proxy support for systems using PF network address redirection.]), [
  SQUID_YESNO([$enableval],
              [unrecognized argument to --enable-pf-transparent: $enableval])
])
#will be AC_DEFINEd later, after checking for appropriate infrastructure
AC_MSG_NOTICE([PF-based transparent proxying requested: ${enable_pf_transparent:=no}])

dnl Enable /dev/pf support for older PF Transparent Proxy systems (OpenBSD 4.x and older)
AC_ARG_WITH(nat-devpf,
  AS_HELP_STRING([--with-nat-devpf],
    [Enable /dev/pf support for NAT on older OpenBSD and FreeBSD kernels.]), [
  SQUID_YESNO([$enableval],
              [unrecognized argument to --with-nat-devpf: $enableval])
])
#will be AC_DEFINEd later, after checking for appropriate infrastructure
AC_MSG_NOTICE([NAT lookups via /dev/pf: ${with_nat_devpf:=no}])

# Linux Netfilter Transparent Proxy
AC_ARG_ENABLE(linux-netfilter,
  AS_HELP_STRING([--enable-linux-netfilter],
                 [Enable Transparent Proxy support for Linux (Netfilter)]), [
  SQUID_YESNO([$enableval],
              [unrecognized argument to --enable-linux-netfilter: $enableval])
])
AC_MSG_NOTICE([Linux Netfilter support requested: ${enable_linux_netfilter:=auto}])
#will be AC_DEFINEd later, after checking for appropriate infrastructure


dnl Look for libnetfilter_conntrack options (needed for QOS netfilter marking)
dnl squid_opt_netfilterconntrack is set only when option is explicity specified
AC_ARG_WITH(netfilter-conntrack,
  AS_HELP_STRING([--without-netfilter-conntrack],
                 [Do not use Netfilter conntrack libraries for packet marking.
                  A path to alternative library location may be specified by
                  using --with-netfilter-conntrack=PATH. Default: auto-detect.]), [
case "$with_netfilter_conntrack" in
  yes|no)
    squid_opt_netfilterconntrack=$with_netfilter_conntrack
    ;;
  *)
    if test ! -d "$withval" ; then
      AC_MSG_ERROR([--with-netfilter-conntrack path does not point to a directory])
    fi
    squid_opt_netfilterconntrackpath=$withval
    LDFLAGS="-L$squid_opt_netfilterconntrackpath/lib $LDFLAGS"
    CPPFLAGS="-I$squid_opt_netfilterconntrackpath/include $CPPFLAGS"
    with_netfilter_conntrack=yes
    squid_opt_netfilterconntrack=yes
  esac
])
AC_MSG_NOTICE([Linux Netfilter Conntrack support requested: ${with_netfilter_conntrack:=auto}])
if test "x$with_netfilter_conntrack" != "xno"; then
    AC_SEARCH_LIBS([nfct_query], [netfilter_conntrack],,[
        if test x"$with_netfilter_conntrack" = "xyes"; then
            AC_MSG_ERROR([--with-netfilter-conntrack specified but libnetfilter-conntrack library not found])
        fi
        with_netfilter_conntrack=no])
    AC_CHECK_HEADERS([libnetfilter_conntrack/libnetfilter_conntrack.h \
        libnetfilter_conntrack/libnetfilter_conntrack_tcp.h],,[
        if test x"$with_netfilter_conntrack" = "xyes"; then
            AC_MSG_ERROR([--with-netfilter-conntrack specified but libnetfilter-conntrack headers not found])
        fi
        with_netfilter_conntrack=no])
  # If nothing is broken; enable the libraries usage.
  if test "x$with_netfilter_conntrack" != "xno"; then
    with_netfilter_conntrack=yes
  fi
fi


dnl Enable Large file support
buildmodel=""
squid_opt_enable_large_files=no

AC_ARG_WITH(large-files,
  AS_HELP_STRING([--with-large-files],[Enable support for large files (logs etc).]), [
  if test "x$withval" = "xyes"; then
    squid_opt_enable_large_files=yes
  fi
])

dnl UNIX Build environment
dnl AS_HELP_STRING is not suited here because it cannot to specify newlines
AC_ARG_WITH(build-environment,
 AS_HELP_STRING([--with-build-environment=model],
     [The build environment to use. Normally one of 
      POSIX_V6_ILP32_OFF32 (32 bits),
      POSIX_V6_ILP32_OFFBIG (32 bits with large file support),
      POSIX_V6_LP64_OFF64 (64 bits),
      POSIX_V6_LPBIG_OFFBIG (large pointers and files),
      XBS5_ILP32_OFF32 i(legacy, 32 bits),
      XBS5_ILP32_OFFBIG (legacy, 32 bits with large file support),
      XBS5_LP64_OFF64 (legacy, 64 bits),
      XBS5_LPBIG_OFFBIG (legacy, large pointers and files)
      or default (The default for your OS)]), [
case "$withval" in
  yes|no)
    AC_MSG_FAILURE([--with-build-environment expects a build environment string as used by getconf])
    ;;
  *)
    buildmodel="$withval"
    ;;
esac
])

#hack. Let's early-detect sizeof(long)
AC_CHECK_SIZEOF(long)

if test "x$squid_opt_enable_large_files" = "xyes" -a "x$buildmodel" = "x"; then
  for model in POSIX_V6_LPBIG_OFFBIG XBS5_LPBIG_OFFBIG POSIX_V6_LP64_OFF64 XBS5_LP64_OFF64 POSIX_V6_ILP32_OFFBIG XBS5_ILP32_OFFBIG; do
    if test "`getconf _$model 2>/dev/null || true`" = 1 || test "`getconf $model 2>/dev/null || true`" ; then
      buildmodel=$model
      break
    fi
  done
  if test "x$buildmodel" = "x"; then
    AC_MSG_WARN([No suitable build environment found for large files. Trying to use _FILE_OFFSET_BITS=64])
  fi
fi
if test "x$buildmodel" = "xdefault" -o "x$buildmodel" = "x"; then
  # define _FILE_OFFSET_BITS if requested and needed
  if test "x$squid_opt_enable_large_files" = "xyes" -a $ac_cv_sizeof_long -le 4 ; then
    AC_MSG_NOTICE([Enabling -D_FILE_OFFSET_BITS=64])
    CFLAGS="-D_FILE_OFFSET_BITS=64 $CFLAGS"
    CXXFLAGS="-D_FILE_OFFSET_BITS=64 $CXXFLAGS"
  fi
else
  AC_MSG_NOTICE([Using $buildmodel build environment])
  if test "`getconf _$buildmodel 2>/dev/null || true`" = 1 || test "`getconf $buildmodel 2>/dev/null || true`" ; then
    : # All fine
  else
    AC_MSG_ERROR(Build environment $buildmodel not known to getconf.)
  fi
  CFLAGS="`getconf ${buildmodel}_CFLAGS` $CFLAGS"
  CXXFLAGS="`getconf ${buildmodel}_CFLAGS` $CXXFLAGS"
  LIBS="`getconf ${buildmodel}_LIBS` $LIBS"
  LDFLAGS="`getconf ${buildmodel}_LDFLAGS` $LDFLAGS"
  if test "x$squid_host_os" = "xsolaris" ; then

# On Solaris getconf returns for CFLAGS -xarch=generic64, -Xa and -Usun options, and
# for LDFLAGS -xarch=generic64, but:
#   "-Xa" is supported only by Sun cc, so we need to remove it when using gcc
#   For gcc "-xarch=generic64" must be replaced with "-m64"
#   The 'sun' define is needed by ipfilter includes, so we must remove "-Usun"
    if test "x$GCC" = "xyes"; then
      AC_MSG_NOTICE([Removing -Xa for gcc/g++ on $host])
      CFLAGS="`echo $CFLAGS | sed -e 's/-Xa//'`"
      CXXFLAGS="`echo $CXXFLAGS | sed -e 's/-Xa//'`"
      AC_MSG_NOTICE([Replacing -xarch=generic64 with -m64 for gcc/g++ on $host])
      CFLAGS="`echo $CFLAGS | sed -e 's/-xarch=generic64/-m64/'`"
      CXXFLAGS="`echo $CXXFLAGS | sed -e 's/-xarch=generic64/-m64/'`"
      LDFLAGS="`echo $LDFLAGS | sed -e 's/-xarch=generic64//'`"
    fi
    AC_MSG_NOTICE([Removing -Usun on $host])
    CFLAGS="`echo $CFLAGS | sed -e 's/-Usun//'`"
    CXXFLAGS="`echo $CXXFLAGS | sed -e 's/-Usun//'`"
  fi
fi

dnl Enable Leak Finding Functions
AC_ARG_ENABLE(leakfinder,
  AS_HELP_STRING([--enable-leakfinder],
    [Enable Leak Finding code. Enabling this alone does nothing;
     you also have to modify the source code to use the leak
     finding functions. Probably Useful for hackers only.]), [ 
  SQUID_YESNO([$enableval],
     [unrecognized argument to --enable-leakfinder: $enableval])
])
AC_MSG_NOTICE([Leak Finder enabled: ${enable_leakfinder:=no}])
SQUID_DEFINE_BOOL(USE_LEAKFINDER,$enable_leakfinder,
  [Enable code for assisting in finding memory leaks. Not for the faint of heart])
AM_CONDITIONAL(ENABLE_LEAKFINDER, [test "x$enable_leakfinder" = "xyes"])


AC_ARG_ENABLE(follow-x-forwarded-for,
  AS_HELP_STRING([--enable-follow-x-forwarded-for],
                 [Enable support for following the X-Forwarded-For
                 HTTP header to try to find the IP address of the
                 original or indirect client when a request has
                 been forwarded through other proxies.]), [
  SQUID_YESNO([$enableval],
    [unrecognized argument to --enable-follow-x-forwarded-for: $enableval])
])
AC_MSG_NOTICE([Support for X-Forwarded-For enabled: ${enable_follow_x_forwarded_for:=yes}])
SQUID_DEFINE_BOOL(FOLLOW_X_FORWARDED_FOR,$enable_follow_x_forwarded_for,
  [Enable following X-Forwarded-For headers])

AC_ARG_ENABLE(ident-lookups,
  AS_HELP_STRING([--disable-ident-lookups],
                 [Remove code that supports performing Ident (RFC 931) lookups.]), [
  SQUID_YESNO([$enableval],[unrecognized argument to --disable-ident-lookups: $enableval])
])
AC_MSG_NOTICE([Support for Ident lookups enabled: ${enable_ident_lookups:=yes}])
SQUID_DEFINE_BOOL(USE_IDENT,$enable_ident_lookups,[Support for Ident (RFC 931) lookups])

dnl Select Default hosts file location
AC_ARG_ENABLE(default-hostsfile,
  AS_HELP_STRING([--enable-default-hostsfile=path],
                 [Select default location for hosts file.
                  See hosts_file directive in squid.conf for details]), [
if test "x$enableval" != "xnone" -a "x$enableval" != "xno" ; then
  if test \! -f "$enableval"; then
    AC_MSG_WARN([Unable to find file $enableval. I hope you know what you are doing.])
  fi
  squid_opt_default_hosts=$enableval
else
  squid_opt_default_hosts="none"
fi
])
AC_MSG_NOTICE([Default hosts file set to: ${squid_opt_default_hosts:=/etc/hosts}])
DEFAULT_HOSTS=$squid_opt_default_hosts
AC_SUBST(DEFAULT_HOSTS)

# Select auth schemes modules to build
AC_ARG_ENABLE(auth,
  AS_HELP_STRING([--enable-auth],
                 [Build global support for authentication. The list of schemes
                  and helpers to be enabled is defined elsewhere]), [
SQUID_YESNO([$enableval],
            [unrecognized argument to --enable-auth: $enableval])
])
AC_MSG_NOTICE([Authentication support enabled: ${enable_auth:=yes}])
SQUID_DEFINE_BOOL(USE_AUTH,$enable_auth,[Enable support for authentication])
AM_CONDITIONAL(ENABLE_AUTH, test "x$enable_auth" != "xno")
AUTH_MODULES=""
require_smblib="no"

AC_ARG_ENABLE(auth-basic,
  AS_HELP_STRING([--enable-auth-basic="list of helpers"],
     [Enable the basic authentication scheme, and build the specified helpers.
      Not providing an explicit list of helpers will attempt build of
      all possible helpers. Default is to do so.
      To disable the basic authentication scheme, use --disable-auth-basic.
      To enable but build no helpers, specify "none".
      To see available helpers, see the src/auth/basic/ directory. ]),[
#nothing to do really
])
m4_include([src/auth/basic/helpers.m4])

AC_ARG_ENABLE(auth-digest,
  AS_HELP_STRING([--enable-auth-digest="list of helpers"],
     [Enable the Digest authentication scheme, and build the specified helpers.
      Not providing an explicit list of helpers will attempt build of
      all possible helpers. Default is to do so.
      To disable the Digest authentication scheme, use --disable-auth-digest.
      To enable but build no helpers, specify "none".
      To see available helpers, see the src/auth/digest/ directory. ]),[
#nothing to do, really
])
m4_include([src/auth/digest/helpers.m4])

AC_ARG_ENABLE(auth-negotiate,
  AS_HELP_STRING([--enable-auth-negotiate="list of helpers"],
     [Enable the Negotiate authentication scheme, and build the specified
      helpers.
      Not providing an explicit list of helpers will attempt build of
      all possible helpers. Default is to do so.
      To disable the Negotiate authentication scheme,
      use --disable-auth-negotiate.
      To enable but build no helpers, specify "none".
      To see available helpers, see the src/auth/negotiate/ directory. ]),[
#nothing to do, really
])
m4_include([src/auth/negotiate/helpers.m4])

AC_ARG_ENABLE(auth-ntlm,
  AS_HELP_STRING([--enable-auth-ntlm="list of helpers"],
     [Enable the NTLM authentication scheme, and build the specified helpers.
      Not providing an explicit list of helpers will attempt build of
      all possible helpers. Default is to do so.
      To disable the NTLM authentication scheme, use --disable-auth-ntlm.
      To enable but build no helpers, specify "none".
      To see available helpers, see the src/auth/ntlm/ directory. ]),[
])
m4_include([src/auth/ntlm/helpers.m4])

dnl Authentication libraries to build
dnl This list will not be needed when each auth library has its own Makefile
dnl this is to be placed AFTER each auth module's handler
AUTH_LIBS_TO_BUILD=
for module in $AUTH_MODULES; do
    AUTH_LIBS_TO_BUILD="$AUTH_LIBS_TO_BUILD ${module}/lib${module}.la"
done
AC_SUBST(AUTH_MODULES)
AC_SUBST(AUTH_LIBS_TO_BUILD)
AM_CONDITIONAL(ENABLE_SMBLIB, test "x$require_smblib" = "xyes")

dnl Select logging daemon helpers to build
AC_ARG_ENABLE(log-daemon-helpers,
  AS_HELP_STRING([--enable-log-daemon-helpers="list of helpers"],
                 [This option selects which logging daemon helpers to
                  build and install as part of the normal build process
                  For a list of available helpers see the src/log/
                  directory.]),[
#nothing to do, really
])
m4_include([src/log/helpers.m4])

AC_ARG_ENABLE(external-acl-helpers,
  AS_HELP_STRING([--enable-external-acl-helpers="list of helpers"],
                 [Enable external_acl helpers support and the helpers themselves.
                  Default is to build all buildable helpers and enable support.
                  To disable support, use --disable-external-acl-helpers.
                  To build no helpers, specify "none".
                  To see available helpers, see the src/acl/external/
                  directory]), [
#nothing to do, really
])
m4_include([src/acl/external/helpers.m4])

dnl Select url_rewrite helpers to build
AC_ARG_ENABLE(url-rewrite-helpers,
  AS_HELP_STRING([--enable-url-rewrite-helpers="list of helpers"],
                 [This option selects which url_rewrite helpers to
                  build and install as part of the normal build
                  process. The default is to attempt the build of all possible
                  helpers. Use --disable-url-rewrite-helpers to build none.
                  For a list of available helpers see the
                  src/http/url_rewriters/ directory.]),[
])
m4_include([src/http/url_rewriters/helpers.m4])

dnl Select security helpers to build
AC_ARG_ENABLE(security-cert-validators,
  AS_HELP_STRING([--enable-security-cert-validators="list of helpers"],
                 [This option selects which security certificate validator
                  helpers to build and install as part of the normal build
                  process. The default is to attempt the build of all possible
                  helpers. Use --disable-security-cert-validators to
                  build none. For a list of available helpers see the
                  src/security/cert_validators/ directory.]),[
])
m4_include([src/security/cert_validators/helpers.m4])

AC_ARG_ENABLE(security-cert-generators,
  AS_HELP_STRING([--enable-security-cert-generators="list of helpers"],
                 [This option selects which security certificate validator
                  helpers to build and install as part of the normal build
                  process. The default is to attempt the build of all possible
                  helpers. Use --disable-security-cert-genrators to
                  build none. For a list of available helpers see the
                  src/security/cert_generators/ directory.]),[
])
m4_include([src/security/cert_generators/helpers.m4])

dnl Select storeid_rewrite helpers to build
AC_ARG_ENABLE(storeid-rewrite-helpers,
  AS_HELP_STRING([--enable-storeid-rewrite-helpers="list of helpers"],
                 [This option selects which Store-ID rewrite helpers to
                  build and install as part of the normal build
                  process. The default is to attempt the build of all possible
                  helpers. Use --disable-storeid-rewrite-helpers to build none.
                  For a list of available helpers see the
                  src/store/id_rewriters/ directory.]),[
])
m4_include([src/store/id_rewriters/helpers.m4])

AC_ARG_WITH(valgrind-debug,
  AS_HELP_STRING([--with-valgrind-debug],
                 [Include debug instrumentation for use with valgrind]),
[
  SQUID_YESNO([$withval],
            [unrecognized argument to --with-valgrind-debug: $withval])
  if test "x$withval" != "xno" ; then
    AC_CHECK_HEADERS(valgrind/memcheck.h,[],[
      AC_MSG_ERROR([Valgrind support requested, needed headers not found.])
    ])
  fi
])
SQUID_DEFINE_BOOL(WITH_VALGRIND,${with_valgrind_debug:=no},
                  [Valgrind memory debugger support])
AC_MSG_NOTICE([Valgrind debug support enabled: $with_valgrind_debug])

dnl Enable WIN32 Service compile mode
AC_ARG_ENABLE(win32-service,
  AS_HELP_STRING([--enable-win32-service],
                 [Compile Squid as a WIN32 Service.
                  Works only on MS-Windows platforms]), [
SQUID_YESNO([$enableval],
            [unrecognized argument to --enable-win32-service: $enableval])
])
SQUID_DEFINE_BOOL(USE_WIN32_SERVICE,${enable_win32_service:=no},
   [Enable code supporting MS Windows service mode])
AC_MSG_NOTICE([MS Windows service mode enabled: $enable_win32_service])


# Disable "unlinkd" code
AC_ARG_ENABLE(unlinkd,
  AS_HELP_STRING([--disable-unlinkd],[Do not use unlinkd]), [
SQUID_YESNO([$enableval],
            [unrecognized argument to --disable-unlinkd: $enableval])
])
SQUID_DEFINE_BOOL(USE_UNLINKD,${enable_unlinkd:=yes},
                      [Enable useage of unlinkd])
AM_CONDITIONAL(ENABLE_UNLINKD,test "x$enable_unlinkd" = "xyes")
AC_MSG_NOTICE([unlinkd enabled: $enable_unlinkd])

# Enable backtraces on fatal errors
AC_ARG_ENABLE(stacktraces,
  AS_HELP_STRING([--enable-stacktraces],
                 [Enable automatic call backtrace on fatal errors]), [
SQUID_YESNO([$enableval],
            [unrecognized argument to --enable-stacktraces: $enableval])
])
SQUID_DEFINE_BOOL(PRINT_STACK_TRACE,${enable_stacktraces:=no},
                      [Print stack traces on fatal errors])
AC_MSG_NOTICE([Automatically print stack trace on fatal errors: $enable_stacktraces])


# CPU Profiling options handling
AC_ARG_ENABLE(cpu-profiling,
  AS_HELP_STRING([--enable-cpu-profiling],
                 [Enable instrumentation to try and understand how CPU power 
                 is spent by squid, by enabling specific probes in selected
                 functions.
                 New probes can only be added by modifying the source code.
                 It is meant to help developers in optimizing performance
                 of Squid internal functions.
                 If you are not developer you should not enable this, 
                 as it slows squid down somewhat.
                 See lib/Profiler.c for more details.]), [
SQUID_YESNO([$enableval],
            [unrecognized argument to --enable-cpu-profiling: $enableval])
])
# Default OFF. This is a debug feature. Only check and enable if forced ON.
if test "x$enable_cpu_profiling" = "xyes"; then
  SQUID_CHECK_FUNCTIONAL_CPU_PROFILER
  if test "x$squid_cv_cpu_profiler_works" = "xno"; then
    AC_MSG_ERROR([CPU profiling will not be functional in this build.])
  fi
fi
SQUID_DEFINE_BOOL(USE_XPROF_STATS,${enable_cpu_profiling:=no},
                      [Define to enable CPU profiling within Squid])
AM_CONDITIONAL(ENABLE_XPROF_STATS,
               test "x$enable_cpu_profiling" = "xyes")
AC_MSG_NOTICE([CPU profiling enabled: $enable_cpu_profiling])

# Enable X-Accelerator-Vary for Vary support within an accelerator setup
AC_ARG_ENABLE(x-accelerator-vary,
  AS_HELP_STRING([--enable-x-accelerator-vary],
                 [Enable support for the X-Accelerator-Vary
                  HTTP header. Can be used to indicate
                  variance within an accelerator setup.
                  Typically used together with other code
                  that adds custom HTTP headers to the requests.]), [
SQUID_YESNO([$enableval],
            [unrecognized argument to --enable-x-accelerator-vary: $enableval])
])
SQUID_DEFINE_BOOL(X_ACCELERATOR_VARY,${enable_x_accelerator_vary:=no},
                      [Enable support for the X-Accelerator-Vary HTTP header])
AC_MSG_NOTICE([X-Accelerator-Vary support enabled: $enable_x_accelerator_vary])

AC_ARG_WITH([cppunit], AS_HELP_STRING([--without-cppunit],[Do not use cppunit test framework]),[
  AS_CASE($with_cppunit, [yes|no],[],
   [
    AS_IF([test ! -d "$withval"],AC_MSG_ERROR([--with-cppunit PATH does not point to a directory]))
    LIBCPPUNIT_CFLAGS="-I$with_cppunit/include"
    LIBCPPUNIT_LIBS="-L$with_cppunit/lib -lcppunit"
  ])
])
AS_IF([test "x$with_cppunit" != "xno"],[
  PKG_CHECK_MODULES([LIBCPPUNIT],[cppunit],[
    squid_cv_cppunit_version="`pkg-config cppunit --version`"
    AC_MSG_NOTICE([using system installed cppunit version $squid_cv_cppunit_version])
    AS_UNSET(squid_cv_cppunit_version)

    SQUID_STATE_SAVE(squid_cppunit_state)
    CXXFLAGS="${CXXFLAGS} ${LIBCPPUNIT_CFLAGS}"
    LIBS="${LIBS} ${LIBCPPUNIT_LIBS}"
    AC_CHECK_HEADERS(cppunit/extensions/HelperMacros.h)
    SQUID_STATE_ROLLBACK(squid_cppunit_state)
  ],[
    AC_MSG_WARN([cppunit does not appear to be installed. Squid does not require this, but code testing with 'make check' will fail.])
  ])
])

# Force some compilers to use ANSI features
#
case "$host" in
  *-hp-hpux*)
    if test "x$ac_cv_prog_CC" = "xcc" ; then
      AC_MSG_NOTICE([adding '-Ae' to cc args for $host])
      CC="cc -Ae";
      ac_cv_prog_CC="$CC"
    fi
    ;;
esac


dnl automake handles this AC_PATH_PROG(MAKEDEPEND, makedepend, $TRUE)

case "$host" in
  *hpux*)
    AC_MSG_NOTICE([Disabling ranlib for HP-UX...])
    RANLIB=":"
    ;;
esac

dnl Check for headers
AC_HEADER_DIRENT
AC_HEADER_STDC

AC_CHECK_HEADERS( \
  arpa/inet.h \
  arpa/nameser.h \
  assert.h \
  bstring.h \
  crypt.h \
  ctype.h \
  direct.h \
  errno.h \
  execinfo.h \
  fcntl.h \
  fnmatch.h \
  getopt.h \
  glob.h \
  gnumalloc.h \
  grp.h \
  ipl.h \
  lber.h \
  ldap.h \
  libc.h \
  limits.h \
  linux/posix_types.h \
  linux/types.h \
  malloc.h \
  math.h \
  memory.h \
  mount.h \
  netdb.h \
  netinet/in.h \
  netinet/in_systm.h \
  netinet/tcp.h \
  paths.h \
  poll.h \
  pwd.h \
  regex.h \
  sched.h \
  siginfo.h \
  signal.h \
  stdarg.h \
  stddef.h \
  stdio.h \
  stdlib.h \
  string.h \
  strings.h \
  sys/bitypes.h \
  sys/file.h \
  sys/ioctl.h \
  sys/ipc.cc \
  sys/param.h \
  sys/prctl.h \
  sys/md5.h \
  sys/mman.h \
  sys/msg.h \
  sys/resource.h \
  sys/select.h \
  sys/shm.h \
  sys/socket.h \
  sys/stat.h \
  syscall.h \
  sys/syscall.h \
  sys/time.h \
  sys/types.h \
  sys/uio.h \
  sys/un.h \
  sys/vfs.h \
  sys/wait.h \
  syslog.h \
  time.h \
  unistd.h \
  utime.h \
  varargs.h \
  byteswap.h \
  glib.h \
  stdint.h \
  inttypes.h \
  wchar.h
)

AC_CHECK_HEADERS( \
  linux/netfilter_ipv4.h \
  linux/netfilter_ipv6/ip6_tables.h \
,,,
SQUID_DEFAULT_INCLUDES
#if HAVE_LIMITS_H
#include <limits.h>
#endif
/* Netfilter ip(6)tables v1.4.0 has broken headers */
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
)

dnl *BSD do not include the dependencies for all their net/ and netinet/ files
dnl We must include a few basic type headers for them to work.
AC_CHECK_HEADERS( \
  net/if.h \
  netinet/if_ether.h\
  netinet/icmp6.h \
  netinet/in.h \
  netinet/ip.h \
  netinet/ip6.h \
  netinet/ip_icmp.h \
  netinet/ipl.h \
  net/pf/pfvar.h \
  net/pfvar.h \
  sys/mount.h\
  resolv.h \
,,,
SQUID_BSDNET_INCLUDES)

AC_C_CONST
AC_C_BIGENDIAN

AC_STRUCT_TM
AC_CHECK_MEMBERS([struct tm.tm_gmtoff],,,[
#if TM_IN_SYS_TIME
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#elif HAVE_TIME_H
#include <time.h>
#endif
])

dnl Override rusage() detect on MinGW because is emulated in source code
case "$squid_host_os" in
  mingw)
    AC_DEFINE(HAVE_STRUCT_RUSAGE)
    ac_cv_func_getrusage='yes'
    AC_MSG_NOTICE([Using own rusage on Windows.])
    ;;
  *)      
    AC_CHECK_TYPE(struct rusage,AC_DEFINE(HAVE_STRUCT_RUSAGE,1,[The system provides struct rusage]),,[
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif])
    ;;
esac

AC_CHECK_MEMBERS([struct iphdr.ip_hl],,,[
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if defined (__linux__) || defined (__CYGWIN__)
#define ip_hl ihl
#endif
#ifndef __linux__
#ifndef __CYGWIN__
#define iphdr ip
#endif
#endif])

dnl Check for typedefs
AC_CHECK_SIZEOF(void *)

# check for a bunch of types
AC_TYPE_INT8_T
AC_TYPE_UINT8_T
AC_TYPE_INT16_T
AC_TYPE_UINT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT64_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_OFF_T
AC_TYPE_UID_T
AC_CHECK_TYPE([bool])
#need the defines for PRId64
AC_CHECK_SIZEOF(int64_t)
AC_CHECK_SIZEOF(long)
#need the defines for PRIuSIZE
AC_CHECK_SIZEOF(size_t)
#need the define for overflow checks
AC_CHECK_SIZEOF(off_t)
AC_CHECK_SIZEOF(size_t)

dnl Some C++11 types we try to use
AX_CXX_TYPE_NULLPTR
AX_CXX_TYPE_UNIQUE_PTR
AX_CXX_TYPE_UNIFORM_DISTRIBUTIONS
SQUID_CXX_STD_UNDERLYING_TYPE

dnl On Solaris 9 x86, gcc may includes a "fixed" set of old system include files
dnl that is incompatible with the updated Solaris header files.
dnl For this reason, we must check if pad128_t and upad128_t are defined.
AC_CHECK_TYPE(pad128_t,
  AC_DEFINE(HAVE_PAD128_T,1,[pad128_t is defined in system headers]),
  ,SQUID_DEFAULT_INCLUDES)

AC_CHECK_TYPE(upad128_t,
  AC_DEFINE(HAVE_UPAD128_T,1,[upad128_t is defined in system headers]),
  ,SQUID_DEFAULT_INCLUDES)

AC_CHECK_TYPE(mode_t, AC_DEFINE(HAVE_MODE_T,1,[mode_t is defined by the system headers]),,SQUID_DEFAULT_INCLUDES)
AC_CHECK_TYPE(fd_mask,  AC_DEFINE(HAVE_FD_MASK,1,[fd_mask is defined by the system headers]),,SQUID_DEFAULT_INCLUDES)

AC_CHECK_TYPE(socklen_t,AC_DEFINE(HAVE_SOCKLEN_T,1,[socklen_t is defined by the system headers]),,[
#include <sys/types.h>
#include <sys/socket.h>
#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif])

AC_CHECK_TYPE(mtyp_t,AC_DEFINE(HAVE_MTYP_T,1,
   [mtyp_t is defined by the system headers]),,[#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>])

AC_CHECK_TYPE(cpu_set_t,
   AC_DEFINE(HAVE_CPU_SET_T,1,[cpu_set_t is defined by the system headers]),,[
#if HAVE_SCHED_H
#include <sched.h>
#endif
])

# check for compiler support of %zu printf macro
AH_TEMPLATE(PRIuSIZE,[Compiler supports %zu printf macro])
AC_MSG_CHECKING([for compiler %zu support])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
  ]],[[size_t n=1;printf("%zu",n);]])],[
    AC_DEFINE(PRIuSIZE,"zu")
    AC_MSG_RESULT(yes)
  ],[AC_MSG_RESULT(no)],[AC_MSG_RESULT(no)])


dnl Check for special functions
AC_FUNC_ALLOCA


dnl Check for libcap header (assume its not broken unless 
AC_ARG_WITH(libcap, AS_HELP_STRING([--without-libcap],
       [disable usage of Linux capabilities library to control privileges]), [
SQUID_YESNO([$withval],[unrecognized argument to --without-libcap: $withval])
],[with_libcap=auto])

if test "x$with_libcap" != "xno"; then
  # cap_clear_flag is the most recent libcap function we require
  AC_CHECK_HEADERS(sys/capability.h)
  AC_CHECK_LIB(cap, cap_clear_flag)
  SQUID_CHECK_FUNCTIONAL_LIBCAP2

  # if it can't be supported..
  if test "x$ac_cv_header_sys_capability_h" = "xno" -o \
     "x$ac_cv_lib_cap_cap_clear_flag" = "xno"; then
    # and it was forced on: error
    if test "x$with_libcap" = "xyes" ; then
      AC_MSG_ERROR([libcap forced enabled but not available or not usable, requires libcap-2.09 or later])
    else
      # with_libcap is "auto"; it can't be supported. Disable.
      with_libcap=no
    fi
  else
    # header and lib are ok, we support
    with_libcap=yes
  fi

fi

SQUID_DEFINE_BOOL(USE_LIBCAP,$with_libcap,
   [use libcap to set capabilities required for TPROXY])
AC_MSG_NOTICE([libcap support enabled: $with_libcap])
SQUID_DEFINE_BOOL(LIBCAP_BROKEN,${squid_cv_sys_capability_works:=no},
   [libcap2 headers are broken and clashing with glibc])
AC_MSG_NOTICE([libcap2 headers are ok: $squid_cv_sys_capability_works])


dnl Check for needed libraries
AC_SEARCH_LIBS([gethostbyname],[nsl resolv bind])
AC_SEARCH_LIBS([res_init],[resolv])
AC_SEARCH_LIBS([__res_search],[resolv])
AC_SEARCH_LIBS([bind],[socket])
AC_SEARCH_LIBS([opcom_stack_trace],[opcom_stack])
AC_SEARCH_LIBS([strlcpy], [bsd])
AC_SEARCH_LIBS([yp_match], [nsl nss_nis nss_nisplus])
dnl Check for Winsock only on MinGW, on Cygwin we must use emulated BSD socket API
if test "x$squid_host_os" = "xmingw" ; then
  SQUID_CHECK_WINSOCK_LIB
  AC_CHECK_HEADERS( \
    windows.h \
    ws2tcpip.h \
    iphlpapi.h ,,,[
#if HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#if HAVE_WINDOWS_H
#include <windows.h>
#endif
#if HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
])
fi

# check that we have unix sockets
SQUID_CHECK_UNIX_SOCKET
SQUID_DEFINE_BOOL(HAVE_UNIXSOCKET,$squid_cv_unixsocket,[System supports unix sockets])

AC_CHECK_LIB(gnumalloc, malloc)
if test "x$ac_cv_lib_gnumalloc_malloc" = "xyes"; then
  AC_MSG_NOTICE([Disabling extended malloc functions when using bundled gnumalloc])
  ac_cv_func_mallocblksize=no
  ac_cv_func_mallopt=no
else
  case "$squid_host_os" in
    solaris)
      AC_MSG_NOTICE([skipping libmalloc check for $host])
      ;;
    freebsd)
      AC_MSG_NOTICE([skipping libmalloc check for $host])
      ;;
    *)
      #used later. FIXME
      AC_CHECK_LIB(malloc, main)
      ;;
  esac
fi

case "$squid_host_os" in
  mingw)
    AC_MSG_NOTICE([Use MSVCRT for math functions.])
    ;;
  *)
    dnl rint() and log() are only used in old C code for now.
    AC_LANG_PUSH([C])
    AC_SEARCH_LIBS([rint],[m])
    AC_SEARCH_LIBS([log],[m])
    AC_LANG_POP([C])
    ;;
esac

dnl --with-maxfd present for compatibility with Squid-2.
dnl undocumented in ./configure --help  to encourage using the Squid-3 directive
AC_ARG_WITH(maxfd,,
[ 
  case ${withval} in
    [[0-9]]*)
      squid_filedescriptors_num=$withval
      AC_MSG_NOTICE([forcing default of $squid_filedescriptors_num filedescriptors (user-forced)])
      ;;
    *)
      AC_MSG_ERROR(--with-maxfd expects a numeric argument)
      ;;
    esac
])

AC_ARG_WITH(filedescriptors,
  AS_HELP_STRING([--with-filedescriptors=NUMBER],
                 [Force squid to support NUMBER filedescriptors]),
[ 
  case ${withval} in
    [[0-9]]*)
      squid_filedescriptors_num=$withval
      AC_MSG_NOTICE([forcing default of $squid_filedescriptors_num filedescriptors (user-forced)])
      ;;
    *)
      AC_MSG_ERROR(--with-filedescriptors expects a numeric argument)
      ;;
    esac
])

SQUID_CHECK_DEFAULT_FD_SETSIZE
SQUID_CHECK_MAXFD


dnl Enable IPv6 support
AC_MSG_CHECKING([whether to enable IPv6])
AC_ARG_ENABLE(ipv6,
  AS_HELP_STRING([--disable-ipv6],[Disable IPv6 support. The default is to probe system capabilities on startup.]), [
SQUID_YESNO([$enableval],[unrecognized argument to --disable-ipv6: $enableval])
])
AC_MSG_RESULT(${enable_ipv6:=yes})
SQUID_DEFINE_BOOL(USE_IPV6,$enable_ipv6,[Enable support for IPv6 ])

if test "x$enable_ipv6" = "xyes" ; then
  SQUID_CHECK_SIN6_LEN_IN_SAI
fi
SQUID_CHECK_SS_LEN_IN_SOCKADDR_STORAGE
SQUID_CHECK_SIN_LEN_IN_SOCKADDR_IN


dnl Check for libdl, used by auth_modules/PAM
if test "x$with_dl" = "xyes"; then
    AC_CHECK_LIB(dl, dlopen)
fi

dnl -lintl is needed on SCO version 3.2v4.2 for strftime()
dnl Robert Side <rside@aiinc.bc.ca>
dnl Mon, 18 Jan 1999 17:48:00 GMT
case "$host" in
	*-pc-sco3.2*)
		AC_CHECK_LIB(intl, strftime)
		;;
esac

dnl System-specific library modifications
dnl
case "$host" in
  i386-*-solaris2.*)
    if test "x$GCC" = "xyes"; then
      AC_MSG_NOTICE([Removing -O for gcc on $host])
      CFLAGS="`echo $CFLAGS | sed -e 's/-O[[0-9g]]*//'`"
    fi
  ;;

  *-sgi-irix*)
    AC_MSG_NOTICE([Removing -lsocket for IRIX...])
    LIBS=`echo $LIBS | sed -e s/-lsocket//`
    AC_MSG_NOTICE([Removing -lnsl for IRIX...])
    LIBS=`echo $LIBS | sed -e s/-lnsl//`
    ac_cv_lib_nsl_main=no
    AC_MSG_NOTICE([Removing -lbsd for IRIX...])
    LIBS=`echo $LIBS | sed -e s/-lbsd//`
  ;;
dnl From: c0032033@ws.rz.tu-bs.de (Joerg Schumacher)
dnl Date: Thu, 17 Oct 1996 04:09:30 +0200
dnl Please change your configure script.  AIX doesn't need -lbsd.
  *-ibm-aix*)
    AC_MSG_NOTICE([Removing -lbsd for AIX...])
    LIBS=`echo $LIBS | sed -e s/-lbsd//`

    SQUID_CC_REQUIRE_ARGUMENT([ac_cv_require_rtti],[-rtti],[[
#include <assert.h>
#ifndef NULL
#define NULL 0
#endif
class Foo{
public:virtual ~Foo(){}
};
class Bar:public Foo{
public:Bar():Foo(){}
};
      ]],[[
Foo * myFoo=new Bar();
Bar * myBar=dynamic_cast<Bar *>(myFoo);
assert(myBar != NULL);
      ]])
    if test "$ac_cv_require_rtti" = "yes"; then
      SQUID_CFLAGS="-rtti $SQUID_CFLAGS"
      SQUID_CXXFLAGS="-rtti $SQUID_CXXFLAGS"
    fi

    AC_LANG_PUSH([C])
    SQUID_CC_REQUIRE_ARGUMENT([ac_cv_require_qcpluscmt],[-qcpluscmt],[[]],[[//c++ cmt]])
    AC_LANG_POP([C])
    if test "$ac_cv_require_qcpluscmt" = "yes"; then
      SQUID_CFLAGS="-qcpluscmt $SQUID_CFLAGS"
    fi
    ;;

    *m88k*)
      SQUID_CFLAGS="$SQUID_CFLAGS -D_SQUID_MOTOROLA_"
      SQUID_CXXFLAGS="$SQUID_CXXFLAGS -D_SQUID_MOTOROLA_"
      AC_DEFINE(GETTIMEOFDAY_NO_TZP,1,
        [If gettimeofday is known to take only one argument])
    ;;
    [*-*-solaris2.[0-4]])
      AC_DEFINE(GETTIMEOFDAY_NO_TZP,1)
    ;;
    [*-sony-newsos[56]*])
      AC_DEFINE(GETTIMEOFDAY_NO_TZP,1)
    ;;
  esac

dnl This has to be before AC_CHECK_FUNCS
# Disable poll() on certain platforms. Override by setting ac_cv_func_poll
# when running configure.
if test "x$ac_cv_func_poll" = "x" ; then
  case "$host" in
    [*-hp-hpux*.*])
      # Duane Wessels
      AC_MSG_NOTICE([disabling poll for $host...])
      ac_cv_func_poll='no'
      ;;
    [*-linux-*])
      # Henrik Nordstrom (hno@squid-cache.org) 19980817
      # poll is problematic on Linux.  We disable it
      # by default until Linux gets it right.
      rev=`uname -r | awk -F. '{printf "%03d%03d",$1,$2}'`
      if test $rev -lt 002002; then
          AC_MSG_NOTICE([disabling poll for $host < 2.2...])
          ac_cv_func_poll='no'
      fi
      ;;
    [powerpc-ibm-aix4.1.*])
      # Mike Laster (mlaster@metavillage.com) 19981021
      AC_MSG_NOTICE([disabling poll for $host...])
      ac_cv_func_poll='no'
      ;;
    [*-pc-sco3.2*])
      # Robert Side <rside@aiinc.bc.ca>
      # Mon, 18 Jan 1999 17:48:00 GMT
      AC_MSG_NOTICE([disabling poll for $host...])
      ac_cv_func_poll='no'
      ;;
  esac
fi

dnl Check for library functions
AC_CHECK_FUNCS(\
	backtrace_symbols_fd \
	bcopy \
	eui64_aton \
	fchmod \
	getdtablesize \
	getpagesize \
	getpass \
	getrusage \
	getspnam \
	gettimeofday \
	glob \
	mallocblksize \
	mallopt \
	memcpy \
	memmove \
	memrchr \
	memset \
	mkstemp \
	mktime \
	mstats \
	poll \
	prctl \
	pthread_attr_setschedparam \
	pthread_attr_setscope \
	pthread_setschedparam \
	pthread_sigmask \
	putenv \
	regcomp \
	regexec \
	regfree \
	res_init \
	__res_init \
	rint \
	sched_getaffinity \
	sched_setaffinity \
	select \
	seteuid \
	setgroups \
	setpgrp \
	setsid \
	sigaction \
	snprintf \
	socketpair \
	sysconf \
	syslog \
	timegm \
	vsnprintf \
)
dnl ... and some we provide local replacements for
AC_REPLACE_FUNCS(\
	initgroups \
	psignal \
	strerror \
	strtoll \
	tempnam \
)

AC_CHECK_DECLS([getaddrinfo,getnameinfo,inet_ntop,inet_pton,InetNtopA,InetPtonA],,,[
/*
 * BSD requires sys/types.h, sys/socket.h, netinet/in.h, netdb.h, arpa/inet.h
 * Linux requires sys/types.h, sys/socket.h, arpa/inet.h
 * Windows requires sys/socket.h, winsock2.h, ws2tcpip.h
 */
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#if HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
])

# Magic which checks whether we are forcing a type of comm loop we
# are actually going to (ab)use.
# Mostly ripped from squid-commloops, thanks to adrian and benno

if test "x$squid_opt_io_loop_engine" != "x"; then
	AC_MSG_NOTICE([choosing user-specified net I/O API $squid_opt_io_loop_engine])
elif test "x$enable_epoll" != "xno" -a "x$squid_cv_epoll_works" = "xyes" ; then
  squid_opt_io_loop_engine="epoll"
elif test "x$enable_kqueue" != "xno" ; then
  squid_opt_io_loop_engine="kqueue"
elif test "x$enable_devpoll" != "xno" ; then
  squid_opt_io_loop_engine="devpoll"
elif test "x$enable_poll" != "xno" -a "x$ac_cv_func_poll" = "xyes" ; then
  squid_opt_io_loop_engine="poll"
elif test "x$enable_select" != "xno" -a "x$ac_cv_func_select" = "xyes"; then
  squid_opt_io_loop_engine="select"
elif test "x$enable_select" != "xno" -a "x$squid_host_os" = "xmingw"; then
  squid_opt_io_loop_engine="select_win32"
else
  AC_MSG_WARN([Eep!  Cannot find epoll, kqueue, /dev/poll, poll or select!])
  AC_MSG_WARN([Will try select and hope for the best.])
  squid_opt_io_loop_engine="select"
fi

AC_MSG_NOTICE([Using ${squid_opt_io_loop_engine} for the IO loop.])

AM_CONDITIONAL(ENABLE_POLL, test "x$squid_opt_io_loop_engine" = "xpoll")
AM_CONDITIONAL(ENABLE_EPOLL, test "x$squid_opt_io_loop_engine" = "xepoll")
AM_CONDITIONAL(ENABLE_SELECT, test "x$squid_opt_io_loop_engine" = "xselect")
AM_CONDITIONAL(ENABLE_SELECT_WIN32, test "x$squid_opt_io_loop_engine" = "xselect_win32")
AM_CONDITIONAL(ENABLE_KQUEUE, test "x$squid_opt_io_loop_engine" = "xkqueue")
AM_CONDITIONAL(ENABLE_DEVPOLL, test "x$squid_opt_io_loop_engine" = "xdevpoll")

case $squid_opt_io_loop_engine in
  epoll) AC_DEFINE(USE_EPOLL,1,[Use epoll() for the IO loop]) ;;
  devpoll) AC_DEFINE(USE_DEVPOLL,1,[Use /dev/poll for the IO loop]) ;;
  poll) AC_DEFINE(USE_POLL,1,[Use poll() for the IO loop]) ;;
  kqueue) AC_DEFINE(USE_KQUEUE,1,[Use kqueue() for the IO loop]) ;;
  select_win32) AC_DEFINE(USE_SELECT_WIN32,1,[Use Winsock select() for the IO loop]) ;;
  select) AC_DEFINE(USE_SELECT,1,[Use select() for the IO loop]) ;;
esac

if test "x$ac_cv_func_sched_getaffinity" = "xyes" -a "x$ac_cv_func_sched_setaffinity" = "xyes" ; then
  AC_DEFINE(HAVE_CPU_AFFINITY,1,[Support setting CPU affinity for workers])
fi

SQUID_CHECK_SETRESUID_WORKS
if test "x$squid_cv_resuid_works" = "xyes" ; then
  AC_DEFINE(HAVE_SETRESUID,1,[Yay! Another Linux brokenness. Knowing that setresuid() exists is not enough, because RedHat 5.0 declares setresuid() but does not implement it.])
fi

AC_CHECK_HEADERS(mswsock.h)
AC_MSG_CHECKING([for constant CMSG_SPACE])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
  #if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
  #endif
  #if HAVE_MSWSOCK_H
  #include <mswsock.h>
  #endif

  int a[CMSG_SPACE(int)];
]])], [
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_CONSTANT_CMSG_SPACE, 1, [Define to 1 if CMSG_SPACE is constant])
], [
  AC_MSG_RESULT(no)
])

AC_CHECK_TYPE(struct cmsghdr,AC_DEFINE(HAVE_CMSGHDR,1,[The system provides struct cmsghdr]),,[
  #if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
  #endif
  #if HAVE_MSWSOCK_H
  #include <mswsock.h>
  #endif
  #if HAVE_WINSOCK2_H
  #include <winsock2.h>
  #endif
])

AC_CHECK_TYPE(struct iovec,AC_DEFINE(HAVE_IOVEC,1,[The system provides struct iovec]),,[
  #if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
  #endif
  #if HAVE_WINSOCK2_H
  #include <winsock2.h>
  #endif
  #if HAVE_SYS_UIO_H
  #include <sys/uio.h>
  #endif
])

AC_CHECK_TYPE(struct msghdr,AC_DEFINE(HAVE_MSGHDR,1,[The system provides struct msghdr]),,[
  #if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
  #endif
  #if HAVE_MSWSOCK_H
  #include <mswsock.h>
  #endif
  #if HAVE_WINSOCK2_H
  #include <winsock2.h>
  #endif
])

AC_CHECK_TYPE(struct sockaddr_un,AC_DEFINE(HAVE_SOCKADDR_UN,1,[The system provides sockaddr_un]),,[
  #if HAVE_SYS_UN_H
  #include <sys/un.h>
  #endif
  #if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
  #endif
  #if HAVE_WINSOCK2_H
  #include <winsock2.h>
  #endif
])

SQUID_CHECK_FUNC_STRNSTR

dnl IP-Filter support requires ipf header files. These aren't
dnl installed by default, so we need to check for them
if test "x$enable_ipf_transparent" != "xno" ; then
    SQUID_CHECK_BROKEN_SOLARIS_IPFILTER
    AC_MSG_CHECKING(for availability of IP-Filter header files)
    # hold on to your hats...
    if test "x$ac_cv_header_ip_compat_h" = "xyes" -o \
        "x$ac_cv_header_ip_fil_compat_h" = "xyes" -o \
        "x$ac_cv_header_netinet_ip_compat_h" = "xyes" -o \
        "x$ac_cv_header_netinet_ip_fil_compat_h" = "xyes" ; then
        have_ipfilter_compat_header="yes"
    fi
    if test "x$have_ipfilter_compat_header" = "xyes" -a \
       "x$ac_cv_header_ip_fil_h" = "xyes" -a \
       "x$ac_cv_header_ip_nat_h" = "xyes" ; then
        enable_ipf_transparent="yes"
    elif test "x$have_ipfilter_compat_header" = "xyes" -a \
         "x$ac_cv_header_netinet_ip_fil_h" = "xyes" -a \
         "x$ac_cv_header_netinet_ip_nat_h" = "xyes" ; then
        enable_ipf_transparent="yes"
    else
        enable_ipf_transparent="no"
    fi
    AC_MSG_RESULT($IPF_TRANSPARENT)

## On Solaris Ipfilter includes expect that SOLARIS2 is defined with the
## Solaris minor version (8, 9, 10, ...)
  if test "x$enable_ipf_transparent" = "xyes" -a "x$squid_host_os" = "xsolaris" ; then
    solrev=`uname -r | sh -c 'IFS=. read j n x; echo $n'`
    CFLAGS="-DSOLARIS2=$solrev $CFLAGS"
    CXXFLAGS="-DSOLARIS2=$solrev $CXXFLAGS"
  fi

fi
AC_MSG_NOTICE([IPF-based transparent proxying enabled: $enable_ipf_transparent])
SQUID_DEFINE_BOOL(IPF_TRANSPARENT,$enable_ipf_transparent,
    [Enable support for IPF-style transparent proxying])

dnl PF /dev/pf support requires a header file.
if test "x$with_nat_devpf" != "xno" ; then
  if test "x$ac_cv_header_net_pfvar_h" = "xyes" -o \
    "x$ac_cv_header_net_pf_pfvar_h" = "xyes"; then
    if test "x$with_nat_devpf" = "xauto" ; then
      with_nat_devpf="no"
    fi
  else
    if test "x$with_nat_devpf" = "xyes" ; then
      AC_MSG_ERROR([PF /dev/pf based NAT requested but needed header not found])
    fi
    with_nat_devpf="no"
  fi
fi
SQUID_DEFINE_BOOL(PF_TRANSPARENT,${enable_pf_transparent:=no},
  [Enable support for PF-style transparent proxying])
SQUID_DEFINE_BOOL(USE_NAT_DEVPF,${with_nat_devpf:=no},
  [Enable support for /dev/pf NAT lookups])

if test "x$enable_linux_netfilter" != "xno" ; then
  if test "x$ac_cv_header_linux_netfilter_ipv4_h" = "xyes"; then
    if test "x$enable_linux_netfilter" = "xauto" ; then
      enable_linux_netfilter=yes
    fi
  else
    if test "x$enable_linux_netfilter" = "xauto" ; then
      enable_linux_netfilter=no
    else
      AC_MSG_ERROR([Linux Netfilter support requested but needed headers not found])
    fi
  fi
fi
SQUID_DEFINE_BOOL(LINUX_NETFILTER,$enable_linux_netfilter,
  [Enable support for Transparent Proxy on Linux via Netfilter])

dnl Netfilter TPROXY depends on libcap but the NAT parts can still work.
AC_MSG_NOTICE([Support for Netfilter-based interception proxy requested: $enable_linux_netfilter])
if test "x$enable_linux_netfilter" = "xyes" -a "x$with_libcap" != "xyes" ; then
    AC_MSG_WARN([Missing needed capabilities (libcap 2.09+) for TPROXY])
    AC_MSG_WARN([Linux Transparent Proxy (version 4+) support WILL NOT be enabled])
    AC_MSG_WARN([Reduced support to NAT Interception Proxy])
    # AC_DEFINEd later
fi

if test "x$squid_opt_netfilterconntrack" = "xyes" -a "x$with_libcap" != "xyes" ; then
    AC_MSG_ERROR([Linux netfilter conntrack requires libcap support (libcap 2.09+)])
fi
if test "x$with_netfilter_conntrack" = "xyes" -a "x$with_libcap" != "xyes" ; then
    AC_MSG_WARN([Missing needed capabilities (libcap 2.09+) for netfilter mark support])
    AC_MSG_WARN([Linux netfilter marking support WILL NOT be enabled])
    with_netfilter_conntrack=no
fi
AC_MSG_NOTICE([Linux Netfilter Conntrack support enabled: ${with_netfilter_conntrack} ${squid_opt_netfilterconntrackpath}])


AC_ARG_ENABLE(zph-qos,
  AS_HELP_STRING([--enable-zph-qos],[Enable ZPH QOS support]), [
SQUID_YESNO([$enableval],
            [unrecognized argument to --enable-zph-qos: $enableval])
])
SQUID_DEFINE_BOOL(USE_QOS_TOS,${enable_zph_qos:=yes},
          [Enable Zero Penalty Hit QOS. When set, Squid will alter the
           TOS field of HIT responses to help policing network traffic])
AC_MSG_NOTICE([ZPH QOS enabled: $enable_zph_qos])
if test x"$enable_zph_qos" = "xyes" ; then
        AC_MSG_NOTICE([QOS netfilter mark preservation enabled: $with_netfilter_conntrack])
        SQUID_DEFINE_BOOL(USE_LIBNETFILTERCONNTRACK,${with_netfilter_conntrack:=no},
                      [Enable support for QOS netfilter mark preservation])
fi


AC_CHECK_LIB(regex, regexec, [REGEXLIB="-lregex"],[REGEXLIB=''])
AC_ARG_ENABLE(gnuregex,
  AS_HELP_STRING([--enable-gnuregex],
                 [Compile GNUregex.  Unless you have reason to use 
                 this option, you should not enable it.
                 This library file is usually only required on Windows and 
                 very old Unix boxes which do not have their own regex 
                 library built in.]), [
SQUID_YESNO([$enableval],[unrecognized argument to --enable-gnuregex: $enableval])
])
# force-enable on old solaris and nextstep
if test "x${enable_gnuregex:=auto}" = "xauto" ; then
    case "$host" in
    *-sun-solaris2.[[0-4]])
	  enable_gnuregex="yes"
	  ;;
    *-next-nextstep*)
	  enable_gnuregex="yes"
	  ;;
    esac
fi

# try detecting if it is needed
if test "x$enable_gnuregex" = "xauto" ; then
  SQUID_CHECK_REGEX_WORKS
  if test "x$squid_cv_regex_works" = "xyes" ; then
    enable_gnuregex=no
  else
    enable_gnuregex=yes
  fi
fi
AC_MSG_CHECKING(if GNUregex needs to be compiled)
AC_MSG_RESULT($enable_gnuregex)
if test "x$enable_gnuregex" = "xyes"; then
  # for some reason (force-enable, test..) gnuregex was found as needed. Override any system lib
  REGEXLIB=""
fi
#if no reason was found to enable gnuregex, disable it
if test "x$enable_gnuregex" = "xauto" ; then
  enable_gnuregex=no
fi
SQUID_DEFINE_BOOL(USE_GNUREGEX,$enable_gnuregex,[Define if we should use GNU regex])
AC_SUBST(REGEXLIB)

SQUID_DETECT_UDP_SND_BUFSIZE
SQUID_DETECT_UDP_RECV_BUFSIZE
SQUID_DETECT_TCP_SND_BUFSIZE
SQUID_DETECT_TCP_RECV_BUFSIZE

SQUID_CHECK_RECV_ARG_TYPE
SQUID_CHECK_NEED_SYS_ERRLIST
SQUID_CHECK_MAXPATHLEN

SQUID_CHECK_LIBRESOLV_DNS_TTL_HACK
SQUID_CHECK_RESOLVER_FIELDS

AC_CHECK_HEADERS(sys/statvfs.h)
if test "x$ac_cv_header_sys_statvfs_h" = "xyes" ; then
  SQUID_CHECK_WORKING_STATVFS
fi
if test "x$ac_cv_func_statvfs" != "xyes" ; then
  AC_CHECK_HEADERS(sys/param.h sys/mount.h sys/vfs.h sys/statfs.h)
  AC_CHECK_FUNCS(statfs)
  SQUID_CHECK_F_FRSIZE_IN_STATFS
fi

dnl Squid will not usually attempt to translate templates when building
AC_ARG_ENABLE(translation,
 AS_HELP_STRING([--enable-translation],[Generate the localized error page templates and manuals.
		 Which can also be downloaded from http://www.squid-cache.org/Versions/langpack/.]), [ 
  SQUID_YESNO([$enableval],
     [unrecognized argument to --enable-translation: $enableval])
])
if test "x${enable_translation:=no}" = "xyes" ; then
  AX_WITH_PROG([PO2HTML],[po2html])
  AX_WITH_PROG([PO2TEXT],[po2txt])
else
  PO2HTML="off"
  PO2TEXT="off"
fi
AC_SUBST(PO2HTML)
AC_SUBST(PO2TEXT)

dnl Squid now has limited locale handling ...
dnl on error pages
AC_ARG_ENABLE(auto-locale,
 AS_HELP_STRING([--disable-auto-locale],[This prevents Squid providing localized error pages based on the
		 clients request headers.
		 When disabled Squid requires explicit language configuration.]), [
SQUID_YESNO([$enableval],
    [unrecognized argument to --disable-auto-locale: $enableval])
])
AC_MSG_NOTICE([Multi-Language support enabled: ${enable_auto_locale:=yes}])
SQUID_DEFINE_BOOL(USE_ERR_LOCALES,$enable_auto_locale,
   [Use multi-language support on error pages])


dnl Need the debugging version of malloc if available
XTRA_OBJS=''
if test "x$ac_cv_lib_malloc_main" = "xyes" ; then
	if test -r /usr/lib/debug/malloc.o ; then
		XTRA_OBJS="$XTRA_OBJS /usr/lib/debug/malloc.o"
	fi
	if test -r /usr/lib/debug/mallocmap.o ; then
		XTRA_OBJS="$XTRA_OBJS /usr/lib/debug/mallocmap.o"
	fi
fi
AC_SUBST(XTRA_OBJS)

if test "x$XTRA_LIBS" = "x"; then
	XTRA_LIBS="$LIBS"
	dnl minor cleanup
	XTRA_LIBS=`echo $XTRA_LIBS | sed -e "s/  */ /g"`
	LIBS=''
fi
AC_SUBST(XTRA_LIBS)

AC_SUBST(SQUID_CFLAGS)
AC_SUBST(SQUID_CXXFLAGS)

AC_ARG_VAR([BUILDCXXFLAGS],[C++ compiler flags for building compile-time tools. e.g. cf_gen])
if test "x$BUILDCXXFLAGS" = "x"; then
  # if we are NOT cross-compiling, use the default build flags for cf_gen and friends
  # otherwise rely on the user-provided value
  if test "x$squid_cv_check_marchnative" = "xyes"; then
    # always valid for the Build compiler.
    BUILDCXXFLAGS="-march=native"
  fi
  BUILDCXXFLAGS="$BUILDCXXFLAGS $CXXFLAGS"
fi
AC_SUBST(BUILDCXXFLAGS)

AC_MSG_NOTICE([BUILD LIBRARIES: $LIBS])
AC_MSG_NOTICE([BUILD EXTRA LIBRARIES: $XTRA_LIBS])
AC_MSG_NOTICE([BUILD OBJECTS: $OBJS])
AC_MSG_NOTICE([BUILD EXTRA OBJECTS: $XTRA_OBJS])
AC_MSG_NOTICE([BUILD C FLAGS: $CFLAGS])
AC_MSG_NOTICE([BUILD EXTRA C FLAGS: $SQUID_CFLAGS])
AC_MSG_NOTICE([BUILD C++ FLAGS: $CXXFLAGS])
AC_MSG_NOTICE([BUILD EXTRA C++ FLAGS: $SQUID_CXXFLAGS])
AC_MSG_NOTICE([BUILD Tools C++ FLAGS: $BUILDCXXFLAGS])

dnl Clean up after OSF/1 core dump bug
rm -f core 

AC_CONFIG_FILES([
	Makefile
	compat/Makefile
	contrib/Makefile
	doc/Makefile
	doc/manuals/Makefile
	doc/release-notes/Makefile
	errors/Makefile
	icons/Makefile
	lib/Makefile
	lib/libTrie/Makefile
	lib/libTrie/test/Makefile
	lib/ntlmauth/Makefile
	lib/profiler/Makefile
	lib/rfcnb/Makefile
	lib/smblib/Makefile
	lib/snmplib/Makefile
	scripts/Makefile
	src/Makefile
	src/acl/Makefile
	src/acl/external/Makefile
	src/acl/external/AD_group/Makefile
	src/acl/external/delayer/Makefile
	src/acl/external/eDirectory_userip/Makefile
	src/acl/external/file_userip/Makefile
	src/acl/external/kerberos_ldap_group/Makefile
	src/acl/external/kerberos_sid_group/Makefile
	src/acl/external/LDAP_group/Makefile
	src/acl/external/LM_group/Makefile
	src/acl/external/session/Makefile
	src/acl/external/SQL_session/Makefile
	src/acl/external/unix_group/Makefile
	src/acl/external/wbinfo_group/Makefile
	src/acl/external/time_quota/Makefile
	src/adaptation/Makefile
	src/adaptation/icap/Makefile
	src/adaptation/ecap/Makefile
	src/anyp/Makefile
	src/auth/Makefile
	src/auth/basic/Makefile
	src/auth/basic/DB/Makefile
	src/auth/basic/fake/Makefile
	src/auth/basic/getpwnam/Makefile
	src/auth/basic/LDAP/Makefile
	src/auth/basic/NCSA/Makefile
	src/auth/basic/NIS/Makefile
	src/auth/basic/PAM/Makefile
	src/auth/basic/POP3/Makefile
	src/auth/basic/RADIUS/Makefile
	src/auth/basic/SASL/Makefile
	src/auth/basic/SMB/Makefile
	src/auth/basic/SMB_LM/Makefile
	src/auth/basic/SSPI/Makefile
	src/auth/digest/Makefile
	src/auth/digest/eDirectory/Makefile
	src/auth/digest/file/Makefile
	src/auth/digest/LDAP/Makefile
	src/auth/negotiate/Makefile
	src/auth/negotiate/kerberos/Makefile
	src/auth/negotiate/SSPI/Makefile
	src/auth/negotiate/wrapper/Makefile
	src/auth/ntlm/Makefile
	src/auth/ntlm/fake/Makefile
	src/auth/ntlm/SMB_LM/Makefile
	src/auth/ntlm/SSPI/Makefile
	src/base/Makefile
	src/clients/Makefile
	src/comm/Makefile
	src/dns/Makefile
	src/DiskIO/Makefile
	src/DiskIO/AIO/Makefile
	src/DiskIO/Blocking/Makefile
	src/DiskIO/DiskDaemon/Makefile
	src/DiskIO/DiskThreads/Makefile
	src/DiskIO/IpcIo/Makefile
	src/DiskIO/Mmapped/Makefile
	src/esi/Makefile
	src/eui/Makefile
	src/format/Makefile
	src/fs/Makefile
	src/ftp/Makefile
	src/helper/Makefile
	src/http/Makefile
	src/http/one/Makefile
	src/http/url_rewriters/Makefile
	src/http/url_rewriters/fake/Makefile
	src/http/url_rewriters/LFS/Makefile
	src/icmp/Makefile
	src/ident/Makefile
	src/ip/Makefile
	src/ipc/Makefile
	src/log/Makefile
	src/log/DB/Makefile
	src/log/file/Makefile
	src/mem/Makefile
	src/mgr/Makefile
	src/parser/Makefile
	src/proxyp/Makefile
	src/repl/Makefile
	src/sbuf/Makefile
	src/security/Makefile
	src/security/cert_generators/Makefile
	src/security/cert_generators/file/Makefile
	src/security/cert_validators/Makefile
	src/security/cert_validators/fake/Makefile
	src/servers/Makefile
	src/snmp/Makefile
	src/ssl/Makefile
	src/store/Makefile
	src/store/id_rewriters/Makefile
	src/store/id_rewriters/file/Makefile
	test-suite/Makefile
	tools/Makefile
	tools/apparmor/Makefile
	tools/helper-mux/Makefile
	tools/purge/Makefile
	tools/squidclient/Makefile
	tools/systemd/Makefile
	tools/sysvinit/Makefile
])

# must configure libltdl subdir unconditionally for "make distcheck" to work
#AC_CONFIG_SUBDIRS(libltdl)

AC_OUTPUT
