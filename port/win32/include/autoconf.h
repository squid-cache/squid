/* include/autoconf.h.  Generated from autoconf.h.in by configure.  */
/* include/autoconf.h.in.  Generated from configure.in by autoheader.  */

/* Defines how many threads aufs uses for I/O */
/* #undef AUFS_IO_THREADS */

/* If you are upset that the cachemgr.cgi form comes up with the hostname
   field blank, then define this to getfullhostname() */
/* #undef CACHEMGR_HOSTNAME */

/* What default TCP port to use for HTTP listening? */
#define CACHE_HTTP_PORT 3128

/* What default UDP port to use for ICP listening? */
#define CACHE_ICP_PORT 3130

/* Enable for cbdata debug information */
/* #undef CBDATA_DEBUG */

/* Host type from configure */
#define CONFIG_HOST_TYPE "i686-pc-winnt"

/* Define if you want to set the COSS membuf size */
/* #undef COSS_MEMBUF_SZ */

/* Define to one of `_getb67', `GETB67', `getb67' for Cray-2 and Cray-YMP
   systems. This function is required for `alloca.c' support on those systems.
   */
/* #undef CRAY_STACKSEG_END */

/* Define to 1 if using `alloca.c'. */
/* #undef C_ALLOCA */

/* Default FD_SETSIZE value */
#define DEFAULT_FD_SETSIZE 256

/* Traffic management via "delay pools". */
/* #undef DELAY_POOLS */

/* Define if you have problems with memPools and want to disable Pools. */
#define DISABLE_POOLS 0

/* Enable Forw/Via database */
#define FORW_VIA_DB 1

/* If gettimeofday is known to take only one argument */
/* #undef GETTIMEOFDAY_NO_TZP */

/* Define to 1 if you have `alloca', as a function or macro. */
#define HAVE_ALLOCA 1

/* Define to 1 if you have <alloca.h> and it should be used (not on Ultrix).
   */
/* #undef HAVE_ALLOCA_H */

/* Define to 1 if you have the <arpa/inet.h> header file. */
/* #undef HAVE_ARPA_INET_H */

/* Define to 1 if you have the <arpa/nameser.h> header file. */
/* #undef HAVE_ARPA_NAMESER_H */

/* Define to 1 if you have the <assert.h> header file. */
#define HAVE_ASSERT_H 1

/* Define to 1 if you have the `backtrace_symbols_fd' function. */
/* #undef HAVE_BACKTRACE_SYMBOLS_FD */

/* Define to 1 if you have the `bcopy' function. */
/* #undef HAVE_BCOPY */

/* Define to 1 if you have the <bstring.h> header file. */
/* #undef HAVE_BSTRING_H */

/* Define to 1 if you have the `bswap16' function. */
/* #undef HAVE_BSWAP16 */

/* Define to 1 if you have the `bswap32' function. */
/* #undef HAVE_BSWAP32 */

/* Define to 1 if you have the `bswap_16' function. */
/* #undef HAVE_BSWAP_16 */

/* Define to 1 if you have the `bswap_32' function. */
/* #undef HAVE_BSWAP_32 */

/* Define to 1 if you have the <byteswap.h> header file. */
/* #undef HAVE_BYTESWAP_H */

/* char is defined in system headers */
#define HAVE_CHAR 1

/* Define to 1 if you have the `crypt' function. */
#define HAVE_CRYPT 1

/* Define to 1 if you have the <crypt.h> header file. */
#define HAVE_CRYPT_H 1

/* Define to 1 if you have the <ctype.h> header file. */
#define HAVE_CTYPE_H 1

/* Define to 1 if you have the <db_185.h> header file. */
/* #undef HAVE_DB_185_H */

/* Define to 1 if you have the <db.h> header file. */
/* #undef HAVE_DB_H */

/* Define to 1 if you have the <dirent.h> header file, and it defines `DIR'.
   */
#define HAVE_DIRENT_H 1

/* Define if you have the GNU dld library. */
/* #undef HAVE_DLD */

/* Define to 1 if you have the `dlerror' function. */
/* #undef HAVE_DLERROR */

/* Define to 1 if you have the <dlfcn.h> header file. */
/* #undef HAVE_DLFCN_H */

/* Define to 1 if you have the `drand48' function. */
/* #undef HAVE_DRAND48 */

/* Define if you have the _dyld_func_lookup function. */
/* #undef HAVE_DYLD */

/* Define to 1 if you have the `epoll_ctl' function. */
/* #undef HAVE_EPOLL_CTL */

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the <execinfo.h> header file. */
/* #undef HAVE_EXECINFO_H */

/* Define to 1 if you have the `fchmod' function. */
/* #undef HAVE_FCHMOD */

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* fd_mask is defined by the system headers */
/* #undef HAVE_FD_MASK */

/* Define to 1 if you have the <fnmatch.h> header file. */
/* #undef HAVE_FNMATCH_H */

/* Define to 1 if you have the `getdtablesize' function. */
/* #undef HAVE_GETDTABLESIZE */

/* Define to 1 if you have the <getopt.h> header file. */
#define HAVE_GETOPT_H 1

/* Define to 1 if you have the `getpagesize' function. */
#define HAVE_GETPAGESIZE 1

/* Define to 1 if you have the `getpass' function. */
/* #undef HAVE_GETPASS */

/* Define to 1 if you have the `getrlimit' function. */
/* #undef HAVE_GETRLIMIT */

/* Define to 1 if you have the `getrusage' function. */
#define HAVE_GETRUSAGE 1

/* Define to 1 if you have the `getspnam' function. */
/* #undef HAVE_GETSPNAM */

/* Define to 1 if you have the `gettimeofday' function. */
/* #undef HAVE_GETTIMEOFDAY */

/* Define to 1 if you have the <glib.h> header file. */
/* #undef HAVE_GLIB_H */

/* Define to 1 if you have the <gnumalloc.h> header file. */
/* #undef HAVE_GNUMALLOC_H */

/* Define to 1 if you have the <grp.h> header file. */
/* #undef HAVE_GRP_H */

/* Define to 1 if you have the `htobe16' function. */
/* #undef HAVE_HTOBE16 */

/* Define to 1 if you have the `htole16' function. */
/* #undef HAVE_HTOLE16 */

/* Define to 1 if you have the `initgroups' function. */
/* #undef HAVE_INITGROUPS */

/* int is defined in system headers */
#define HAVE_INT 1

/* int16_t is defined in system headers */
/* #undef HAVE_INT16_T */

/* int32_t is defined in system headers */
/* #undef HAVE_INT32_T */

/* int64_t is defined in system headers */
/* #undef HAVE_INT64_T */

/* int8_t is defined in system headers */
/* #undef HAVE_INT8_T */

/* Define to 1 if you have the <inttypes.h> header file. */
/* #undef HAVE_INTTYPES_H */

/* Define to 1 if you have the <ipl.h> header file. */
/* #undef HAVE_IPL_H */

/* Define to 1 if you have the <ip_compat.h> header file. */
/* #undef HAVE_IP_COMPAT_H */

/* Define to 1 if you have the <ip_fil_compat.h> header file. */
/* #undef HAVE_IP_FIL_COMPAT_H */

/* Define to 1 if you have the <ip_fil.h> header file. */
/* #undef HAVE_IP_FIL_H */

/* Define to 1 if you have the <ip_nat.h> header file. */
/* #undef HAVE_IP_NAT_H */

/* Define to 1 if you have the `kqueue' function. */
/* #undef HAVE_KQUEUE */

/* Define to 1 if you have the `44bsd' library (-l44bsd). */
/* #undef HAVE_LIB44BSD */

/* Define to 1 if you have the `aio' library (-laio). */
/* #undef HAVE_LIBAIO */

/* Define to 1 if you have the `bind' library (-lbind). */
/* #undef HAVE_LIBBIND */

/* Define to 1 if you have the `bsd' library (-lbsd). */
/* #undef HAVE_LIBBSD */

/* Define to 1 if you have the <libc.h> header file. */
/* #undef HAVE_LIBC_H */

/* Define to 1 if you have the `dl' library (-ldl). */
/* #undef HAVE_LIBDL */

/* Define to 1 if you have the `gnumalloc' library (-lgnumalloc). */
/* #undef HAVE_LIBGNUMALLOC */

/* Define to 1 if you have the `intl' library (-lintl). */
/* #undef HAVE_LIBINTL */

/* Define to 1 if you have the `m' library (-lm). */
/* #undef HAVE_LIBM */

/* Define to 1 if you have the `malloc' library (-lmalloc). */
/* #undef HAVE_LIBMALLOC */

/* Define to 1 if you have the `nsl' library (-lnsl). */
/* #undef HAVE_LIBNSL */

/* Define to 1 if you have the `pthread' library (-lpthread). */
/* #undef HAVE_LIBPTHREAD */

/* Define to 1 if you have the `resolv' library (-lresolv). */
/* #undef HAVE_LIBRESOLV */

/* Define to 1 if you have the `rt' library (-lrt). */
/* #undef HAVE_LIBRT */

/* Define to 1 if you have the `socket' library (-lsocket). */
/* #undef HAVE_LIBSOCKET */

/* Define to 1 if you have the <libxml/parser.h> header file. */
#define HAVE_LIBXML_PARSER_H 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the <linux/netfilter_ipv4.h> header file. */
/* #undef HAVE_LINUX_NETFILTER_IPV4_H */

/* Define to 1 if you have the <linux/netfilter_ipv4/ip_tproxy.h> header file.
   */
/* #undef HAVE_LINUX_NETFILTER_IPV4_IP_TPROXY_H */

/* long is defined in system headers */
#define HAVE_LONG 1

/* long long is defined in system headers */
/* #undef HAVE_LONG_LONG */

/* Define to 1 if you have the `lrand48' function. */
/* #undef HAVE_LRAND48 */

/* Define to 1 if you have the `mallinfo' function. */
/* #undef HAVE_MALLINFO */

/* Define to 1 if you have the `mallocblksize' function. */
/* #undef HAVE_MALLOCBLKSIZE */

/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* Define to 1 if you have the `mallopt' function. */
/* #undef HAVE_MALLOPT */

/* Define to 1 if you have the <math.h> header file. */
#define HAVE_MATH_H 1

/* Define to 1 if you have the `memcpy' function. */
#define HAVE_MEMCPY 1

/* Define to 1 if you have the `memmove' function. */
#define HAVE_MEMMOVE 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define to 1 if you have the `mkstemp' function. */
/* #undef HAVE_MKSTEMP */

/* Define to 1 if you have the `mktime' function. */
#define HAVE_MKTIME 1

/* mode_t is defined by the system headers */
/* #undef HAVE_MODE_T */

/* Define to 1 if you have the <mount.h> header file. */
/* #undef HAVE_MOUNT_H */

/* Define to 1 if you have the `mstats' function. */
/* #undef HAVE_MSTATS */

/* mtyp_t is defined by the system headers */
/* #undef HAVE_MTYP_T */

/* Define to 1 if you have the <ndir.h> header file, and it defines `DIR'. */
/* #undef HAVE_NDIR_H */

/* Define to 1 if you have the <netdb.h> header file. */
/* #undef HAVE_NETDB_H */

/* Define to 1 if you have the <netinet/if_ether.h> header file. */
/* #undef HAVE_NETINET_IF_ETHER_H */

/* Define to 1 if you have the <netinet/in.h> header file. */
/* #undef HAVE_NETINET_IN_H */

/* Define to 1 if you have the <netinet/ipl.h> header file. */
/* #undef HAVE_NETINET_IPL_H */

/* Define to 1 if you have the <netinet/ip_compat.h> header file. */
/* #undef HAVE_NETINET_IP_COMPAT_H */

/* Define to 1 if you have the <netinet/ip_fil_compat.h> header file. */
/* #undef HAVE_NETINET_IP_FIL_COMPAT_H */

/* Define to 1 if you have the <netinet/ip_fil.h> header file. */
/* #undef HAVE_NETINET_IP_FIL_H */

/* Define to 1 if you have the <netinet/ip_nat.h> header file. */
/* #undef HAVE_NETINET_IP_NAT_H */

/* Define to 1 if you have the <netinet/tcp.h> header file. */
/* #undef HAVE_NETINET_TCP_H */

/* Define to 1 if you have the <net/if.h> header file. */
/* #undef HAVE_NET_IF_H */

/* Define to 1 if you have the <net/pfvar.h> header file. */
/* #undef HAVE_NET_PFVAR_H */

/* Define to 1 if you have the <nss_common.h> header file. */
/* #undef HAVE_NSS_COMMON_H */

/* Define to 1 if you have the <nss.h> header file. */
/* #undef HAVE_NSS_H */

/* off_t is defined by the system headers */
#define HAVE_OFF_T 1

/* Define to 1 if you have the <openssl/engine.h> header file. */
#define HAVE_OPENSSL_ENGINE_H 1

/* Define to 1 if you have the <openssl/err.h> header file. */
#define HAVE_OPENSSL_ERR_H 1

/* Define to 1 if you have the <openssl/md5.h> header file. */
#define HAVE_OPENSSL_MD5_H 1

/* Define to 1 if you have the <openssl/ssl.h> header file. */
#define HAVE_OPENSSL_SSL_H 1

/* pad128_t is defined in system headers */
/* #undef HAVE_PAD128_T */

/* Define to 1 if you have the <paths.h> header file. */
/* #undef HAVE_PATHS_H */

/* pid_t is defined by the system headers */
#define HAVE_PID_T 1

/* Define to 1 if you have the `poll' function. */
/* #undef HAVE_POLL */

/* Define to 1 if you have the <poll.h> header file. */
/* #undef HAVE_POLL_H */

/* Define to 1 if you have the `prctl' function. */
/* #undef HAVE_PRCTL */

/* Define to 1 if you have the `pthread_attr_setschedparam' function. */
/* #undef HAVE_PTHREAD_ATTR_SETSCHEDPARAM */

/* Define to 1 if you have the `pthread_attr_setscope' function. */
/* #undef HAVE_PTHREAD_ATTR_SETSCOPE */

/* Define to 1 if you have the `pthread_setschedparam' function. */
/* #undef HAVE_PTHREAD_SETSCHEDPARAM */

/* Define to 1 if you have the `pthread_sigmask' function. */
/* #undef HAVE_PTHREAD_SIGMASK */

/* Define to 1 if you have the `putenv' function. */
#define HAVE_PUTENV 1

/* Define to 1 if you have the <pwd.h> header file. */
/* #undef HAVE_PWD_H */

/* Define to 1 if you have the `random' function. */
/* #undef HAVE_RANDOM */

/* Define to 1 if you have the `regcomp' function. */
#define HAVE_REGCOMP 1

/* Define to 1 if you have the `regexec' function. */
#define HAVE_REGEXEC 1

/* Define to 1 if you have the <regex.h> header file. */
/* #undef HAVE_REGEX_H */

/* Define to 1 if you have the `regfree' function. */
#define HAVE_REGFREE 1

/* Define to 1 if you have the <resolv.h> header file. */
/* #undef HAVE_RESOLV_H */

/* Define to 1 if you have the `res_init' function. */
/* #undef HAVE_RES_INIT */

/* If _res structure has nsaddr_list member */
/* #undef HAVE_RES_NSADDR_LIST */

/* If _res structure has ns_list member */
/* #undef HAVE_RES_NS_LIST */

/* Define to 1 if you have the `rint' function. */
/* #undef HAVE_RINT */

/* Define to 1 if you have the <sasl.h> header file. */
/* #undef HAVE_SASL_H */

/* Define to 1 if you have the <sasl/sasl.h> header file. */
/* #undef HAVE_SASL_SASL_H */

/* Define to 1 if you have the `sbrk' function. */
/* #undef HAVE_SBRK */

/* Define to 1 if you have the <sched.h> header file. */
/* #undef HAVE_SCHED_H */

/* Define to 1 if you have the `select' function. */
#define HAVE_SELECT 1

/* Define to 1 if you have the `seteuid' function. */
#define HAVE_SETEUID 1

/* Define to 1 if you have the `setgroups' function. */
/* #undef HAVE_SETGROUPS */

/* Define to 1 if you have the `setpgrp' function. */
/* #undef HAVE_SETPGRP */

/* Yay! Another Linux brokenness. Its not good enough to know that setresuid()
   exists, because RedHat 5.0 declare setresuid() but doesn't implement it. */
/* #undef HAVE_SETRESUID */

/* Define to 1 if you have the `setrlimit' function. */
/* #undef HAVE_SETRLIMIT */

/* Define to 1 if you have the `setsid' function. */
/* #undef HAVE_SETSID */

/* Define to 1 if you have the <shadow.h> header file. */
/* #undef HAVE_SHADOW_H */

/* Define if you have the shl_load function. */
/* #undef HAVE_SHL_LOAD */

/* short is defined in system headers */
#define HAVE_SHORT 1

/* Define to 1 if you have the `sigaction' function. */
/* #undef HAVE_SIGACTION */

/* Define to 1 if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1

/* size_t is defined by the system headers */
#define HAVE_SIZE_T 1

/* Define to 1 if you have the `snprintf' function. */
#define HAVE_SNPRINTF 1

/* Define to 1 if you have the `socketpair' function. */
/* #undef HAVE_SOCKETPAIR */

/* socklen_t is defined by the system headers */
/* #undef HAVE_SOCKLEN_T */

/* Define to 1 if you have the `srand48' function. */
/* #undef HAVE_SRAND48 */

/* Define to 1 if you have the `srandom' function. */
/* #undef HAVE_SRANDOM */

/* ssize_t is defined by the system headers */
/* #undef HAVE_SSIZE_T */

/* Define to 1 if you have the `statfs' function. */
#define HAVE_STATFS 1

/* If your system has statvfs(), and if it actually works! */
/* #undef HAVE_STATVFS */

/* Define to 1 if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define to 1 if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
/* #undef HAVE_STRINGS_H */

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strsep' function. */
/* #undef HAVE_STRSEP */

/* Define to 1 if you have the `strtoll' function. */
/* #undef HAVE_STRTOLL */

/* Define to 1 if `ip_hl' is member of `struct iphdr'. */
/* #undef HAVE_STRUCT_IPHDR_IP_HL */

/* The system provides struct mallinfo */
/* #undef HAVE_STRUCT_MALLINFO */

/* Define to 1 if `mxfast' is member of `struct mallinfo'. */
/* #undef HAVE_STRUCT_MALLINFO_MXFAST */

/* The system provides struct rusage */
#define HAVE_STRUCT_RUSAGE 1

/* Define to 1 if `tm_gmtoff' is member of `struct tm'. */
/* #undef HAVE_STRUCT_TM_TM_GMTOFF */

/* Define to 1 if you have the <syscall.h> header file. */
/* #undef HAVE_SYSCALL_H */

/* Define to 1 if you have the `sysconf' function. */
/* #undef HAVE_SYSCONF */

/* Define to 1 if you have the `syslog' function. */
/* #undef HAVE_SYSLOG */

/* Define to 1 if you have the <syslog.h> header file. */
/* #undef HAVE_SYSLOG_H */

/* Define to 1 if you have the <sys/bitypes.h> header file. */
/* #undef HAVE_SYS_BITYPES_H */

/* Define to 1 if you have the <sys/bswap.h> header file. */
/* #undef HAVE_SYS_BSWAP_H */

/* Define to 1 if you have the <sys/capability.h> header file. */
/* #undef HAVE_SYS_CAPABILITY_H */

/* Define to 1 if you have the <sys/dir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_DIR_H */

/* Define to 1 if you have the <sys/endian.h> header file. */
/* #undef HAVE_SYS_ENDIAN_H */

/* Define to 1 if you have the <sys/file.h> header file. */
/* #undef HAVE_SYS_FILE_H */

/* Define to 1 if you have the <sys/ioctl.h> header file. */
/* #undef HAVE_SYS_IOCTL_H */

/* Define to 1 if you have the <sys/md5.h> header file. */
/* #undef HAVE_SYS_MD5_H */

/* Define to 1 if you have the <sys/mount.h> header file. */
/* #undef HAVE_SYS_MOUNT_H */

/* Define to 1 if you have the <sys/msg.h> header file. */
/* #undef HAVE_SYS_MSG_H */

/* Define to 1 if you have the <sys/ndir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_NDIR_H */

/* Define to 1 if you have the <sys/param.h> header file. */
/* #undef HAVE_SYS_PARAM_H */

/* Define to 1 if you have the <sys/prctl.h> header file. */
/* #undef HAVE_SYS_PRCTL_H */

/* Define to 1 if you have the <sys/resource.h> header file. */
/* #undef HAVE_SYS_RESOURCE_H */

/* Define to 1 if you have the <sys/select.h> header file. */
/* #undef HAVE_SYS_SELECT_H */

/* Define to 1 if you have the <sys/socket.h> header file. */
/* #undef HAVE_SYS_SOCKET_H */

/* Define to 1 if you have the <sys/statvfs.h> header file. */
/* #undef HAVE_SYS_STATVFS_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/syscall.h> header file. */
/* #undef HAVE_SYS_SYSCALL_H */

/* Define to 1 if you have the <sys/time.h> header file. */
/* #undef HAVE_SYS_TIME_H */

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/un.h> header file. */
/* #undef HAVE_SYS_UN_H */

/* Define to 1 if you have the <sys/vfs.h> header file. */
/* #undef HAVE_SYS_VFS_H */

/* Define to 1 if you have the <sys/wait.h> header file. */
/* #undef HAVE_SYS_WAIT_H */

/* Define to 1 if you have the `tempnam' function. */
#define HAVE_TEMPNAM 1

/* Define to 1 if you have the `timegm' function. */
/* #undef HAVE_TIMEGM */

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* uint16_t is defined in system headers */
#define HAVE_UINT16_T 1

/* uint32_t is defined in system headers */
#define HAVE_UINT32_T 1

/* uint64_t is defined in system headers */
#define HAVE_UINT64_T 1

/* uint8_t is defined in system headers */
#define HAVE_UINT8_T 1

/* Define to 1 if you have the <unistd.h> header file. */
/* #undef HAVE_UNISTD_H */

/* Do we have unix sockets? (required for the winbind ntlm helper */
/* #undef HAVE_UNIXSOCKET */

/* upad128_t is defined in system headers */
/* #undef HAVE_UPAD128_T */

/* Define to 1 if you have the <utime.h> header file. */
/* #undef HAVE_UTIME_H */

/* u_int16_t is defined in system headers */
/* #undef HAVE_U_INT16_T */

/* u_int32_t is defined in system headers */
/* #undef HAVE_U_INT32_T */

/* u_int64_t is defined in system headers */
/* #undef HAVE_U_INT64_T */

/* u_int8_t is defined in system headers */
/* #undef HAVE_U_INT8_T */

/* Define to 1 if you have the <varargs.h> header file. */
#define HAVE_VARARGS_H 1

/* If your system have va_copy */
/* #undef HAVE_VA_COPY 1 */

/* Define to 1 if you have the `vsnprintf' function. */
#define HAVE_VSNPRINTF 1

/* Define if you have PSAPI.DLL on Windows systems */
#define HAVE_WIN32_PSAPI 1

/* __int64 is defined in system headers */
#define HAVE___INT64 1

/* Define to 1 if you have the `__res_init' function. */
/* #undef HAVE___RES_INIT */

/* Some systems have __va_copy instead of va_copy */
/* #undef HAVE___VA_COPY 1 */

/* By default (for now anyway) Squid includes options which allows the cache
   administrator to violate the HTTP protocol specification in terms of cache
   behaviour. Setting this to '0' will disable such code. */
#define HTTP_VIOLATIONS 1

/* Enable ICAP client features in Squid */
#define ICAP_CLIENT 1

/* Enable support for Transparent Proxy on systems using FreeBSD IPFW address
   redirection. */
/* #undef IPFW_TRANSPARENT */

/* Enable support for Transparent Proxy on systems using IP-Filter address
   redirection. This provides "masquerading" support for non Linux system. */
/* #undef IPF_TRANSPARENT */

/* A dangerous feature which causes Squid to kill its parent process
   (presumably the RunCache script) upon receipt of SIGTERM or SIGINT. Use
   with caution. */
/* #undef KILL_PARENT_OPT */

/* If libresolv.a has been hacked to export _dns_ttl_ */
/* #undef LIBRESOLV_DNS_TTL_HACK */

/* Enable support for Transparent Proxy on Linux (Netfilter) systems */
/* #undef LINUX_NETFILTER */

/* Enable real Transparent Proxy support for Netfilter TPROXY. */
/* #undef LINUX_TPROXY */

/* If we need to declare sys_errlist[] as external */
#define NEED_SYS_ERRLIST 1

/* Define to 1 if your C compiler doesn't accept -c and -o together. */
/* #undef NO_MINUS_C_MINUS_O */

/* Define if NTLM is allowed to fail gracefully when a helper has problems.
   WARNING: This has security implications. DO NOT enable unless you KNOW you
   need it. */
/* #undef NTLM_FAIL_OPEN */

/* Enable support for Transparent Proxy on systems using PF address
   redirection. This provides "masquerading" support for OpenBSD. */
/* #undef PF_TRANSPARENT */

/* Print stacktraces on fatal errors */
/* #undef PRINT_STACK_TRACE */

/* The size of `char', as computed by sizeof. */
#define SIZEOF_CHAR 1

/* The size of `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of `int16_t', as computed by sizeof. */
/* #undef SIZEOF_INT16_T */

/* The size of `int32_t', as computed by sizeof. */
/* #undef SIZEOF_INT32_T */

/* The size of `int64_t', as computed by sizeof. */
/* #undef SIZEOF_INT64_T */

/* The size of `int8_t', as computed by sizeof. */
/* #undef SIZEOF_INT8_T */

/* The size of `long', as computed by sizeof. */
#define SIZEOF_LONG 4

/* The size of `long long', as computed by sizeof. */
#define SIZEOF_LONG_LONG 8

/* The size of `off_t', as computed by sizeof. */
#define SIZEOF_OFF_T 4

/* The size of `short', as computed by sizeof. */
#define SIZEOF_SHORT 2

/* The size of `size_t', as computed by sizeof. */
#define SIZEOF_SIZE_T 4

/* The size of `uint16_t', as computed by sizeof. */
#define SIZEOF_UINT16_T 2

/* The size of `uint32_t', as computed by sizeof. */
#define SIZEOF_UINT32_T 4

/* The size of `uint64_t', as computed by sizeof. */
#define SIZEOF_UINT64_T 8

/* The size of `uint8_t', as computed by sizeof. */
/* #undef SIZEOF_UINT8_T */

/* The size of `u_int16_t', as computed by sizeof. */
/* #undef SIZEOF_U_INT16_T */

/* The size of `u_int32_t', as computed by sizeof. */
/* #undef SIZEOF_U_INT32_T */

/* The size of `u_int64_t', as computed by sizeof. */
/* #undef SIZEOF_U_INT64_T */

/* The size of `u_int8_t', as computed by sizeof. */
/* #undef SIZEOF_U_INT8_T */

/* The size of `void *', as computed by sizeof. */
#define SIZEOF_VOID_P 4

/* The size of `__int64', as computed by sizeof. */
#define SIZEOF___INT64 8

/* UDP receive buffer size */
#define SQUID_DETECT_UDP_SO_RCVBUF 16384

/* UDP send buffer size */
#define SQUID_DETECT_UDP_SO_SNDBUF 16384

/* Maximum number of open filedescriptors */
#define SQUID_MAXFD 2048

/* Define to enable SNMP monitoring of Squid */
#define SQUID_SNMP 1

/* TCP receive buffer size */
#define SQUID_TCP_SO_RCVBUF 16384

/* TCP send buffer size */
#define SQUID_TCP_SO_SNDBUF 16384

/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at runtime.
	STACK_DIRECTION > 0 => grows toward higher addresses
	STACK_DIRECTION < 0 => grows toward lower addresses
	STACK_DIRECTION = 0 => direction of growth unknown */
/* #undef STACK_DIRECTION */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if your <sys/time.h> declares `struct tm'. */
/* #undef TM_IN_SYS_TIME */

/* Define this to include code which lets you specify access control elements
   based on ethernet hardware addresses. This code uses functions found in 4.4
   BSD derviations (e.g. FreeBSD, ?). */
#define USE_ARP_ACL 1

/* Use Cache Digests for locating objects in neighbor caches. This code is
   still semi-experimental. */
#define USE_CACHE_DIGESTS 1

/* Cache Array Routing Protocol */
#define USE_CARP 1

/* Use dnsserver processes instead of the internal DNS protocol support */
/* #undef USE_DNSSERVERS */

/* Use epoll() for the IO loop */
/* #undef USE_EPOLL */

/* Define if we should use GNU regex */
#define USE_GNUREGEX 1

/* Define this to include code for the Hypertext Cache Protocol (HTCP) */
#define USE_HTCP 1

/* If you want to use Squid's ICMP features (highly recommended!) then define
   this. When USE_ICMP is defined, Squid will send ICMP pings to origin server
   sites. This information is used in numerous ways: - Sent in ICP replies so
   neighbor caches know how close you are to the source. - For finding the
   closest instance of a URN. - With the 'test_reachability' option. Squid
   will return ICP_OP_MISS_NOFETCH for sites which it cannot ping. */
/* #undef USE_ICMP */

/* Compile in support for Ident (RFC 931) lookups? Enabled by default. */
#define USE_IDENT 1

/* Use kqueue() for the IO loop */
/* #undef USE_KQUEUE */

/* Enable code for assisting in finding memory leaks. Hacker stuff only. */
/* #undef USE_LEAKFINDER */

/* Define this to make use of the OpenSSL libraries for MD5 calculation rather
   than Squid's own MD5 implementation or if building with SSL encryption
   (USE_SSL) */
/* #undef USE_OPENSSL */

/* Use poll() for the IO loop */
/* #undef USE_POLL */

/* If you want to log Referer request header values, define this. By default,
   they are written to referer.log in the Squid log directory. */
#define USE_REFERER_LOG 1

/* Use select() for the IO loop */
/* #undef USE_SELECT */

/* Use Winsock select() for the IO loop */
#define USE_SELECT_WIN32 1

/* Compile the ESI processor and Surrogate header support */
#define USE_SQUID_ESI 0

/* Define this to include code for SSL encryption. */
/* #undef USE_SSL */

/* Define this if unlinkd is required (strongly recommended for ufs storage
   type) */
#define USE_UNLINKD 1

/* If you want to log User-Agent request header values, define this. By
   default, they are written to useragent.log in the Squid log directory. */
#define USE_USERAGENT_LOG 1

/* Define to enable WCCP */
/* #undef USE_WCCP */

/* Define to enable WCCP V2 */
/* #undef USE_WCCPv2 */

/* Define Windows NT & Windows 2000 run service mode */
#define USE_WIN32_SERVICE 1

/* Define to enable CPU profiling within Squid */
/* #undef USE_XPROF_STATS */

/* Valgrind memory debugger support */
/* #undef WITH_VALGRIND */

/* Define to 1 if your processor stores words with the most significant byte
   first (like Motorola and SPARC, unlike Intel and VAX). */
/* #undef WORDS_BIGENDIAN */

/* Define to have malloc statistics */
/* #undef XMALLOC_STATISTICS */

/* Enable support for the X-Accelerator-Vary HTTP header */
/* #undef X_ACCELERATOR_VARY */

/* Keyword used by squid for inlining methods */
#define _SQUID_INLINE_ inline

/* Include inline methods into header file */
#define _USE_INLINE_ 

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

#if (USE_SQUID_ESI == 1)
#define STR_SQUID_ESI "--enable-esi "
#else
#define STR_SQUID_ESI ""
#endif
#if DELAY_POOLS
#define STR_DELAY_POOLS "--enable-delay-pools "
#else
#define STR_DELAY_POOLS ""
#endif
#if USE_ICMP
#define STR_USE_ICMP "--enable-icmp "
#else
#define STR_USE_ICMP ""
#endif
#if USE_DNSSERVERS
#define STR_USE_DNSSERVERS "--disable-internal-dns "
#else
#define STR_USE_DNSSERVERS ""
#endif
#if USE_SSL
#define STR_USE_SSL "--enable-ssl "
#else
#define STR_USE_SSL ""
#endif
#if USE_ARP_ACL
#define STR_USE_ARP_ACL "--enable-arp-acl "
#else
#define STR_USE_ARP_ACL ""
#endif
#if USE_XPROF_STATS
#define STR_USE_XPROF_STATS "--enable-cpu-profiling "
#else
#define STR_USE_XPROF_STATS ""
#endif

#define SQUID_CONFIGURE_OPTIONS "--enable-win32-service --enable-storeio='ufs aufs null coss' --enable-disk-io='Blocking AIO DiskThreads' " \
    "--enable-removal-policies='heap lru' --enable-snmp --enable-htcp --disable-wccp --disable-wccpv2 --enable-useragent-log " \
    "--enable-referer-log --enable-cache-digests --enable-icap-client --enable-forw-via-db " \
    "--with-large-files --enable-default-hostsfile=none --enable-auth=basic ntlm digest negotiate " \
    STR_DELAY_POOLS \
    STR_USE_ICMP \
    STR_USE_DNSSERVERS \
    STR_USE_SSL \
    STR_SQUID_ESI \
    STR_USE_ARP_ACL \
    STR_USE_XPROF_STATS \
    "--prefix=c:/squid"

