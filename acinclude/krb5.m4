dnl 
dnl AUTHOR: Squid Web Cache team
dnl
dnl SQUID Web Proxy Cache          http://www.squid-cache.org/
dnl ----------------------------------------------------------
dnl Squid is the result of efforts by numerous individuals from
dnl the Internet community; see the CONTRIBUTORS file for full
dnl details.   Many organizations have provided support for Squid's
dnl development; see the SPONSORS file for full details.  Squid is
dnl Copyrighted (C) 2001 by the Regents of the University of
dnl California; see the COPYRIGHT file for full details.  Squid
dnl incorporates software developed and/or copyrighted by other
dnl sources; see the CREDITS file for full details.
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.

dnl these checks must be performed in the same order as here defined,
dnl and have mostly been lifted out of an inlined configure.ac.

dnl checks for a broken solaris header file, and sets squid_cv_broken_krb5_h
dnl to yes if that's the case
AC_DEFUN([SQUID_CHECK_KRB5_SOLARIS_BROKEN_KRB5_H], [
  AC_CACHE_CHECK([for broken Solaris krb5.h],squid_cv_broken_krb5_h, [
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <krb5.h>
int i;
]])], [ squid_cv_broken_krb5_h=no ], [ 
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if defined(__cplusplus)
#define KRB5INT_BEGIN_DECLS     extern "C" {
#define KRB5INT_END_DECLS
KRB5INT_BEGIN_DECLS
#endif
#include <krb5.h>
int i;
]])], [ squid_cv_broken_krb5_h=yes ], [ squid_cv_broken_krb5_h=no ])
    ])
  ])
]) dnl SQUID_CHECK_KRB5_SOLARIS_BROKEN_KRB5_H


AC_DEFUN([SQUID_CHECK_KRB5_HEIMDAL_BROKEN_KRB5_H], [
  AC_CACHE_CHECK([for broken Heimdal krb5.h],squid_cv_broken_heimdal_krb5_h, [
    AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <krb5.h>
int
main(void)
{
        krb5_context context;

        krb5_init_context(&context);

        return 0;
}
]])], [ squid_cv_broken_heimdal_krb5_h=no ], [
    AC_RUN_IFELSE([AC_LANG_SOURCE([[
#if defined(__cplusplus)
extern "C" {
#endif
#include <krb5.h>
#if defined(__cplusplus)
}
#endif
int
main(void)
{
        krb5_context context;

        krb5_init_context(&context);

        return 0;
}
]])], [ squid_cv_broken_heimdal_krb5_h=yes ], [ squid_cv_broken_heimdal_krb5_h=no ])
    ])
  ])
]) dnl SQUID_CHECK_KRB5_HEIMDAL_BROKEN_KRB5_H

dnl check the max skew in the krb5 context, and sets squid_cv_max_skew_context
AC_DEFUN([SQUID_CHECK_MAX_SKEW_IN_KRB5_CONTEXT],[
  AC_CACHE_CHECK([for max_skew in struct krb5_context],
                  squid_cv_max_skew_context, [
    AC_COMPILE_IFELSE([
      AC_LANG_PROGRAM([[
#if HAVE_BROKEN_SOLARIS_KRB5_H
#if defined(__cplusplus)
#define KRB5INT_BEGIN_DECLS     extern "C" {
#define KRB5INT_END_DECLS
KRB5INT_BEGIN_DECLS
#endif
#endif
#include <krb5.h>
krb5_context kc; kc->max_skew = 1;
      ]])
    ],[ squid_cv_max_skew_context=yes ],
    [ squid_cv_max_skew_context=no ])
  ])
])

dnl check whether the kerberos context has a memory cache. Sets
dnl squid_cv_memory_cache if that's the case.
AC_DEFUN([SQUID_CHECK_KRB5_CONTEXT_MEMORY_CACHE],[
  AC_CACHE_CHECK([for memory cache], squid_cv_memory_cache, [
    AC_RUN_IFELSE([
      AC_LANG_SOURCE([[
#if HAVE_BROKEN_SOLARIS_KRB5_H
#if defined(__cplusplus)
#define KRB5INT_BEGIN_DECLS     extern "C" {
#define KRB5INT_END_DECLS
KRB5INT_BEGIN_DECLS
#endif
#endif
#include <krb5.h>
int main(int argc, char *argv[])
{
    krb5_context context;
    krb5_ccache cc;

    krb5_init_context(&context);
    return krb5_cc_resolve(context, "MEMORY:test_cache", &cc);
}
      ]])
    ], [ squid_cv_memory_cache=yes ], [ squid_cv_memory_cache=no ], [:])
  ])
])


dnl checks that gssapi is ok, and sets squid_cv_working_gssapi accordingly
AC_DEFUN([SQUID_CHECK_WORKING_GSSAPI], [
  AC_CACHE_CHECK([for working gssapi], squid_cv_working_gssapi, [
    AC_RUN_IFELSE([AC_LANG_SOURCE([[
#ifdef HAVE_HEIMDAL_KERBEROS
#ifdef HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#elif defined(HAVE_GSSAPI_H)
#include <gssapi.h>
#endif
#else
#ifdef HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#elif defined(HAVE_GSSAPI_H)
#include <gssapi.h>
#endif
#ifdef HAVE_GSSAPI_GSSAPI_KRB5_H
#include <gssapi/gssapi_krb5.h>
#endif
#ifdef HAVE_GSSAPI_GSSAPI_GENERIC_H
#include <gssapi/gssapi_generic.h>
#endif
#endif
int
main(void)
{
        OM_uint32 val;
        gss_OID_set set;

        gss_create_empty_oid_set(&val, &set);

        return 0;
}
  ]])],  [ squid_cv_working_gssapi=yes ], [ squid_cv_working_gssapi=no ], [:])])
])


dnl check for a working spnego, and set squid_cv_have_spnego
AC_DEFUN([SQUID_CHECK_SPNEGO_SUPPORT], [
  AC_CACHE_CHECK([for spnego support], squid_cv_have_spnego, [
    AC_RUN_IFELSE([AC_LANG_SOURCE([[
#ifdef HAVE_HEIMDAL_KERBEROS
#ifdef HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#elif defined(HAVE_GSSAPI_H)
#include <gssapi.h>
#endif
#else
#ifdef HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#elif defined(HAVE_GSSAPI_H)
#include <gssapi.h>
#endif
#ifdef HAVE_GSSAPI_GSSAPI_KRB5_H
#include <gssapi/gssapi_krb5.h>
#endif
#ifdef HAVE_GSSAPI_GSSAPI_GENERIC_H
#include <gssapi/gssapi_generic.h>
#endif
#endif
#include <string.h>
int main(int argc, char *argv[]) {
 OM_uint32 major_status,minor_status;
 gss_OID_set gss_mech_set;
 int i;

static gss_OID_desc _gss_mech_spnego  = {6, (void *)"\x2b\x06\x01\x05\x05\x02"};
gss_OID gss_mech_spnego = &_gss_mech_spnego;

 major_status = gss_indicate_mechs( &minor_status, &gss_mech_set);

 for (i=0;i<gss_mech_set->count;i++) {
     if (!memcmp(gss_mech_set->elements[i].elements,gss_mech_spnego->elements,gss_mech_set->elements[i].length)) {
        return 0;
     }
 }

 return 1;
}
  ]])],  
  [ squid_cv_have_spnego=yes ], [ squid_cv_have_spnego=no ],[:])])
])

dnl checks that krb5 is functional. Sets squid_cv_working_krb5
AC_DEFUN([SQUID_CHECK_WORKING_KRB5],[
  AC_CACHE_CHECK([for working krb5], squid_cv_working_krb5, [
    AC_RUN_IFELSE([AC_LANG_SOURCE([[
#ifdef HAVE_KRB5_H
#if HAVE_BROKEN_SOLARIS_KRB5_H
#if defined(__cplusplus)
#define KRB5INT_BEGIN_DECLS     extern "C" {
#define KRB5INT_END_DECLS
KRB5INT_BEGIN_DECLS
#endif
#endif
#if HAVE_BROKEN_HEIMDAL_KRB5_H
extern "C" {
#include <krb5.h>
}
#else
#include <krb5.h>
#endif
#endif

int
main(void)
{
        krb5_context context;

        krb5_init_context(&context);

        return 0;
}
  ]])], [ squid_cv_working_krb5=yes ], [ squid_cv_working_krb5=no ],[:])])
])
