## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

## Process this file with automake to produce Makefile.in
##
## Makefile for libsnmp.
## 
AM_CFLAGS = $(SQUID_CFLAGS)
AM_CXXFLAGS = $(SQUID_CXXFLAGS)
AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include

noinst_LTLIBRARIES = libsnmplib.la
libsnmplib_la_SOURCES = \
	asn1.c \
	coexistance.c \
	mib.c \
	parse.c \
	snmp_api.c \
	snmp_api_error.c \
	snmp_error.c \
	snmp_msg.c \
	snmp_pdu.c \
	snmp_vars.c \
	snmplib_debug.c

VERSION		= 3.4
DEFS		= -DSQUID_SNMP=1
