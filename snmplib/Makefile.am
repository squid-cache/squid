## Process this file with automake to produce Makefile.in
##
## Makefile for libsnmp.
## 
noinst_LIBRARIES = libsnmp.a
libsnmp_a_SOURCES  = asn1.c parse.c snmp_vars.c \
	coexistance.c snmp_api.c snmp_error.c  \
	mib.c snmp_api_error.c   \
	snmp_msg.c \
	snmp_pdu.c  snmplib_debug.c
INCLUDES	= -I$(top_builddir)/include -I$(top_srcdir)/include

VERSION		= 3.4
DEFS		= -DSQUID_SNMP=1
