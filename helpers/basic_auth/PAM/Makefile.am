#
#  Makefile for the Squid PAM authentication helper
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

man_MANS		= pam_auth.8
EXTRA_DIST		= pam_auth.8
libexec_PROGRAMS	= pam_auth

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/include

LDADD = \
	-L$(top_builddir)/libsquid-compat/libsquid-compat.la \
	-L$(top_builddir)/lib -lmiscutil \
	-lpam \
	$(XTRA_LIBS)
