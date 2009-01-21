#
#  Makefile for the Squid Object Cache server
#
#  $Id$
#
#  Uncomment and customize the following to suit your needs:
#

libexec_SCRIPTS	= squid_db_auth
CLEANFILES = squid_db_auth squid_db_auth.8
do_subst = sed -e 's,[@]PERL[@],$(PERL),g'
man_MANS 	= squid_db_auth.8
EXTRA_DIST	= passwd.sql \
		  squid_db_auth.in

squid_db_auth.8: squid_db_auth
	pod2man squid_db_auth squid_db_auth.8

squid_db_auth: squid_db_auth.in
	$(do_subst) < $(srcdir)/squid_db_auth.in  >squid_db_auth
