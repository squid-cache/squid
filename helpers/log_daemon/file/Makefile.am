include $(top_srcdir)/src/Common.am

libexec_PROGRAMS = log_file_daemon
log_file_daemon_SOURCES = log_file_daemon.cc
log_file_daemon_LDADD = \
	-L$(top_builddir)/lib $(COMPAT_LIB) \
	$(XTRA_LIBS)
EXTRA_DIST = required.m4
