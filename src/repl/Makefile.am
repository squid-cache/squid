#  Makefile for storage modules in the Squid Object Cache server
#
#  $Id: Makefile.am,v 1.1 2001/08/31 11:19:35 robertc Exp $
#

AUTOMAKE_OPTIONS = subdir-objects

DIST_SUBDIRS = lru heap
SUBDIRS		= 
# No recursion is needed for the subdirs, we build from here. // @REPL_POLICIES@
OUTLIBS		= @REPL_LIBS@

EXTRA_LIBRARIES = liblru.a libheap.a
noinst_LIBRARIES = @REPL_LIBS@

liblru_a_SOURCES = lru/store_repl_lru.c
libheap_a_SOURCES = heap/store_heap_replacement.c heap/store_repl_heap.c

INCLUDES      = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
	-I$(top_srcdir)/src/

##all:
##	@test -z "$(SUBDIRS)" || for dir in $(SUBDIRS); do \
##	   sh -c "cd $$dir && $(MAKE) $(MFLAGS) all" || exit 1; \
##	done; \
##	if [ ! -f stamp ]; then \
##	   touch stamp; \
##	fi

##$(OUTLIBS):
##	@sh -c "cd `basename $@ .a` && $(MAKE) $(MFLAGS) ../$@"

##clean:
##	-rm -f *.a stamp
##	-for dir in *; do \
##	    if [ -f $$dir/Makefile ]; then \
##	       sh -c "cd $$dir && $(MAKE) $(MFLAGS) $@" || exit 1;\
##	    fi; \
##	done

##distclean:
##	-rm -f *.a Makefile
##	-for dir in *; do \
##	    if [ -f $$dir/Makefile ]; then \
##		sh -c "cd $$dir && $(MAKE) $(MFLAGS) distclean"; \
##	    fi; \
##	done

##.DEFAULT:
##	@test -z "$(SUBDIRS)" || for dir in $(SUBDIRS); do \
##	   sh -c "cd $$dir && $(MAKE) $(MFLAGS) $@" || exit 1; \
##	done
