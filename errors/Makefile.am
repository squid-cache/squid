## Process this file with automake to produce Makefile.in
#
# $Id: Makefile.am,v 1.1 2001/08/31 11:19:08 robertc Exp $
#

errordir = $(sysconfdir)/errors


##dist-hook eveything

DEFAULT_ERROR_DIR	= $(errordir)

LANGUAGE	= @ERR_LANGUAGE@
LANGUAGES	= Bulgarian Czech Danish Dutch English Estonian Finnish French \
		  German Hungarian Italian Japanese Korean Polish Portuguese \
		  Romanian Russian-1251 Russian-koi8-r Serbian Simplify_Chinese \
		  Slovak Spanish Swedish Traditional_Chinese Turkish


install-data-local: 
	-@$(mkinstalldirs) $(DESTDIR)$(DEFAULT_ERROR_DIR)
	@for f in $(srcdir)/$(LANGUAGE)/ERR_*; do \
		if test -f $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$f ; then \
			:; \
		else \
			echo "$(INSTALL_DATA) $$f $(DESTDIR)$(DEFAULT_ERROR_DIR)"; \
			$(INSTALL_DATA) $$f $(DESTDIR)$(DEFAULT_ERROR_DIR); \
		fi; \
	done

uninstall-local:
	@for f in $(srcdir)/$(LANGUAGE)/ERR_*; do \
	        if test -f $(DESTDIR)$(DEFAULT_ERROR_DIR)/`echo $$f | echo "$$f" | sed -e "s/.*\///;"` ; then \
	                rm -f $(DESTDIR)$(DEFAULT_ERROR_DIR)/`echo $$f | echo "$$f" | sed -e "s/.*\///;"`; \
	        fi; \
	done

# undocumented hack.  You can use this target to create multi-lingual
# error pages.  For example:
#
#	make ADDLANG=English addlang
#
# by Andres Kroonmaa <andre@mail.lbi.ee>
#
addlang: all
	-@if test -d $(srcdir)/$(ADDLANG); then \
	cd $(srcdir)/$(ADDLANG)/ ; \
	for f in ERR_*; do \
		if test -f $(DEFAULT_ERROR_DIR)/$$f ; then \
			echo "appending $(ADDLANG)/$$f"; \
			echo "<HR>" >> $(DEFAULT_ERROR_DIR)/$$f ; \
			cat $$f >> $(DEFAULT_ERROR_DIR)/$$f; \
		fi; \
	done; \
	fi

dist-hook:
	@ for lang in $(LANGUAGES); do \
	  if test "$$lang" = .; then :; else \
	    test -d $(distdir)/$$lang \
	    || mkdir $(distdir)/$$lang \
	    || exit 1; \
	    cp -p $(srcdir)/$$lang/ERR_*  $(distdir)/$$lang \
	      || exit 1; \
	  fi; \
	done		
