## Process this file with automake to produce Makefile.in
#
# $Id$
#

errordir = $(datadir)/errors

##dist-hook eveything

DEFAULT_ERROR_DIR	= $(errordir)
DEFAULT_STYLESHEET	= $(sysconfdir)/errorpage.css

## List of automated translations possible:
ERROR_TEMPLATES =  \
	templates/ERR_FTP_PUT_MODIFIED \
	templates/ERR_ESI \
	templates/ERR_SECURE_CONNECT_FAIL \
	templates/ERR_ZERO_SIZE_OBJECT \
	templates/ERR_SHUTTING_DOWN \
	templates/ERR_URN_RESOLVE \
	templates/ERR_CONNECT_FAIL \
	templates/ERR_SOCKET_FAILURE \
	templates/ERR_FTP_NOT_FOUND \
	templates/ERR_FTP_UNAVAILABLE \
	templates/ERR_LIFETIME_EXP \
	templates/ERR_READ_ERROR \
	templates/ERR_ONLY_IF_CACHED_MISS \
	templates/ERR_UNSUP_HTTPVERSION \
	templates/ERR_READ_TIMEOUT \
	templates/ERR_ICAP_FAILURE \
	templates/ERR_DIR_LISTING \
	templates/ERR_FTP_FORBIDDEN \
	templates/ERR_ACCESS_DENIED \
	templates/ERR_FORWARDING_DENIED \
	templates/ERR_CANNOT_FORWARD \
	templates/ERR_CACHE_MGR_ACCESS_DENIED \
	templates/ERR_INVALID_REQ \
	templates/ERR_CACHE_ACCESS_DENIED \
	templates/ERR_FTP_PUT_ERROR \
	templates/ERR_FTP_PUT_CREATED \
	templates/ERR_TOO_BIG \
	templates/ERR_UNSUP_REQ \
	templates/ERR_FTP_FAILURE \
	templates/ERR_DNS_FAIL \
	templates/ERR_FTP_DISABLED \
	templates/ERR_NO_RELAY \
	templates/ERR_INVALID_URL \
	templates/ERR_INVALID_RESP \
	templates/ERR_WRITE_ERROR

TRANSLATE_LANGUAGES = \
	af.lang \
	ar.lang \
	az.lang \
	bg.lang \
	ca.lang \
	cs.lang \
	da.lang \
	de.lang \
	el.lang \
	en.lang \
	es.lang \
	et.lang \
	fa.lang \
	fi.lang \
	fr.lang \
	he.lang \
	hu.lang \
	hy.lang \
	id.lang \
	it.lang \
	ja.lang \
	ko.lang \
	lt.lang \
	lv.lang \
	ms.lang \
	nl.lang \
	pl.lang \
	pt-br.lang \
	pt.lang \
	ro.lang \
	ru.lang \
	sk.lang \
	sr.lang \
	sv.lang \
	th.lang \
	tr.lang \
	uk.lang \
	uz.lang \
	zh-cn.lang \
	zh-tw.lang

CLEANFILES = $(TRANSLATE_LANGUAGES) translate-warn
EXTRA_DIST = \
	$(ERROR_TEMPLATES) \
	aliases alias-link.sh alias-upgrade errorpage.css TRANSLATORS COPYRIGHT

all: all-am

translate: translate-warn $(TRANSLATE_LANGUAGES)

translate-warn:
	case "$(PO2HTML)" in \
	off) \
	    echo "WARNING: Translation is disabled."; \
	    ;; \
	""|no) \
	    echo "WARNING: Translation toolkit was not detected."; \
	    ;; \
	esac; \
	touch translate-warn

$(TRANSLATE_LANGUAGES): $(ERROR_TEMPLATES)

NOTIDY=`$(PO2HTML) --help | grep -o "\-\-notidy"`

.po.lang:
	if test "$(PO2HTML)" != "" && test "$(PO2HTML)" != "no" && test "$(PO2HTML)" != "off" && test -f $(top_srcdir)/errors/en.po; then \
	    lang=`basename $@ .lang`; \
	    mkdir -p $(top_builddir)/errors/$$lang; \
	    echo -n "Translate '$$lang' ..."; \
	    for f in $(ERROR_TEMPLATES); do \
			page=`basename $$f`; \
			$(PO2HTML) $(NOTIDY) --progress=none -i $(top_srcdir)/errors/$$lang.po -t $(top_srcdir)/errors/$$f >$(top_builddir)/errors/$$lang/$$page || exit 1; \
		done; \
		echo "done."; \
	fi; \
	touch $@

install-exec-local: translate
	if test -f $(DESTDIR)$(DEFAULT_STYLESHEET) ; then \
		echo "$@ will not overwrite existing $(DESTDIR)$(DEFAULT_STYLESHEET)" ; \
	else \
		$(mkinstalldirs) $(DESTDIR)`dirname $(DEFAULT_STYLESHEET)` ; \
		echo "$(INSTALL_DATA) $(srcdir)/errorpage.css $(DESTDIR)$(DEFAULT_STYLESHEET)"; \
		$(INSTALL_DATA) $(srcdir)/errorpage.css $(DESTDIR)$(DEFAULT_STYLESHEET); \
	fi

install-data-local: translate
	$(mkinstalldirs) $(DESTDIR)$(DEFAULT_ERROR_DIR) ; \
	for l in $(TRANSLATE_LANGUAGES) templates; do \
	    l=`basename $$l .lang`; \
	    echo "Located $$l for install..."; \
	    if test -d $(srcdir)/$$l || test -d $(builddir)/$$l; then \
		$(mkinstalldirs) $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l; \
	    fi; \
	    for f in $(ERROR_TEMPLATES); do \
		page=`basename $$f`; \
		if test -f $(builddir)/$$l/$$page; then \
		    echo "$(INSTALL_DATA) $(builddir)/$$l/$$page $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l"; \
			    $(INSTALL_DATA) $(builddir)/$$l/$$page $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l; \
		elif test -f $(srcdir)/$$l/$$page; then \
		    echo "$(INSTALL_DATA) $(srcdir)/$$l/$$page $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l"; \
			    $(INSTALL_DATA) $(srcdir)/$$l/$$page $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l; \
		fi; \
	    done; \
	done; \
	$(INSTALL_DATA) $(srcdir)/TRANSLATORS $(DESTDIR)$(DEFAULT_ERROR_DIR)/TRANSLATORS; \
	$(INSTALL_DATA) $(srcdir)/COPYRIGHT $(DESTDIR)$(DEFAULT_ERROR_DIR)/COPYRIGHT; \
	$(INSTALL_DATA) $(srcdir)/errorpage.css $(DESTDIR)$(DEFAULT_STYLESHEET).default; \
	$(SHELL) $(srcdir)/alias-link.sh "$(LN)" "$(RM)" "$(DESTDIR)$(DEFAULT_ERROR_DIR)" "$(srcdir)/aliases" || exit 1 ;

uninstall-local:
	for l in $(TRANSLATE_LANGUAGES) templates; do \
	  l=`basename $$l .lang`; \
	  echo "Located $$l for uninstall ..."; \
	  if test -d $(srcdir)/$$l; then \
		for f in $(srcdir)/$$l/ERR_*; do \
			if test -f $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l/`basename $$f`; then \
		        	$(RM) $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l/`basename $$f`; \
			fi; \
		done; \
	  fi ; \
	  if test -d $(builddir)/$$l; then \
		for f in $(builddir)/$$l/ERR_*; do \
			if test -f $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l/`basename $$f`; then \
		        	$(RM) $(DESTDIR)$(DEFAULT_ERROR_DIR)/$$l/`basename $$f`; \
			fi; \
		done; \
	  fi \
	done;
	@$(SHELL) $(top_srcdir)/scripts/remove-cfg.sh "$(RM)" $(DESTDIR)$(DEFAULT_STYLESHEET)
	rm -f $(DESTDIR)$(DEFAULT_STYLESHEET).default
	rm -f $(DESTDIR)$(DEFAULT_ERROR_DIR)/TRANSLATORS
	rm -f $(DESTDIR)$(DEFAULT_ERROR_DIR)/COPYRIGHT

## Upgrade requires the new files to be pre-installed
upgrade: install
	$(SHELL) $(srcdir)/alias-link.sh "$(LN)" "$(RM)" "$(DESTDIR)$(DEFAULT_ERROR_DIR)" "$(srcdir)/alias-upgrade" || exit 1 ;

# undocumented hack.  You can use this target to create multi-lingual
# error pages.  For example:
#
#	make ADDLANG=English DESTLANG=French addlang
#
# by Andres Kroonmaa <andre@mail.lbi.ee>
#
# UPDATE: this hack completely breaks HTML standards and with the addition
#	  of language translations is now largely obsolete.
#	  It will be removed without notice at some future date.
#
addlang: all
	-@if test -d $(srcdir)/$(ADDLANG); then \
	if test -d $(DEFAULT_ERROR_DIR)/$(DESTLANG); then \
	cd $(srcdir)/$(ADDLANG)/ ; \
	for f in ERR_*; do \
		if test -f $(DEFAULT_ERROR_DIR)/$(DESTLANG)/$$f ; then \
			echo "appending $(ADDLANG)/$$f"; \
			echo "<HR>" >> $(DEFAULT_ERROR_DIR)/$(DESTLANG)/$$f ; \
			cat $$f >> $(DEFAULT_ERROR_DIR)/$(DESTLANG)/$$f; \
		fi; \
	done; \
	fi \
	fi

dist-hook: translate
	for lang in $(TRANSLATE_LANGUAGES); do \
	  lang=`basename $$lang .lang`; \
	  if test -d $$lang ; then \
		mkdir -p $(distdir)/$$lang; \
		cp -p $(top_builddir)/errors/$$lang/ERR_*  $(distdir)/$$lang \
		  || exit 1; \
	  fi; \
	done

clean: clean-am
	if test "$(PO2HTML)" != "" && test "$(PO2HTML)" != "no" && test "$(PO2HTML)" != "off" && test -f $(top_srcdir)/errors/en.po; then \
	  for lang in $(TRANSLATE_LANGUAGES); do \
	    lang=`basename $$lang .lang`; \
	    rm -rf $$lang; \
	  done; \
	fi

all: translate
