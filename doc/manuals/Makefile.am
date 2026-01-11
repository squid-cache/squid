## Copyright (C) 1996-2026 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

##
## None of the .po or .pot are distributed for builds at this stage.
##

include $(srcdir)/language.am

EXTRA_DIST = \
	language.am \
	manuals.conf

DISTCLEANFILES= manuals.conf

manuals.conf: Makefile
	( \
	  echo "[po4a_langs] $(LANGUAGE_FILES)" | sed -e 's%[.]lang%%g'; \
	  echo -n "[options] --no-translations -o groff_code=verbatim "; \
	  echo " --package-name=$(PACKAGE) --package-version=$(VERSION) "; \
	  echo "[po4a_paths] doc/manuals/manuals.pot \$$lang:doc/manuals/\$$lang.po"; \
	  for fname in `cd $(top_srcdir) ; git ls-files *.8 *.8.in`; do \
	    manp=`basename $${fname}`; \
	    echo "[type: man] $${fname} \$$lang:doc/manuals/\$$lang/$${manp}"; \
	  done \
	) >$@
