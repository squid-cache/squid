## Copyright (C) 1996-2016 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/icons/icon.list

icondir = $(datadir)/icons/silk
icon_DATA = $(ICONS)
EXTRA_DIST = $(ICONS) icon.list SN.png
DISTCLEANFILES = 

install-data-local: SN.png install-iconDATA
	$(INSTALL_DATA) $(srcdir)/SN.png "$(DESTDIR)$(datadir)/icons/"

uninstall-local:
	$(RM) $(DESTDIR)$(datadir)/icons/SN.png
