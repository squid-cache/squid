## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/icons/icon.am

icondir = $(datadir)/icons/silk
icon_DATA = $(ICONS)
EXTRA_DIST = \
	$(ICONS) \
	icon.am \
	SN.png
DISTCLEANFILES =

install-data-local: SN.png install-iconDATA
	$(INSTALL_DATA) $(srcdir)/SN.png "$(DESTDIR)$(datadir)/icons/"

uninstall-local:
	$(RM) $(DESTDIR)$(datadir)/icons/SN.png
