# Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##
#
s%[@]SERVICE_NAME[@]%${service_name}%g
s%_SQUID_WINDOWS_%MS Windows%g
s%FOLLOW_X_FORWARDED_FOR%--enable-follow-x-forwarded-for%g
s%FOLLOW_X_FORWARDED_FOR&&LINUX_NETFILTER%--enable-follow-x-forwarded-for and --enable-linux-netfilter%g
s%FOLLOW_X_FORWARDED_FOR&&USE_ADAPTATION%--enable-follow-x-forwarded-for and (--enable-icap-client and/or --enable-ecap)%g
s%FOLLOW_X_FORWARDED_FOR&&USE_DELAY_POOLS%--enable-follow-x-forwarded-for and --enable-delay-pools%g
s%HAVE_AUTH_MODULE_BASIC%--enable-auth-basic%g
s%HAVE_AUTH_MODULE_DIGEST%--enable-auth-digest%g
s%HAVE_LIBCAP&&SO_MARK%--with-cap and Packet MARK (Linux)%g
s%HAVE_LIBGNUTLS||USE_OPENSSL%--with-gnutls or --with-openssl%g
s%HAVE_MSTATS&&HAVE_GNUMALLOC_H%GNU Malloc with mstats()%g
s%ICAP_CLIENT%--enable-icap-client%g
s%SQUID_SNMP%--enable-snmp%g
s%USE_ADAPTATION%--enable-ecap or --enable-icap-client%g
s%USE_AUTH%--enable-auth%g
s%USE_CACHE_DIGESTS%--enable-cache-digests%g
s%USE_DELAY_POOLS%--enable-delay-pools%g
s%USE_ECAP%--enable-ecap%g
s%USE_ERR_LOCALES%--enable-auto-locale%g
s%USE_HTCP%--enable-htcp%g
s%USE_HTTP_VIOLATIONS%--enable-http-violations%g
s%USE_ICMP%--enable-icmp%g
s%USE_LOADABLE_MODULES%--enable-shared%g
s%USE_OPENSSL%--with-openssl%g
s%USE_QOS_TOS%--enable-zph-qos%g
s%USE_SQUID_EUI%--enable-eui%g
s%USE_SSL_CRTD%--enable-ssl-crtd%g
s%USE_UNLINKD%--enable-unlinkd%g
s%USE_WCCP%--enable-wccp%g
s%USE_WCCPv2%--enable-wccpv2%g
