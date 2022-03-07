BUILDINFO := $(shell lsb_release -si 2>/dev/null)

CFLAGS="-g -O3 -pipe -m64 -fPIE -fstack-protector-strong -Wformat -Werror=format-security -Wall" LDFLAGS=" -fPIE -pie -Wl,-z,relro -W
l,-z,now" CPPFLAGS="-D_FORTIFY_SOURCE=2" CXXFLAGS="-g -O3 -pipe -m64 -fPIE -fstack-protector-strong -Wformat -Werror=format-security"
 \
./configure \
    --with-build-environment=default \ 
    --enable-build-info="$(BUILDINFO) $(DEB_HOST_ARCH_OS)" \
		--datadir=/usr/share/squid \
		--sysconfdir=/etc/squid \
		--libexecdir=/usr/lib/squid \
		--mandir=/usr/share/man \
		--enable-inline \
		--disable-arch-native \
		--enable-async-io-8 \
		--enable-storeio="ufs,aufs,null" \
		--enable-removal-policies="lru,heap" \
		--enable-delay-pools \
		--enable-cache-digests \
		--enable-icap-client \
		--enable-follow-x-forwarded-for \
		--enable-auth-basic="fake,getpwam,SASL" \
		--enable-auth-digest="file" \
		--enable-auth-negotiate="kerberos,wrapper" \
		--enable-auth-ntlm="fake" \
		--enable-external-acl-helpers="file_userip,session,unix_group,delayer" \
		--enable-security-cert-validators="fake" \
		--enable-storeid-rewrite-helpers="file" \
		--enable-url-rewrite-helpers="fake" \
		--enable-linux-netfilter \
		--enable-epoll \
		--enable-eui \
		--enable-esi \
		--enable-icmp \
		--enable-underscores \
		--enable-zph-qos \
		--enable-ecap \
		--with-openssl \
		--enable-ssl-crtd \
		--disable-maintainer-mode \
		--disable-dependency-tracking \
		--disable-translation \
		--with-filedescriptors=65536 \
		--with-large-files \
		--with-systemd \
		--with-default-user=proxy \
		--disable-translation \
		--disable-arch-native \
		--disable-devpoll \
		--disable-kqueue \
		--disable-wccp \
		--disable-wccp2 \
		--disable-icap-client \
		--with-gnutls

 make
