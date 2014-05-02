EXTRA_DIST = defines.h

DIST_SUBDIRS = \
	basic_auth \
	digest_auth \
	external_acl \
	log_daemon \
	negotiate_auth \
	ntlm_auth \
	url_rewrite \
	ssl \
	storeid_rewrite

SUBDIRS = \
	basic_auth \
	digest_auth \
	external_acl \
	log_daemon \
	negotiate_auth \
	url_rewrite \
	storeid_rewrite

if ENABLE_AUTH_NTLM
SUBDIRS += ntlm_auth
endif

if ENABLE_SSL
SUBDIRS += ssl
endif

