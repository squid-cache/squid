#ifndef _SQUID_CHARSET_H
#define _SQUID_CHARSET_H

#ifdef __cplusplus
extern "C"
#else
extern
#endif

char *latin1_to_utf8(char *out, size_t size, const char *in);

#endif /* _SQUID_CHARSET_H */
