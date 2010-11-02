#ifndef _SQUID_BASE64_H
#define _SQUID_BASE64_H

#ifdef __cplusplus
extern "C" {
#endif

    extern char *base64_decode(const char *coded);
    extern const char *base64_encode(const char *decoded);
    extern const char *base64_encode_bin(const char *data, int len);

#ifdef __cplusplus
}
#endif
#endif /* _SQUID_BASE64_H */
