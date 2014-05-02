#ifndef _SQUID_RFC1123_H
#define _SQUID_RFC1123_H

#ifdef __cplusplus
extern "C" {
#endif

    extern const char *mkhttpdlogtime(const time_t *);
    extern const char *mkrfc1123(time_t);
    extern time_t parse_rfc1123(const char *str);

#ifdef __cplusplus
}
#endif
#endif /* _SQUID_RFC1123_H */
