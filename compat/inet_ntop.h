#ifndef _INC_INET_NTOP_H
#define _INC_INET_NTOP_H

/* Use the system provided version where possible */
#if !HAVE_INET_NTOP

/* char *
* inet_ntop(af, src, dst, size)
*      convert a network format address to presentation format.
* return:
*      pointer to presentation format address (`dst'), or NULL (see errno).
* author:
*      Paul Vixie, 1996.
*/
SQUIDCEXTERN const char * xinet_ntop(int af, const void *src, char *dst, size_t size);
#define inet_ntop xinet_ntop

#endif
#endif /* _INC_INET_NTOP_H */
