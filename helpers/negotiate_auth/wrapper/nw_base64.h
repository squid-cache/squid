#ifndef _NW_BASE64_H
#define _NW_BASE64_H

/*
 * Markus Moeller has modified the following code from Squid
 */

void nw_base64_decode(char *result, const char *data, int result_size);
int nw_base64_decode_len(const char *data);

#endif
