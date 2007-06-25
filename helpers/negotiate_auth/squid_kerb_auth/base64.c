/*
 * Markus Moeller has modified the following code from Squid
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "base64.h"


static void base64_init(void);

static int base64_initialized = 0;
#define BASE64_VALUE_SZ 256
int base64_value[BASE64_VALUE_SZ];
const char base64_code[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


static void
base64_init(void)
{
    int i;

    for (i = 0; i < BASE64_VALUE_SZ; i++)
	base64_value[i] = -1;

    for (i = 0; i < 64; i++)
	base64_value[(int) base64_code[i]] = i;
    base64_value['='] = 0;

    base64_initialized = 1;
}

void base64_decode(char* result, const char *data, int result_size)
{
    int j;
    int c;
    long val;
    if (!data)
	return;
    if (!base64_initialized)
	base64_init();
    val = c = 0;
    
    for (j = 0; *data ;data++) {
	unsigned int k = ((unsigned char) *data) % BASE64_VALUE_SZ;
	if (base64_value[k] < 0)
	    continue;
	val <<= 6;
	val += base64_value[k];
	if (++c < 4)
	    continue;
	/* One quantum of four encoding characters/24 bit */
        if (j >= result_size)
          break;
	result[j++] = val >> 16;	/* High 8 bits */
        if (j >= result_size)
          break;
	result[j++] = (val >> 8) & 0xff;	/* Mid 8 bits */
        if (j >= result_size)
          break;
	result[j++] = val & 0xff;	/* Low 8 bits */
	val = c = 0;
    }
    return;
}

/* adopted from http://ftp.sunet.se/pub2/gnu/vm/base64-encode.c with adjustments */
void base64_encode(char* result, const char *data, int result_size, int data_size)
{
    int bits = 0;
    int char_count = 0;
    int out_cnt = 0;

    if (!data)
	return;

    if (!base64_initialized)
	base64_init();

    while (data_size--) {
        int c = (unsigned char) *data++;
	bits += c;
	char_count++;
	if (char_count == 3) {
            if (out_cnt >= result_size)
              break;
	    result[out_cnt++] = base64_code[bits >> 18];
            if (out_cnt >= result_size)
              break;
	    result[out_cnt++] = base64_code[(bits >> 12) & 0x3f];
            if (out_cnt >= result_size)
              break;
	    result[out_cnt++] = base64_code[(bits >> 6) & 0x3f];
            if (out_cnt >= result_size)
              break;
	    result[out_cnt++] = base64_code[bits & 0x3f];
	    bits = 0;
	    char_count = 0;
	} else {
	    bits <<= 8;
	}
    }
    if (char_count != 0) {
	bits <<= 16 - (8 * char_count);
        if (out_cnt >= result_size)
          goto end;
	result[out_cnt++] = base64_code[bits >> 18];
        if (out_cnt >= result_size)
          goto end;
	result[out_cnt++] = base64_code[(bits >> 12) & 0x3f];
	if (char_count == 1) {
            if (out_cnt >= result_size)
              goto end;
	    result[out_cnt++] = '=';
            if (out_cnt >= result_size)
              goto end;
	    result[out_cnt++] = '=';
	} else {
            if (out_cnt >= result_size)
              goto end;
	    result[out_cnt++] = base64_code[(bits >> 6) & 0x3f];
            if (out_cnt >= result_size)
              goto end;
	    result[out_cnt++] = '=';
	}
    }
end:
    if (out_cnt >= result_size) {
       result[result_size-1] = '\0';	/* terminate */
    } else {
       result[out_cnt] = '\0';	/* terminate */
    }
    return;
}

int base64_encode_len(int len)
{
  return ((len+2)/3*4)+1;
}

int base64_decode_len(const char *data)
{
  int i,j;

  j=0;
  for (i=strlen(data)-1;i>=0;i--) {
   if (data[i] == '=') j++;
   if (data[i] != '=') break;
  }
  return strlen(data)/4*3-j;
}
