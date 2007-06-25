/*
 *
 *	RADIUS
 *	Remote Authentication Dial In User Service
 *
 *
 *	Livingston Enterprises, Inc.
 *	6920 Koll Center Parkway
 *	Pleasanton, CA   94566
 *
 *	Copyright 1992 Livingston Enterprises, Inc.
 *	Copyright 1997 Cistron Internet Services B.V.
 *
 *	Permission to use, copy, modify, and distribute this software for any
 *	purpose and without fee is hereby granted, provided that this
 *	copyright and permission notice appear on all copies and supporting
 *	documentation, the name of Livingston Enterprises, Inc. not be used
 *	in advertising or publicity pertaining to distribution of the
 *	program without specific prior permission, and notice be given
 *	in supporting documentation that copying and distribution is by
 *	permission of Livingston Enterprises, Inc.   
 *
 *	Livingston Enterprises, Inc. makes no representations about
 *	the suitability of this software for any purpose.  It is
 *	provided "as is" without express or implied warranty.
 *
 */

/*
 * util.c	Miscellanous generic functions.
 *
 */

char util_sccsid[] =
"@(#)util.c	1.5 Copyright 1992 Livingston Enterprises Inc\n"
"		2.1 Copyright 1997 Cistron Internet Services B.V.";

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<netdb.h>
#include	<pwd.h>
#include	<time.h>
#include	<ctype.h>
#include	<signal.h>

#include	"md5.h"
#include	"util.h"

/*
 *	Check for valid IP address in standard dot notation.
 */
static int good_ipaddr(char *addr)
{
	int	dot_count;
	int	digit_count;

	dot_count = 0;
	digit_count = 0;
	while(*addr != '\0' && *addr != ' ') {
		if(*addr == '.') {
			dot_count++;
			digit_count = 0;
		}
		else if(!isdigit(*addr)) {
			dot_count = 5;
		}
		else {
			digit_count++;
			if(digit_count > 3) {
				dot_count = 5;
			}
		}
		addr++;
	}
	if(dot_count != 3) {
		return(-1);
	}
	else {
		return(0);
	}
}

/*
 *	Return an IP address in host long notation from
 *	one supplied in standard dot notation.
 */
static UINT4 ipstr2long(char *ip_str)
{
	char	buf[6];
	char	*ptr;
	int	i;
	int	count;
	UINT4	ipaddr;
	int	cur_byte;

	ipaddr = (UINT4)0;
	for(i = 0;i < 4;i++) {
		ptr = buf;
		count = 0;
		*ptr = '\0';
		while(*ip_str != '.' && *ip_str != '\0' && count < 4) {
			if(!isdigit(*ip_str)) {
				return((UINT4)0);
			}
			*ptr++ = *ip_str++;
			count++;
		}
		if(count >= 4 || count == 0) {
			return((UINT4)0);
		}
		*ptr = '\0';
		cur_byte = atoi(buf);
		if(cur_byte < 0 || cur_byte > 255) {
			return((UINT4)0);
		}
		ip_str++;
		ipaddr = ipaddr << 8 | (UINT4)cur_byte;
	}
	return(ipaddr);
}

/*
 *	Return an IP address in host long notation from a host
 *	name or address in dot notation.
 */
UINT4 get_ipaddr(char *host)
{
	struct hostent	*hp;

	if(good_ipaddr(host) == 0) {
		return(ipstr2long(host));
	}
	else if((hp = gethostbyname(host)) == (struct hostent *)NULL) {
		return((UINT4)0);
	}
	return(ntohl(*(UINT4 *)hp->h_addr));
}


void md5_calc(unsigned char *output, unsigned char *input, unsigned int inlen)
{
	MD5_CTX	context;

	MD5Init(&context);
	MD5Update(&context, input, inlen);
	MD5Final(output, &context);
}

