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
 *	@(#)radius.h	2.0  03-Aug-1996
 */

#define AUTH_VECTOR_LEN		16
#define AUTH_PASS_LEN		16
#define AUTH_STRING_LEN		128	/* maximum of 254 */


typedef struct pw_auth_hdr {
    u_char		code;
    u_char		id;
    uint16_t		length;
    u_char		vector[AUTH_VECTOR_LEN];
    u_char		data[2];
} AUTH_HDR;

#define AUTH_HDR_LEN			20
#define CHAP_VALUE_LENGTH		16

#define PW_AUTH_UDP_PORT		1812
#define PW_ACCT_UDP_PORT		1813

#define VENDORPEC_USR			429

#define PW_TYPE_STRING			0
#define PW_TYPE_INTEGER			1
#define PW_TYPE_IPADDR			2
#define PW_TYPE_DATE			3


#define	PW_AUTHENTICATION_REQUEST	1
#define	PW_AUTHENTICATION_ACK		2
#define	PW_AUTHENTICATION_REJECT	3
#define	PW_ACCOUNTING_REQUEST		4
#define	PW_ACCOUNTING_RESPONSE		5
#define	PW_ACCOUNTING_STATUS		6
#define PW_PASSWORD_REQUEST		7
#define PW_PASSWORD_ACK			8
#define PW_PASSWORD_REJECT		9
#define	PW_ACCOUNTING_MESSAGE		10
#define PW_ACCESS_CHALLENGE		11

#define	PW_USER_NAME			1
#define	PW_PASSWORD			2
#define	PW_CHAP_PASSWORD		3
#define	PW_NAS_IP_ADDRESS		4
#define	PW_NAS_PORT_ID			5
#define	PW_SERVICE_TYPE			6
#define	PW_FRAMED_PROTOCOL		7
#define	PW_FRAMED_IP_ADDRESS		8
#define	PW_FRAMED_IP_NETMASK		9
#define	PW_FRAMED_ROUTING		10
#define	PW_FILTER_ID			11
#define	PW_FRAMED_MTU			12
#define	PW_FRAMED_COMPRESSION		13
#define	PW_LOGIN_IP_HOST		14
#define	PW_LOGIN_SERVICE		15
#define	PW_LOGIN_TCP_PORT		16
#define PW_OLD_PASSWORD			17
#define PW_REPLY_MESSAGE		18
#define PW_CALLBACK_NUMBER		19
#define PW_CALLBACK_ID			20
#define PW_EXPIRATION			21
#define PW_FRAMED_ROUTE			22
#define PW_FRAMED_IPXNET		23
#define PW_STATE			24
#define PW_CLASS			25
#define PW_VENDOR_SPECIFIC		26
#define PW_SESSION_TIMEOUT		27
#define PW_IDLE_TIMEOUT			28
#define PW_CALLED_STATION_ID		30
#define PW_CALLING_STATION_ID		31
#define PW_NAS_ID			32
#define PW_PROXY_STATE			33

#define PW_ACCT_STATUS_TYPE		40
#define PW_ACCT_DELAY_TIME		41
#define PW_ACCT_INPUT_OCTETS		42
#define PW_ACCT_OUTPUT_OCTETS		43
#define PW_ACCT_SESSION_ID		44
#define PW_ACCT_AUTHENTIC		45
#define PW_ACCT_SESSION_TIME		46
#define PW_ACCT_INPUT_PACKETS		47
#define PW_ACCT_OUTPUT_PACKETS		48

#define PW_CHAP_CHALLENGE		60
#define PW_NAS_PORT_TYPE		61
#define PW_PORT_LIMIT			62
#define PW_CONNECT_INFO			77

#define PW_HUNTGROUP_NAME		221
#define PW_AUTHTYPE			1000
#define PW_PREFIX			1003
#define PW_SUFFIX			1004
#define PW_GROUP			1005
#define PW_CRYPT_PASSWORD		1006
#define PW_CONNECT_RATE			1007
#define PW_USER_CATEGORY		1029
#define PW_GROUP_NAME			1030
#define PW_SIMULTANEOUS_USE		1034
#define PW_STRIP_USERNAME		1035
#define PW_FALL_THROUGH			1036
#define PW_ADD_PORT_TO_IP_ADDRESS	1037
#define PW_EXEC_PROGRAM			1038
#define PW_EXEC_PROGRAM_WAIT		1039
#define PW_HINT				1040
#define PAM_AUTH_ATTR			1041
#define PW_LOGIN_TIME			1042

/*
 *	INTEGER TRANSLATIONS
 */

/*	USER TYPES	*/

#define	PW_LOGIN_USER			1
#define	PW_FRAMED_USER			2
#define	PW_DIALBACK_LOGIN_USER		3
#define	PW_DIALBACK_FRAMED_USER		4

/*	FRAMED PROTOCOLS	*/

#define	PW_PPP				1
#define	PW_SLIP				2

/*	FRAMED ROUTING VALUES	*/

#define	PW_NONE				0
#define	PW_BROADCAST			1
#define	PW_LISTEN			2
#define	PW_BROADCAST_LISTEN		3

/*	FRAMED COMPRESSION TYPES	*/

#define	PW_VAN_JACOBSEN_TCP_IP		1

/*	LOGIN SERVICES	*/

#define	PW_TELNET			0
#define	PW_RLOGIN			1
#define	PW_TCP_CLEAR			2
#define	PW_PORTMASTER			3

/*	AUTHENTICATION LEVEL	*/

#define PW_AUTHTYPE_LOCAL		0
#define PW_AUTHTYPE_SYSTEM		1
#define PW_AUTHTYPE_SECURID		2
#define PW_AUTHTYPE_CRYPT		3
#define PW_AUTHTYPE_REJECT		4
#define PW_AUTHTYPE_PAM			253
#define PW_AUTHTYPE_ACCEPT		254

/*	PORT TYPES		*/
#define PW_NAS_PORT_ASYNC		0
#define PW_NAS_PORT_SYNC		1
#define PW_NAS_PORT_ISDN		2
#define PW_NAS_PORT_ISDN_V120		3
#define PW_NAS_PORT_ISDN_V110		4

/*	STATUS TYPES	*/

#define PW_STATUS_START			1
#define PW_STATUS_STOP			2
#define PW_STATUS_ALIVE			3
#define PW_STATUS_ACCOUNTING_ON		7
#define PW_STATUS_ACCOUNTING_OFF	8

