#include "squid.h"

typedef struct _Countstr Countstr;
typedef struct _htcpHeader htcpHeader;
typedef struct _htcpDataHeader htcpDataHeader;
typedef struct _htcpAuthHeader htcpAuthHeader;
typedef struct _Specifier Specifier;
typedef struct _Detail Detail;
typedef struct _Identity Identity;

struct _Countstr {
    u_short length;
    char *text;
};

struct _htcpHeader {
    u_short length;
    u_char major;
    u_char minor;
};

struct _htcpDataHeader {
    u_short length;
    u_char opcode:4;
    u_char response:4;
    u_char reserved:6;
    u_char F1:1;
    /* RR == 0 --> F1 = RESPONSE DESIRED FLAG */
    /* RR == 1 --> F1 = MESSAGE OVERALL FLAG */
    u_char RR:1;
    /* RR == 0 --> REQUEST */
    /* RR == 1 --> RESPONSE */
    u_num32 msg_id;
};

struct _htcpAuthHeader {
    u_short length;
    time_t sig_time;
    time_t sig_expire;
    Countstr key_name;
    Countstr signature;
};

struct _Specifier {
    Countstr method;
    Countstr URI;
    Countstr version;
    Countstr req_hdrs;
};

struct _Detail {
    Countstr resp_hdrs;
    Countstr entity_hdrs;
    Countstr cache_hdrs;
};

struct _Identity {
    Specifier specifier;
    Detail detail;
};

enum {
    HTCP_NOP,
    HTCP_TST,
    HTCP_MON,
    HTCP_SET,
    HTCP_CLR
};

/*
 * values for htcpDataHeader->response
 */
enum {
    AUTH_REQUIRED,
    AUTH_FAILURE,
    OPCODE_UNIMPLEMENTED,
    MAJOR_VERSION_UNSUPPORTED,
    MINOR_VERSION_UNSUPPORTED,
    INVALID_OPCODE
};

/*
 * values for htcpDataHeader->RR
 */
enum {
    RR_REQUEST,
    RR_RESPONSE
};


size_t
htpcBuildAuth(char *buf, size_t buflen)
{
    htcpAuthHeader auth;
    size_t copy_sz = 0;
    assert(2 == sizeof(u_short));
    auth.length = htons(2);
    copy_sz += 2;
    assert(buflen >= copy_sz);
    xmemcpy(buf, &auth, copy_sz);
    return copy_sz;
}

Specifier *
htcpBuildSpecifier(char *buf, size_t buflen, HtcpStuff *stuff)
{
	off_t off = 0;
	...
}

size_t
htcpBuildTstOpData(char *buf, size_t buflen, HtcpStuff *stuff)
{
	return htcpBuildSpecifier(buf, buflen, stuff);
}

size_t
htcpBuildOpData(char *buf, size_t buflen, HtcpStuff *stuff)
{
	off_t off = 0;
	switch(stuff->op) {
	case HTCP_TST:
		off = htcpBuildTstOpData(buf + off, buflen, stuff);
		break:
	default:
		assert(0);
		break;
	}
	return off;
}

size_t
htcpBuildData(char *buf, size_t buflen, HtcpStuff *stuff)
{
	off_t off = 0;
	off += sizeof(htcpDataHeader);	/* skip! */
	htcpBuildOpData(buf + off, buflen - off, stuff);
	...
}

htcpBuildPacket(HtcpStuff *stuff)
{
	size_t buflen = 8192;
	off_t off = 0;
	char *buf = xcalloc(buflen, 1);
	/* skip the header -- we don't know the overall length */
	off += sizeof(htcpHeader);
	off += htcpBuildData(buf + off, buflen-off, stuff);
	...
}
