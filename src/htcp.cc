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


char *
htpcBuildAuth(u_short * len)
{
    static char buf[2];
    u_short n_len;
    assert(2 == sizeof(u_short));
    *len = (u_short) 2;
    n_len = htons(*len);
    xmemcpy(buf, &n_len, 2);
    return buf;
}
