#ifndef _SQUID_COMM_COMM_ERR_T_H
#define _SQUID_COMM_COMM_ERR_T_H

typedef enum {
    COMM_OK = 0,
    COMM_ERROR = -1,
    COMM_NOMESSAGE = -3,
    COMM_TIMEOUT = -4,
    COMM_SHUTDOWN = -5,
    COMM_IDLE = -6, /* there are no active fds and no pending callbacks. */
    COMM_INPROGRESS = -7,
    COMM_ERR_CONNECT = -8,
    COMM_ERR_DNS = -9,
    COMM_ERR_CLOSING = -10,
    COMM_ERR_PROTOCOL = -11, /* IPv4 or IPv6 cannot be used on the fd socket */
    COMM_ERR__END__ = -999999 /* Dummy entry to make syntax valid (comma on line above), do not use. New entries added above */
} comm_err_t;

#endif /* _SQUID_COMM_COMM_ERR_T_H */
