#ifndef SQUID__SRC_CLIENTINFO_H
#define SQUID__SRC_CLIENTINFO_H

#include "ip/IpAddress.h"
#include "hash.h"
#include "enums.h"
#include "typedefs.h"

class ClientInfo
{
public:
    hash_link hash;             /* must be first */

    IpAddress addr;

    struct {
        int result_hist[LOG_TYPE_MAX];
        int n_requests;
        kb_t kbytes_in;
        kb_t kbytes_out;
        kb_t hit_kbytes_out;
    } Http, Icp;

    struct {
        time_t time;
        int n_req;
        int n_denied;
    } cutoff;
    int n_established;          /* number of current established connections */
    time_t last_seen;
};

#endif
