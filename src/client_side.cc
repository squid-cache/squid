
#include "squid.h"

static void clientRedirectDone _PARAMS((void *data, char *result));

static int clientLookupDstIPDone(fd, hp, data)
     int fd;
     struct hostent *hp;
     void *data;
{
    icpStateData *icpState = data;
    debug(33, 5, "clientLookupDstIPDone: FD %d, '%s'\n",
	fd,
	icpState->url);
    icpState->aclChecklist->state[ACL_DST_IP] = ACL_LOOKUP_DONE;
    if (hp) {
	xmemcpy(&icpState->aclChecklist->dst_addr.s_addr,
	    *(hp->h_addr_list),
	    hp->h_length);
	debug(33, 5, "clientLookupDstIPDone: %s is %s\n",
	    icpState->request->host,
	    inet_ntoa(icpState->aclChecklist->dst_addr));
    }
    clientAccessCheck(icpState, icpState->aclHandler);
    return 1;
}

static void clientLookupSrcFQDNDone(fd, fqdn, data)
     int fd;
     char *fqdn;
     void *data;
{
    icpStateData *icpState = data;
    debug(33, 5, "clientLookupSrcFQDNDone: FD %d, '%s', FQDN %s\n",
	fd,
	icpState->url,
	fqdn ? fqdn : "NULL");
    icpState->aclChecklist->state[ACL_SRC_DOMAIN] = ACL_LOOKUP_DONE;
    clientAccessCheck(icpState, icpState->aclHandler);
}

static void clientLookupIdentDone(data)
     void *data;
{
}

void clientAccessCheck(icpState, handler)
     icpStateData *icpState;
     void (*handler) _PARAMS((icpStateData *, int));
{
    int answer = 1;
    request_t *r = icpState->request;
    aclCheck_t *ch = NULL;
    if (icpState->aclChecklist == NULL) {
	icpState->aclChecklist = xcalloc(1, sizeof(aclCheck_t));
	icpState->aclChecklist->src_addr = icpState->peer.sin_addr;
	icpState->aclChecklist->request = requestLink(icpState->request);
    }
    ch = icpState->aclChecklist;
    icpState->aclHandler = handler;
    if (httpd_accel_mode && !Config.Accel.withProxy && r->protocol != PROTO_CACHEOBJ) {
	/* this cache is an httpd accelerator ONLY */
	if (!BIT_TEST(icpState->flags, REQ_ACCEL))
	    answer = 0;
    } else {
	answer = aclCheck(HTTPAccessList, ch);
	if (ch->state[ACL_DST_IP] == ACL_LOOKUP_NEED) {
	    ch->state[ACL_DST_IP] = ACL_LOOKUP_PENDING;		/* first */
	    ipcache_nbgethostbyname(icpState->request->host,
		icpState->fd,
		clientLookupDstIPDone,
		icpState);
	    return;
	} else if (ch->state[ACL_SRC_DOMAIN] == ACL_LOOKUP_NEED) {
	    ch->state[ACL_SRC_DOMAIN] = ACL_LOOKUP_PENDING;	/* first */
	    fqdncache_nbgethostbyaddr(icpState->peer.sin_addr,
		icpState->fd,
		clientLookupSrcFQDNDone,
		icpState);
	    return;
	}
    }
    requestUnlink(icpState->aclChecklist->request);
    safe_free(icpState->aclChecklist);
    icpState->aclHandler = NULL;
    (*handler) (icpState, answer);
}

void clientAccessCheckDone(icpState, answer)
     icpStateData *icpState;
     int answer;
{
    int fd = icpState->fd;
    char *buf = NULL;
    debug(33, 5, "clientAccessCheckDone: '%s' answer=%d\n", icpState->url, answer);
    if (answer) {
	urlCanonical(icpState->request, icpState->url);
	redirectStart(fd, icpState, clientRedirectDone, icpState);
    } else {
	debug(33, 5, "Access Denied: %s\n", icpState->url);
	buf = access_denied_msg(icpState->http_code = 400,
	    icpState->method,
	    icpState->url,
	    fd_table[fd].ipaddr);
	icpSendERROR(fd, LOG_TCP_DENIED, buf, icpState, 403);
    }
}

static void clientRedirectDone(data, result)
     void *data;
     char *result;
{
    icpStateData *icpState = data;
    int fd = icpState->fd;
    request_t *new_request = NULL;
    debug(33, 5, "clientRedirectDone: '%s' result=%s\n", icpState->url,
	result ? result : "NULL");
    if (result)
	new_request = urlParse(icpState->request->method, result);
    if (new_request) {
	safe_free(icpState->url);
	icpState->url = xstrdup(result);
	requestUnlink(icpState->request);
	icpState->request = requestLink(new_request);
	urlCanonical(icpState->request, icpState->url);
    }
    icpParseRequestHeaders(icpState);
    fd_note(fd, icpState->url);
    comm_set_select_handler(fd,
	COMM_SELECT_READ,
	(PF) icpDetectClientClose,
	(void *) icpState);
    icp_hit_or_miss(fd, icpState);
}
