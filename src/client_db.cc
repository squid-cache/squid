
#include "squid.h"

typedef struct _client_info {
    char *key;
    struct client_info *next;
    struct in_addr addr;
    int result_hist[ERR_MAX];
    int n_http;
    int n_icp;
    int n_requests;
} ClientInfo;

int client_info_sz;

static HashID client_table = 0;

static ClientInfo *clientdbAdd _PARAMS((struct in_addr addr));

static ClientInfo *
clientdbAdd(struct in_addr addr)
{
    ClientInfo *c;
    c = xcalloc(1, sizeof(ClientInfo));
    c->key = xstrdup(inet_ntoa(addr));
    c->addr = addr;
    hash_join(client_table, (hash_link *) c);
    meta_data.client_info++;
    return c;
}

void
clientdbInit(void)
{
    if (client_table)
	return;
    client_table = hash_create((int (*)_PARAMS((const char *, const char *))) strcmp,
	229,
	hash_string);
    client_info_sz = sizeof(ClientInfo);
}

void
clientdbUpdate(struct in_addr addr, log_type log_type, u_short port)
{
    char *key = inet_ntoa(addr);
    ClientInfo *c = (ClientInfo *) hash_lookup(client_table, key);
    if (c == NULL)
	c = clientdbAdd(addr);
    if (c == NULL)
	debug_trap("clientdbUpdate: Failed to add entry");
    c->result_hist[log_type]++;
    if (port == Config.Port.http)
	c->n_http++;
    else if (port == Config.Port.icp)
	c->n_icp++;
    c->n_requests++;
}

int
clientdbDeniedPercent(struct in_addr addr)
{
    char *key = inet_ntoa(addr);
    int n = 100;
    ClientInfo *c = (ClientInfo *) hash_lookup(client_table, key);
    if (c == NULL)
	return 0;
    if (c->n_icp > 100)
	n = c->n_icp;
    return 100 * c->result_hist[ICP_OP_DENIED] / n;
}

void
clientdbDump(StoreEntry * sentry)
{
    ClientInfo *c;
    log_type l;
    storeAppendPrintf(sentry, "{Cache Clients:\n");
    c = (ClientInfo *) hash_first(client_table);
    while (c) {
	storeAppendPrintf(sentry, "{Address: %s}\n", c->key);
	storeAppendPrintf(sentry, "{Name: %s}\n", fqdnFromAddr(c->addr));
	storeAppendPrintf(sentry, "{    HTTP Requests %d}\n",
	    c->n_http);
	storeAppendPrintf(sentry, "{    ICP Requests %d}\n",
	    c->n_icp);
	storeAppendPrintf(sentry, "{    Log Code Histogram:}\n");
	for (l = LOG_TAG_NONE; l < ERR_MAX; l++) {
	    if (c->result_hist[l] == 0)
		continue;
	    storeAppendPrintf(sentry,
		"{        %-20.20s %7d %3d%%}\n",
		log_tags[l],
		c->result_hist[l],
		percent(c->result_hist[l], c->n_requests));
	}
	storeAppendPrintf(sentry, "{}\n");
	c = (ClientInfo *) hash_next(client_table);
    }
    storeAppendPrintf(sentry, close_bracket);
}
