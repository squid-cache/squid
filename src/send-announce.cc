/* $Id: send-announce.cc,v 1.11 1996/05/01 22:36:36 wessels Exp $ */

/*
 * DEBUG: Section 27          send-announce
 */

#include "squid.h"


void send_announce()
{
    static char tbuf[256];
    static char sndbuf[BUFSIZ];
    icpUdpData *qdata = NULL;
    struct hostent *hp = NULL;
    char *host = NULL;
    char *file = NULL;
    int port;
    int fd;
    int l;
    int n;

    host = getAnnounceHost();
    port = getAnnouncePort();

    if ((hp = ipcache_gethostbyname(host)) == NULL) {
	debug(27, 1, "send_announce: Unknown host '%s'\n", host);
	return;
    }
    sndbuf[0] = '\0';
    sprintf(tbuf, "cache_version SQUID/%s\n", version_string);
    strcat(sndbuf, tbuf);
    sprintf(tbuf, "Running on %s %d %d\n",
	getMyHostname(),
	getAsciiPortNum(),
	getUdpPortNum());
    strcat(sndbuf, tbuf);
    if (getAdminEmail()) {
	sprintf(tbuf, "cache_admin: %s\n", getAdminEmail());
	strcat(sndbuf, tbuf);
    }
    sprintf(tbuf, "generated %d [%s]\n",
	(int) squid_curtime,
	mkhttpdlogtime(&squid_curtime));
    strcat(sndbuf, tbuf);
    l = strlen(sndbuf);

    if ((file = getAnnounceFile())) {
	fd = file_open(file, NULL, O_RDONLY);
	if (fd > -1 && (n = read(fd, sndbuf + l, BUFSIZ - l - 1)) > 0) {
	    l += n;
	    sndbuf[l] = '\0';
	} else {
	    debug(27, 1, "send_announce: %s: %s\n", file, xstrerror());
	}
    }
    qdata = (icpUdpData *) xcalloc(1, sizeof(icpUdpData));
    qdata->msg = xstrdup(sndbuf);
    qdata->len = strlen(sndbuf) + 1;
    qdata->address.sin_family = AF_INET;
    qdata->address.sin_port = htons(port);
    memcpy(&qdata->address.sin_addr, hp->h_addr_list[0], hp->h_length);
    AppendUdp(qdata);
    comm_set_select_handler(theUdpConnection,
	COMM_SELECT_WRITE,
	(PF) icpUdpReply,
	(void *) qdata);
}
