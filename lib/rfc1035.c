#include "config.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_MEMORY_H
#include <memory.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_ASSERT_H
#include <assert.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif

#define RFC1035_TYPE_A 1
#define RFC1035_CLASS_IN 1

#define RFC1035_MAXLABELSZ 63
#define RFC1035_MAXHOSTNAMESZ 128

typedef struct _rfc1305_header rfc1305_header;
typedef struct _rfc1305_rr rfc1305_rr;

int rfc1035_errno;

struct _rfc1305_header {
    unsigned short id;
    unsigned int qr:1;
    unsigned int opcode:4;
    unsigned int aa:1;
    unsigned int tc:1;
    unsigned int rd:1;
    unsigned int ra:1;
    unsigned int rcode:4;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

struct _rfc1305_rr {
    char name[RFC1035_MAXHOSTNAMESZ];
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short rdlength;
    char *rdata;
};

/*
 * rfc1035HeaderPack()
 * 
 * Packs a rfc1305_header structure into a buffer.
 * Returns number of octets packed (should always be 12)
 */
static off_t
rfc1035HeaderPack(char *buf, size_t sz, rfc1305_header * hdr)
{
    off_t off = 0;
    unsigned short s;
    unsigned short t;
    assert(sz >= 12);
    s = htons(hdr->id);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    t = 0;
    t |= hdr->qr << 15;
    t |= (hdr->opcode << 11);
    t |= (hdr->aa << 10);
    t |= (hdr->tc << 9);
    t |= (hdr->rd << 8);
    t |= (hdr->ra << 7);
    t |= hdr->rcode;
    s = htons(t);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    s = htons(hdr->qdcount);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    s = htons(hdr->ancount);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    s = htons(hdr->nscount);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    s = htons(hdr->arcount);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    assert(off == 12);
    return off;
}

/*
 * rfc1035LabelPack()
 * 
 * Packs a label into a buffer.  The format of
 * a label is one octet specifying the number of character
 * bytes to follow.  Labels must be smaller than 64 octets.
 * Returns number of octets packed.
 */
static off_t
rfc1035LabelPack(char *buf, size_t sz, const char *label)
{
    off_t off = 0;
    size_t len = label ? strlen(label) : 0;
    if (label)
	assert(!strchr(label, '.'));
    if (len > RFC1035_MAXLABELSZ)
	len = RFC1035_MAXLABELSZ;
    assert(sz >= len + 1);
    *(buf + off) = (char) len;
    off++;
    memcpy(buf + off, label, len);
    off += len;
    return off;
}

/*
 * rfc1035NamePack()
 * 
 * Packs a name into a buffer.  Names are packed as a
 * sequence of labels, terminated with NULL label.
 * Note message compression is not supported here.
 * Returns number of octets packed.
 */
off_t
rfc1035NamePack(char *buf, size_t sz, const char *name)
{
    off_t off = 0;
    char *copy = strdup(name);
    char *t;
    for (t = strtok(copy, "."); t; t = strtok(NULL, "."))
	off += rfc1035LabelPack(buf + off, sz - off, t);
    free(copy);
    off += rfc1035LabelPack(buf + off, sz - off, NULL);
    assert(off <= sz);
    return off;
}

/*
 * rfc1035QuestionPack()
 * 
 * Packs a QUESTION section of a message.
 * Returns number of octets packed.
 */
static off_t
rfc1035QuestionPack(char *buf,
    size_t sz,
    const char *name,
    unsigned short type,
    unsigned short class)
{
    off_t off = 0;
    unsigned short s;
    off += rfc1035NamePack(buf + off, sz - off, name);
    s = htons(type);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    s = htons(class);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    assert(off <= sz);
    return off;
}

/*
 * rfc1035HeaderUnpack()
 * 
 * Unpacks a RFC1035 message header buffer into a rfc1305_header
 * structure.
 * Returns the new buffer offset, which is the same as number of
 * octects unpacked since the header starts at offset 0.
 */
static off_t
rfc1035HeaderUnpack(const char *buf, size_t sz, rfc1305_header * h)
{
    unsigned short s;
    unsigned short t;
    off_t off = 0;
    assert(sz >= 12);
    memcpy(&s, buf + off, sizeof(s));
    off += sizeof(s);
    h->id = ntohs(s);
    memcpy(&s, buf + off, sizeof(s));
    off += sizeof(s);
    t = ntohs(s);
    h->qr = (t >> 15) & 0x01;
    h->opcode = (t >> 11) & 0x0F;
    h->aa = (t >> 10) & 0x01;
    h->tc = (t >> 8) & 0x01;
    h->rd = (t >> 8) & 0x01;
    h->ra = (t >> 7) & 0x01;
    h->rcode = t & 0x0F;
    memcpy(&s, buf + off, sizeof(s));
    off += sizeof(s);
    h->qdcount = ntohs(s);
    memcpy(&s, buf + off, sizeof(s));
    off += sizeof(s);
    h->ancount = ntohs(s);
    memcpy(&s, buf + off, sizeof(s));
    off += sizeof(s);
    h->nscount = ntohs(s);
    memcpy(&s, buf + off, sizeof(s));
    off += sizeof(s);
    h->arcount = ntohs(s);
    assert(off == 12);
    return off;
}

/*
 * rfc1035NameUnpack()
 * 
 * Unpacks a Name in a message buffer into a char*.
 * Note 'buf' points to the beginning of the whole message,
 * 'off' points to the spot where the Name begins, and 'sz'
 * is the size of the whole message.  'name' must be allocated
 * by the caller.
 *
 * Supports the RFC1035 message compression through recursion.
 *
 * Returns the new buffer offset.
 */
static off_t
rfc1035NameUnpack(const char *buf, size_t sz, off_t off, char *name, size_t ns)
{
    off_t no = 0;
    unsigned char c;
    size_t len;
    assert(ns > 0);
    do {
	c = *(buf + off);
	if (c > RFC1035_MAXLABELSZ) {
	    /* fucking compression */
	    unsigned short s;
	    off_t ptr;
	    memcpy(&s, buf + off, sizeof(s));
	    s = ntohs(s);
	    off += sizeof(s);
	    ptr = s & 0x3FFF;
	    (void) rfc1035NameUnpack(buf, sz, ptr, name + no, ns - no);
	    return off;
	} else {
	    off++;
	    len = (size_t) c;
	    if (len == 0)
		break;
	    if (len > (ns-1))
		len = ns-1;
	    memcpy(name + no, buf + off, len);
	    off += len;
	    no += len;
	    *(name + (no++)) = '.';
	}
    } while (c > 0);
    *(name + no - 1) = '\0';
    assert(no <= ns);
    return off;
}

/*
 * rfc1035RRUnpack()
 * 
 * Unpacks a RFC1035 Resource Record into 'RR' from a message buffer.
 * The caller must free RR->rdata!
 * Returns the new message buffer offset.
 */
static off_t
rfc1035RRUnpack(const char *buf, size_t sz, off_t off, rfc1305_rr * RR)
{
    unsigned short s;
    unsigned int i;
    off = rfc1035NameUnpack(buf, sz, off, RR->name, RFC1035_MAXHOSTNAMESZ);
    memcpy(&s, buf + off, sizeof(s));
    off += sizeof(s);
    RR->type = ntohs(s);
    memcpy(&s, buf + off, sizeof(s));
    off += sizeof(s);
    RR->class = ntohs(s);
    memcpy(&i, buf + off, sizeof(i));
    off += sizeof(i);
    RR->ttl = ntohl(i);
    memcpy(&s, buf + off, sizeof(s));
    off += sizeof(s);
    RR->rdlength = ntohs(s);
    RR->rdata = malloc(RR->rdlength);
    memcpy(RR->rdata, buf + off, RR->rdlength);
    off += RR->rdlength;
    assert(off <= sz);
    return off;
}

int
rfc1035ARecordsUnpack(const char *buf,
	size_t sz,
	struct in_addr *addrs,
	int naddrs,
	char *name,
	size_t namelen,
	unsigned short *id,
	time_t * ttl)
{
    off_t off = 0;
    int l;
    int i;
    int na = 0;
    rfc1305_header hdr;
    memset(&hdr, '\0', sizeof(hdr));
    off = rfc1035HeaderUnpack(buf + off, sz - off, &hdr);
    *id = hdr.id;
    if (hdr.rcode) {
	rfc1035_errno = (int) hdr.rcode;
	return -rfc1035_errno;
    }
    i = (int) hdr.qdcount;
    /* skip question */
    while (i--) {
	do {
	    l = (int) *(buf + off);
	    off++;
	    if (l > RFC1035_MAXLABELSZ) {	/* compression */
		off++;
		break;
	    } else {
		off += l;
	    }
	} while (l > 0);
	off += 4;		/* qtype, qclass */
	assert(off <= sz);
    }
    i = (int) hdr.ancount;
    while (i--) {
	rfc1305_rr RR;
	memset(&RR, '\0', sizeof(RR));
	off = rfc1035RRUnpack(buf, sz, off, &RR);
	if (RR.type != RFC1035_TYPE_A) {
	    free(RR.rdata);
	    RR.rdata = NULL;
	    continue;
	}
	if (na == 0) {
	    strncpy(name, RR.name, namelen);
	    *ttl = (time_t) RR.ttl;
	}
	memcpy(&addrs[na].s_addr, RR.rdata, 4);
	free(RR.rdata);
	RR.rdata = NULL;
	assert(off <= sz);
	if (++na == naddrs)
	    break;
    }
    return na;
}

/*
 * rfc1035BuildQuery()
 * 
 * Builds a message buffer with a QUESTION to lookup A records
 * for a hostname.  Caller must allocate 'buf' which should
 * probably be at least 512 octets.  The 'szp' initially
 * specifies the size of the buffer, on return it contains
 * the size of the message (i.e. how much to write).
 * Return value is the query ID.
 */
unsigned short
rfc1035BuildQuery(const char *hostname, char *buf, size_t * szp)
{
    static unsigned short id = 0x0001;
    static rfc1305_header h;
    off_t offset = 0;
    size_t sz = *szp;
    memset(&h, '\0', sizeof(h));
    h.id = id;
    h.qr = 0;
    h.rd = 1;
    h.opcode = 0;		/* QUERY */
    h.qdcount = (unsigned int) 1;
    offset += rfc1035HeaderPack(buf + offset, sz - offset, &h);
    offset += rfc1035QuestionPack(buf + offset,
	sz - offset,
	hostname,
	RFC1035_TYPE_A,
	RFC1035_CLASS_IN);
    assert(offset <= sz);
    *szp = (size_t) offset;
    return id++;
}

#if DRIVER
int
main(int argc, char *argv[])
{
    rfc1305_header h;
    char input[512];
    char buf[512];
    char rbuf[512];
    size_t sz = 512;
    unsigned short sid;
    off_t offset = 0;
    int s;
    int rl;
    struct sockaddr_in S;
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
	perror("socket");
	return 1;
    }
    while (fgets(input, 512, stdin)) {
	strtok(input, "\r\n");
	memset(buf, '\0', 512);
	memset(&h, '\0', sizeof(h));
	offset = 0;
	h.id = sid = (unsigned short) 0x1234;
	h.qr = 0;
	h.rd = 1;
	h.opcode = 0;
	h.qdcount = (unsigned int) 1;
	offset += rfc1035HeaderPack(buf + offset, sz - offset, &h);
	offset += rfc1035QuestionPack(buf + offset,
	    sz - offset,
	    input,
	    RFC1035_TYPE_A,
	    RFC1035_CLASS_IN);
	memset(&S, '\0', sizeof(S));
	S.sin_family = AF_INET;
	S.sin_port = htons(53);
	S.sin_addr.s_addr = inet_addr("128.117.28.219");
	sendto(s, buf, (size_t) offset, 0, (struct sockaddr *) &S, sizeof(S));
	do {
    	    fd_set R;
    	    struct timeval to;
	    FD_ZERO(&R);
	    FD_SET(s, &R);
	    to.tv_sec = 10;
	    to.tv_usec = 0;
	    rl = select(s+1, &R, NULL, NULL, &to);
	} while(0);
	    if (rl < 1) {
		    printf("TIMEOUT\n");
		    continue;
	    }
	memset(rbuf, '\0', 512);
	rl = recv(s, rbuf, 512, 0);
	{
	    unsigned short rid;
	    int i;
	    int n;
	    struct in_addr addrs[10];
	    time_t ttl = 0;
	    char rname[RFC1035_MAXHOSTNAMESZ];
	    n = rfc1035ARecordsUnpack(rbuf,
		rl,
		addrs, 10,
		rname, RFC1035_MAXHOSTNAMESZ,
		&rid,
		&ttl);
	    if (rid != sid) {
		printf("ERROR, ID mismatch (%#hx, %#hx)\n", sid, rid);
	    } else if (n < 0) {
		printf("ERROR %d\n", rfc1035_errno);
	    } else {
		printf("name\t%s, %d A records\n", rname, n);
		printf("ttl\t%d\n", (int) ttl);
		for (i = 0; i < n; i++)
		    printf("addr %d\t%s\n", i, inet_ntoa(addrs[i]));
	    }
	}
    }
    return 0;
}
#endif
