
/*
 * $Id: rfc1035.c,v 1.31 2004/04/11 09:15:11 hno Exp $
 *
 * Low level DNS protocol routines
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

/*
 * KNOWN BUGS:
 * 
 * UDP replies with TC set should be retried via TCP
 */

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

#include "rfc1035.h"
#include "snprintf.h"

#define RFC1035_MAXLABELSZ 63
#define rfc1035_unpack_error 15

#if 0
#define RFC1035_UNPACK_DEBUG  fprintf(stderr, "unpack error at %s:%d\n", __FILE__,__LINE__)
#else
#define RFC1035_UNPACK_DEBUG  (void)0
#endif


typedef struct _rfc1035_header rfc1035_header;

int rfc1035_errno;
const char *rfc1035_error_message;
struct _rfc1035_header {
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

static const char *Alphanum =
"abcdefghijklmnopqrstuvwxyz"
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"0123456789";


/*
 * rfc1035HeaderPack()
 * 
 * Packs a rfc1035_header structure into a buffer.
 * Returns number of octets packed (should always be 12)
 */
static off_t
rfc1035HeaderPack(char *buf, size_t sz, rfc1035_header * hdr)
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
static off_t
rfc1035NamePack(char *buf, size_t sz, const char *name)
{
    off_t off = 0;
    char *copy = strdup(name);
    char *t;
    /*
     * NOTE: use of strtok here makes names like foo....com valid.
     */
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
    unsigned short _class)
{
    off_t off = 0;
    unsigned short s;
    off += rfc1035NamePack(buf + off, sz - off, name);
    s = htons(type);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    s = htons(_class);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    assert(off <= sz);
    return off;
}

/*
 * rfc1035HeaderUnpack()
 * 
 * Unpacks a RFC1035 message header buffer into a rfc1035_header
 * structure.
 *
 * Updates the buffer offset, which is the same as number of
 * octects unpacked since the header starts at offset 0.
 *
 * Returns 0 (success) or 1 (error)
 */
static int
rfc1035HeaderUnpack(const char *buf, size_t sz, off_t * off, rfc1035_header * h)
{
    unsigned short s;
    unsigned short t;
    assert(*off == 0);
    /*
     * The header is 12 octets.  This is a bogus message if the size
     * is less than that.
     */
    if (sz < 12)
	return 1;
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    h->id = ntohs(s);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    t = ntohs(s);
    h->qr = (t >> 15) & 0x01;
    h->opcode = (t >> 11) & 0x0F;
    h->aa = (t >> 10) & 0x01;
    h->tc = (t >> 9) & 0x01;
    h->rd = (t >> 8) & 0x01;
    h->ra = (t >> 7) & 0x01;
    /*
     * We might want to check that the reserved 'Z' bits (6-4) are
     * all zero as per RFC 1035.  If not the message should be
     * rejected.
     */
    h->rcode = t & 0x0F;
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    h->qdcount = ntohs(s);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    h->ancount = ntohs(s);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    h->nscount = ntohs(s);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    h->arcount = ntohs(s);
    assert((*off) == 12);
    return 0;
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
 * Updates the new buffer offset.
 *
 * Returns 0 (success) or 1 (error)
 */
static int
rfc1035NameUnpack(const char *buf, size_t sz, off_t * off, char *name, size_t ns, int rdepth)
{
    off_t no = 0;
    unsigned char c;
    size_t len;
    assert(ns > 0);
    do {
	assert((*off) < sz);
	c = *(buf + (*off));
	if (c > 191) {
	    /* blasted compression */
	    unsigned short s;
	    off_t ptr;
	    if (rdepth > 64)	/* infinite pointer loop */
		return 1;
	    memcpy(&s, buf + (*off), sizeof(s));
	    s = ntohs(s);
	    (*off) += sizeof(s);
	    /* Sanity check */
	    if ((*off) >= sz)
		return 1;
	    ptr = s & 0x3FFF;
	    /* Make sure the pointer is inside this message */
	    if (ptr >= sz)
		return 1;
	    return rfc1035NameUnpack(buf, sz, &ptr, name + no, ns - no, rdepth + 1);
	} else if (c > RFC1035_MAXLABELSZ) {
	    /*
	     * "(The 10 and 01 combinations are reserved for future use.)"
	     */
	    return 1;
	} else {
	    (*off)++;
	    len = (size_t) c;
	    if (len == 0)
		break;
	    if (len > (ns - no - 1))	/* label won't fit */
		return 1;
	    if ((*off) + len >= sz)	/* message is too short */
		return 1;
	    memcpy(name + no, buf + (*off), len);
	    (*off) += len;
	    no += len;
	    *(name + (no++)) = '.';
	}
    } while (c > 0 && no < ns);
    if (no)
	*(name + no - 1) = '\0';
    else
	*name = '\0';
    /* make sure we didn't allow someone to overflow the name buffer */
    assert(no <= ns);
    return 0;
}

/*
 * rfc1035RRUnpack()
 * 
 * Unpacks a RFC1035 Resource Record into 'RR' from a message buffer.
 * The caller must free RR->rdata!
 *
 * Updates the new message buffer offset.
 *
 * Returns 0 (success) or 1 (error)
 */
static int
rfc1035RRUnpack(const char *buf, size_t sz, off_t * off, rfc1035_rr * RR)
{
    unsigned short s;
    unsigned int i;
    off_t rdata_off;
    if (rfc1035NameUnpack(buf, sz, off, RR->name, RFC1035_MAXHOSTNAMESZ, 0)) {
	RFC1035_UNPACK_DEBUG;
	memset(RR, '\0', sizeof(*RR));
	return 1;
    }
    /*
     * Make sure the remaining message has enough octets for the
     * rest of the RR fields.
     */
    if ((*off) + 10 > sz) {
	RFC1035_UNPACK_DEBUG;
	memset(RR, '\0', sizeof(*RR));
	return 1;
    }
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    RR->type = ntohs(s);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    RR->_class = ntohs(s);
    memcpy(&i, buf + (*off), sizeof(i));
    (*off) += sizeof(i);
    RR->ttl = ntohl(i);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    if ((*off) + ntohs(s) > sz) {
	/*
	 * We got a truncated packet.  'dnscache' truncates UDP
	 * replies at 512 octets, as per RFC 1035.
	 */
	RFC1035_UNPACK_DEBUG;
	memset(RR, '\0', sizeof(*RR));
	return 1;
    }
    RR->rdlength = ntohs(s);
    switch (RR->type) {
    case RFC1035_TYPE_PTR:
	RR->rdata = malloc(RFC1035_MAXHOSTNAMESZ);
	rdata_off = *off;
	if (rfc1035NameUnpack(buf, sz, &rdata_off, RR->rdata, RFC1035_MAXHOSTNAMESZ, 0))
	    return 1;
	if (rdata_off != ((*off) + RR->rdlength)) {
	    /*
	     * This probably doesn't happen for valid packets, but
	     * I want to make sure that NameUnpack doesn't go beyond
	     * the RDATA area.
	     */
	    RFC1035_UNPACK_DEBUG;
	    memset(RR, '\0', sizeof(*RR));
	    return 1;
	}
	break;
    case RFC1035_TYPE_A:
    default:
	RR->rdata = malloc(RR->rdlength);
	memcpy(RR->rdata, buf + (*off), RR->rdlength);
	break;
    }
    (*off) += RR->rdlength;
    assert((*off) <= sz);
    return 0;
}

static unsigned short
rfc1035Qid(void)
{
    static unsigned short qid = 0x0001;
    if (++qid == 0xFFFF)
	qid = 0x0001;
    return qid;
}

static void
rfc1035SetErrno(int n)
{
    switch (rfc1035_errno = n) {
    case 0:
	rfc1035_error_message = "No error condition";
	break;
    case 1:
	rfc1035_error_message = "Format Error: The name server was "
	    "unable to interpret the query.";
	break;
    case 2:
	rfc1035_error_message = "Server Failure: The name server was "
	    "unable to process this query.";
	break;
    case 3:
	rfc1035_error_message = "Name Error: The domain name does "
	    "not exist.";
	break;
    case 4:
	rfc1035_error_message = "Not Implemented: The name server does "
	    "not support the requested kind of query.";
	break;
    case 5:
	rfc1035_error_message = "Refused: The name server refuses to "
	    "perform the specified operation.";
	break;
    case rfc1035_unpack_error:
	rfc1035_error_message = "The DNS reply message is corrupt or could "
	    "not be safely parsed.";
	break;
    default:
	rfc1035_error_message = "Unknown Error";
	break;
    }
}

void
rfc1035RRDestroy(rfc1035_rr * rr, int n)
{
    if (rr == NULL)
	return;
    assert(n > 0);
    while (n--) {
	if (rr[n].rdata)
	    free(rr[n].rdata);
    }
    free(rr);
}

/*
 * rfc1035AnswersUnpack()
 *
 * Takes the contents of a DNS reply and fills in an array
 * of resource record structures.  The records array is allocated
 * here, and should be freed by calling rfc1035RRDestroy().
 *
 * Returns number of records unpacked, zero if DNS reply indicates
 * zero answers, or an error number < 0.
 */

int
rfc1035AnswersUnpack(const char *buf,
    size_t sz,
    rfc1035_rr ** records,
    unsigned short *id)
{
    off_t off = 0;
    int l;
    int i;
    int nr = 0;
    rfc1035_header hdr;
    rfc1035_rr *recs;
    memset(&hdr, '\0', sizeof(hdr));
    if (rfc1035HeaderUnpack(buf + off, sz - off, &off, &hdr)) {
	RFC1035_UNPACK_DEBUG;
	rfc1035SetErrno(rfc1035_unpack_error);
	return -rfc1035_unpack_error;
    }
    *id = hdr.id;
    rfc1035_errno = 0;
    rfc1035_error_message = NULL;
    if (hdr.rcode) {
	RFC1035_UNPACK_DEBUG;
	rfc1035SetErrno((int) hdr.rcode);
	return -rfc1035_errno;
    }
    i = (int) hdr.qdcount;
    /* skip question */
    while (i--) {
	do {
	    l = (int) (unsigned char) *(buf + off);
	    off++;
	    if (l > 191) {	/* compression */
		off++;
		break;
	    } else if (l > RFC1035_MAXLABELSZ) {
		/* illegal combination of compression bits */
		RFC1035_UNPACK_DEBUG;
		rfc1035SetErrno(rfc1035_unpack_error);
		return -rfc1035_unpack_error;
	    } else {
		off += l;
	    }
	} while (l > 0);	/* a zero-length label terminates */
	off += 4;		/* qtype, qclass */
	if (off > sz) {
	    RFC1035_UNPACK_DEBUG;
	    rfc1035SetErrno(rfc1035_unpack_error);
	    return -rfc1035_unpack_error;
	}
    }
    i = (int) hdr.ancount;
    if (i == 0)
	return 0;
    recs = calloc(i, sizeof(*recs));
    while (i--) {
	if (off >= sz) {	/* corrupt packet */
	    RFC1035_UNPACK_DEBUG;
	    break;
	}
	if (rfc1035RRUnpack(buf, sz, &off, &recs[i])) {		/* corrupt RR */
	    RFC1035_UNPACK_DEBUG;
	    break;
	}
	nr++;
    }
    if (nr == 0) {
	/*
	 * we expected to unpack some answers (ancount != 0), but
	 * didn't actually get any.
	 */
	free(recs);
	rfc1035SetErrno(rfc1035_unpack_error);
	return -rfc1035_unpack_error;
    }
    *records = recs;
    return nr;
}

/*
 * rfc1035BuildAQuery()
 * 
 * Builds a message buffer with a QUESTION to lookup A records
 * for a hostname.  Caller must allocate 'buf' which should
 * probably be at least 512 octets.  The 'szp' initially
 * specifies the size of the buffer, on return it contains
 * the size of the message (i.e. how much to write).
 * Return value is the query ID.
 */
unsigned short
rfc1035BuildAQuery(const char *hostname, char *buf, size_t * szp)
{
    static rfc1035_header h;
    size_t offset = 0;
    size_t sz = *szp;
    memset(&h, '\0', sizeof(h));
    /* the first char of hostname must be alphanmeric */
    if (NULL == strchr(Alphanum, *hostname)) {
	rfc1035SetErrno(3);
	return 0;
    }
    h.id = rfc1035Qid();
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
    return h.id;
}

/*
 * rfc1035BuildPTRQuery()
 * 
 * Builds a message buffer with a QUESTION to lookup PTR records
 * for an address.  Caller must allocate 'buf' which should
 * probably be at least 512 octets.  The 'szp' initially
 * specifies the size of the buffer, on return it contains
 * the size of the message (i.e. how much to write).
 * Return value is the query ID.
 */
unsigned short
rfc1035BuildPTRQuery(const struct in_addr addr, char *buf, size_t * szp)
{
    static rfc1035_header h;
    size_t offset = 0;
    size_t sz = *szp;
    static char rev[32];
    unsigned int i;
    memset(&h, '\0', sizeof(h));
    i = (unsigned int) ntohl(addr.s_addr);
    snprintf(rev, 32, "%u.%u.%u.%u.in-addr.arpa.",
	i & 255,
	(i >> 8) & 255,
	(i >> 16) & 255,
	(i >> 24) & 255);
    h.id = rfc1035Qid();
    h.qr = 0;
    h.rd = 1;
    h.opcode = 0;		/* QUERY */
    h.qdcount = (unsigned int) 1;
    offset += rfc1035HeaderPack(buf + offset, sz - offset, &h);
    offset += rfc1035QuestionPack(buf + offset,
	sz - offset,
	rev,
	RFC1035_TYPE_PTR,
	RFC1035_CLASS_IN);
    assert(offset <= sz);
    *szp = offset;
    return h.id;
}

/*
 * We're going to retry a former query, but we
 * just need a new ID for it.  Lucky for us ID
 * is the first field in the message buffer.
 */
unsigned short
rfc1035RetryQuery(char *buf)
{
    unsigned short qid = rfc1035Qid();
    unsigned short s = htons(qid);
    memcpy(buf, &s, sizeof(s));
    return qid;
}

#if DRIVER
#include <sys/socket.h>
#include <sys/time.h>
int
main(int argc, char *argv[])
{
    char input[512];
    char buf[512];
    char rbuf[512];
    size_t sz = 512;
    unsigned short sid;
    int s;
    int rl;
    struct sockaddr_in S;
    if (3 != argc) {
	fprintf(stderr, "usage: %s ip port\n", argv[0]);
	return 1;
    }
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
	perror("socket");
	return 1;
    }
    memset(&S, '\0', sizeof(S));
    S.sin_family = AF_INET;
    S.sin_port = htons(atoi(argv[2]));
    S.sin_addr.s_addr = inet_addr(argv[1]);
    while (fgets(input, 512, stdin)) {
	struct in_addr junk;
	strtok(input, "\r\n");
	memset(buf, '\0', 512);
	sz = 512;
	if (inet_aton(input, &junk)) {
	    sid = rfc1035BuildPTRQuery(junk, buf, &sz);
	} else {
	    sid = rfc1035BuildAQuery(input, buf, &sz);
	}
	sendto(s, buf, sz, 0, (struct sockaddr *) &S, sizeof(S));
	do {
	    fd_set R;
	    struct timeval to;
	    FD_ZERO(&R);
	    FD_SET(s, &R);
	    to.tv_sec = 10;
	    to.tv_usec = 0;
	    rl = select(s + 1, &R, NULL, NULL, &to);
	} while (0);
	if (rl < 1) {
	    printf("TIMEOUT\n");
	    continue;
	}
	memset(rbuf, '\0', 512);
	rl = recv(s, rbuf, 512, 0);
	{
	    unsigned short rid = 0;
	    int i;
	    int n;
	    rfc1035_rr *answers = NULL;
	    n = rfc1035AnswersUnpack(rbuf,
		rl,
		&answers,
		&rid);
	    if (n < 0) {
		printf("ERROR %d\n", rfc1035_errno);
	    } else if (rid != sid) {
		printf("ERROR, ID mismatch (%#hx, %#hx)\n", sid, rid);
	    } else {
		printf("%d answers\n", n);
		for (i = 0; i < n; i++) {
		    if (answers[i].type == RFC1035_TYPE_A) {
			struct in_addr a;
			memcpy(&a, answers[i].rdata, 4);
			printf("A\t%d\t%s\n", answers[i].ttl, inet_ntoa(a));
		    } else if (answers[i].type == RFC1035_TYPE_PTR) {
			char ptr[128];
			strncpy(ptr, answers[i].rdata, answers[i].rdlength);
			printf("PTR\t%d\t%s\n", answers[i].ttl, ptr);
		    } else {
			fprintf(stderr, "can't print answer type %d\n",
			    (int) answers[i].type);
		    }
		}
	    }
	}
    }
    return 0;
}
#endif
