
/*
 * $Id: wccp.cc,v 1.1 1999/04/26 20:44:12 glenn Exp $
 *
 * DEBUG: section 80	 WCCP Support
 * AUTHOR: Glenn Chisholm
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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
#include "squid.h"

#define WCCP_PORT 2048
#define WCCP_VERSION 4
#define WCCP_REVISION 0
#define WCCP_RESPONSE_SIZE 12448
#define WCCP_ACTIVE_CACHES 32
#define WCCP_HASH_SIZE 32
#define WCCP_BUCKETS 256

#define WCCP_HERE_I_AM 7
#define WCCP_I_SEE_YOU 8
#define WCCP_ASSIGN_BUCKET 9

struct wccp_here_i_am_t {
    int type;
    int version;
    int revision;
    char hash[WCCP_HASH_SIZE];
    int reserved;
    int id;
};

struct wccp_cache_entry_t {
    int ip_addr;
    int revision;
    int hash[WCCP_HASH_SIZE];
    int reserved;
};

struct wccp_i_see_you_t {
    int type;
    int version;
    int change;
    int id;
    int number;
    struct wccp_cache_entry_t wccp_cache_entry[WCCP_ACTIVE_CACHES];
};

struct wccp_assign_bucket_t {
        int type;
        int id;
        int number;
        int ip_addr[32];
        char bucket[WCCP_BUCKETS];
};

static struct wccp_here_i_am_t wccp_here_i_am;
static struct sockaddr_in router;
static int router_len;
static int last_change;
static int last_assign;
static int change;

static void wccpAssignBuckets(struct wccp_i_see_you_t * wccp_i_see_you);
/*
 * The functions used during startup:
 * wccpInit
 * wccpConnectionOpen
 * wccpConnectionShutdown
 * wccpConnectionClose
 */

void
wccpInit(void)
{
    debug(80, 5) ("wccpInit: Called\n");

    router_len = sizeof(router);  
    memset(&router, '\0', router_len);
    router.sin_family = AF_INET;
    router.sin_port = htons(2048);
    router.sin_addr = Config.Wccp.router;
            
    memset(&wccp_here_i_am, '\0', sizeof(wccp_here_i_am));
    wccp_here_i_am.type = htonl(WCCP_HERE_I_AM);
    wccp_here_i_am.version = htonl(WCCP_VERSION);
    wccp_here_i_am.revision = htonl(WCCP_REVISION); 

    change = 0;
    last_change = 0;
    last_assign = 0;
}

void
wccpConnectionOpen(void)
{
    u_short port = WCCP_PORT;

    debug(80, 5) ("wccpConnectionOpen: Called\n");
    if (Config.Wccp.router.s_addr != inet_addr("0.0.0.0")) {
	enter_suid();
	theInWccpConnection = comm_open(SOCK_DGRAM,
	    0,
	    Config.Addrs.wccp_incoming,
	    port,
	    COMM_NONBLOCKING,
	    "WCCP Port");
	theInGreConnection = comm_open(SOCK_RAW,
	    47,
	    Config.Addrs.wccp_incoming,
	    0,
	    COMM_NONBLOCKING,
	    "GRE Port");
	leave_suid();
	if ((theInWccpConnection < 0) || (theInGreConnection < 0))
	    fatal("Cannot open wccp Port");
	commSetSelect(theInWccpConnection, COMM_SELECT_READ, wccpHandleUdp, NULL, 0);
	commSetSelect(theInGreConnection, COMM_SELECT_READ, wccpHandleGre, NULL, 0);
	debug(1, 1) ("Accepting WCCP UDP messages on port %d, FD %d.\n",
	    (int) port, theInWccpConnection);
	debug(1, 1) ("Accepting WCCP GRE messages on FD %d.\n",
	    theInGreConnection);
	if (Config.Addrs.wccp_outgoing.s_addr != no_addr.s_addr) {
	    enter_suid();
	    theOutWccpConnection = comm_open(SOCK_DGRAM,
		0,
		Config.Addrs.wccp_outgoing,
		port,
		COMM_NONBLOCKING,
		"WCCP Port");
	    leave_suid();
	    if (theOutWccpConnection < 0)
		fatal("Cannot open Outgoing WCCP Port");
	    commSetSelect(theOutWccpConnection,
		COMM_SELECT_READ,
		wccpHandleUdp,
		NULL, 0);
	    debug(1, 1) ("Outgoing WCCP messages on port %d, FD %d.\n",
		(int) port, theOutWccpConnection);
	    fd_note(theOutWccpConnection, "Outgoing WCCP socket");
	    fd_note(theInWccpConnection, "Incoming WCCP socket");
	} else {
	    theOutWccpConnection = theInWccpConnection;
	    theOutGreConnection = theInGreConnection;
	}
    }else{
	debug(1, 1) ("WCCP Disabled.\n");
    }
}

void
wccpConnectionShutdown(void)
{
    if (theInWccpConnection < 0)
	return;
    if (theInWccpConnection != theOutWccpConnection) {
	debug(80, 1) ("FD %d Closing WCCP socket\n", theInWccpConnection);
	comm_close(theInWccpConnection);
    }
    /*
     * Here we set 'theInWccpConnection' to -1 even though the WCCP 'in'
     * and 'out' sockets might be just one FD.  This prevents this
     * function from executing repeatedly.  When we are really ready to
     * exit or restart, main will comm_close the 'out' descriptor.
     */ theInWccpConnection = -1;
    /*
     * Normally we only write to the outgoing WCCP socket, but we
     * also have a read handler there to catch messages sent to that
     * specific interface.  During shutdown, we must disable reading
     * on the outgoing socket.
     */
    assert(theOutWccpConnection > -1);
    commSetSelect(theOutWccpConnection, COMM_SELECT_READ, NULL, NULL, 0);
}

void
wccpConnectionClose(void)
{
    wccpConnectionShutdown();
    if (theOutWccpConnection > -1) {
	debug(80, 1) ("FD %d Closing WCCP socket\n", theOutWccpConnection);
	comm_close(theOutWccpConnection);
    }
}

/*          
 * Functions for handling the requests.
 */

/*
 * Accept the GRE packet
 */    
void
wccpHandleGre(int sock, void *not_used)
{      
    struct wccp_i_see_you_t wccp_i_see_you;
    struct sockaddr_in from;
    socklen_t from_len; 
    int len;   

    debug(80, 6) ("wccpHandleUdp: Called.\n");

    commSetSelect(sock, COMM_SELECT_READ, wccpHandleUdp, NULL, 0);
    from_len = sizeof(struct sockaddr_in);
    memset(&from, '\0', from_len);

    Counter.syscalls.sock.recvfroms++;

    len = recvfrom(sock,
        &wccp_i_see_you,   
        WCCP_RESPONSE_SIZE,
        0,     
        (struct sockaddr *) &from,
        &from_len);

    if (len > 0) {
        debug(80, 5) ("wccpHandleUdp: FD %d: received %d bytes from %s.\n",
            sock,
            len,
            inet_ntoa(from.sin_addr));
        if(Config.Wccp.router.s_addr != ntohl(from.sin_addr.s_addr)){
             if((ntohl(wccp_i_see_you.version) == WCCP_VERSION) && (ntohl(wccp_i_see_you.type) == WCCP_I_SEE_YOU)){
                debug(80, 5) ("wccpHandleUdp: Valid WCCP packet recieved.\n");
                wccp_here_i_am.id = wccp_i_see_you.id;
                if(change != wccp_i_see_you.change){
                    change = wccp_i_see_you.change;
                    if(last_assign)
                        last_assign = 0;
                    else
                        last_change = 4;
                }
                if(last_change){
                    last_change--;
                    if(!last_change){
                        wccpAssignBuckets(&wccp_i_see_you);
                        last_assign = 1;
                    }
                }
             }else{
                debug(80, 5) ("wccpHandleUdp: Invalid WCCP packet recieved.\n");
             }
        } else {
             debug(80, 5) ("wccpHandleUdp: WCCP packet recieved from invalid address.\n");
        }
    }
}    
            
/*          
 * Accept the UDP packet
 */     
void
wccpHandleUdp(int sock, void *not_used)
{       
    struct wccp_i_see_you_t wccp_i_see_you;
    struct sockaddr_in from;
    socklen_t from_len;  
    int len;    

    debug(80, 6) ("wccpHandleUdp: Called.\n");
                
    commSetSelect(sock, COMM_SELECT_READ, wccpHandleUdp, NULL, 0);
    from_len = sizeof(struct sockaddr_in);
    memset(&from, '\0', from_len);
                
    Counter.syscalls.sock.recvfroms++;
                
    len = recvfrom(sock,
        &wccp_i_see_you,    
        WCCP_RESPONSE_SIZE,
        0,      
        (struct sockaddr *) &from,
        &from_len);
        
    if (len > 0) {
        debug(80, 5) ("wccpHandleUdp: FD %d: received %d bytes from %s.\n",
            sock,
            len,
            inet_ntoa(from.sin_addr));
        if(Config.Wccp.router.s_addr != ntohl(from.sin_addr.s_addr)){
	     if((ntohl(wccp_i_see_you.version) == WCCP_VERSION) && (ntohl(wccp_i_see_you.type) == WCCP_I_SEE_YOU)){
		debug(80, 5) ("wccpHandleUdp: Valid WCCP packet recieved.\n");
		wccp_here_i_am.id = wccp_i_see_you.id;
		if(change != wccp_i_see_you.change){
		    change = wccp_i_see_you.change;
		    if(last_assign)
			last_assign = 0;
		    else
		        last_change = 4;
		}
		if(last_change){
		    last_change--;
		    if(!last_change){
			wccpAssignBuckets(&wccp_i_see_you); 
			last_assign = 1;
		    }
		}
	     }else{
		debug(80, 5) ("wccpHandleUdp: Invalid WCCP packet recieved.\n");
	     }
	} else {
	     debug(80, 5) ("wccpHandleUdp: WCCP packet recieved from invalid address.\n");
	}
    } 
}   

void
wccpHereIam(void *voidnotused)
{
    debug(80, 6) ("wccpHereIam: Called\n"); 

    sendto(theOutWccpConnection, 
	&wccp_here_i_am, 
	sizeof(wccp_here_i_am), 
	0, 
	(struct sockaddr *) & router, 
	router_len);

    eventAdd("wccpHereIam", wccpHereIam, NULL, 10.0, 1);
}

void
wccpAssignBuckets(struct wccp_i_see_you_t * wccp_i_see_you)
{
    struct wccp_assign_bucket_t wccp_assign_bucket;
    int number_buckets, loop_buckets, loop, bucket, number_caches;

    debug(80, 6) ("wccpAssignBuckets: Called\n");
    memset(&wccp_assign_bucket, '\0', sizeof(wccp_assign_bucket));
    memset(&wccp_assign_bucket.bucket, 0, sizeof(wccp_assign_bucket.bucket));

    number_caches = ntohl(wccp_i_see_you->number);
    if(number_caches > WCCP_ACTIVE_CACHES)
	number_caches = WCCP_ACTIVE_CACHES;

    number_buckets = WCCP_BUCKETS/number_caches;
    bucket = 0;
    for(loop=0;loop < number_caches;loop++){
	wccp_assign_bucket.ip_addr[loop] = wccp_i_see_you->wccp_cache_entry[loop].ip_addr;
	for(loop_buckets=0;loop_buckets < number_buckets;loop_buckets++){
	    wccp_assign_bucket.bucket[bucket++] = loop;
	}
    }
    wccp_assign_bucket.type = ntohl(WCCP_ASSIGN_BUCKET);
    wccp_assign_bucket.id = wccp_i_see_you->id;
    wccp_assign_bucket.number = ntohl(number_caches);
    sendto(theOutWccpConnection,
	&wccp_assign_bucket,
	sizeof(wccp_assign_bucket),
	0,
	(struct sockaddr *) & router,
	router_len);
}
