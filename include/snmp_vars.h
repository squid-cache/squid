/*
 * Definitions for SNMP (RFC 1067) agent variable finder.
 * and more.
 */
/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University
	Copyright 1989	TGV, Incorporated

		      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU and TGV not be used
in advertising or publicity pertaining to distribution of the software
without specific, written prior permission.

CMU AND TGV DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
EVENT SHALL CMU OR TGV BE LIABLE FOR ANY SPECIAL, INDIRECT OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

#ifndef SNMPLIB_H
#define SNMPLIB_H


#undef _ANSI_ARGS_
#if (defined(__STDC__) && ! defined(NO_PROTOTYPE)) || defined(USE_PROTOTYPE)
#define _ANSI_ARGS_(x) x
#else
#define _ANSI_ARGS_(x) ()
#endif


u_char *var_system();
u_char *var_ifEntry();
u_char *var_atEntry();
u_char *var_ip();
u_char *var_ipAddrEntry();
u_char *var_ipRouteEntry();
u_char *var_icmp();
u_char *var_tcp();
u_char *var_udp();
#ifdef linux
u_char *var_snmp();
u_char *var_id();
#endif
u_char *var_process();
u_char *var_event();
u_char *var_capture();
u_char *var_demo();
u_char *var_snmpStats();
u_char *var_usecStats();
u_char *var_usecAgent();
u_char *var_orEntry();
u_char *var_rwstats();
u_char *getStatPtr();

extern long long_return;
extern u_char return_buf[];

#define INST	0xFFFFFFFF	/* used to fill out the instance field of the variables table */

/*
 * These are unit magic numbers for each variable.
 */

#define VERSION_DESCR	0
#define VERSION_ID	1
#define IFNUMBER	2
#define UPTIME		3
#define SYSCONTACT	4
#define SYSYSNAME	5
#define SYSLOCATION	6
#define SYSSERVICES	7
#define SYSORLASTCHANGE 8

#define IFINDEX		1
#define IFDESCR		2
#define IFTYPE		3
#define IFMTU		4
#define IFSPEED		5
#define IFPHYSADDRESS	6
#define IFADMINSTATUS	7
#define IFOPERSTATUS	8
#define IFLASTCHANGE	9
#define IFINOCTETS	10
#define IFINUCASTPKTS	11
#define IFINNUCASTPKTS	12
#define IFINDISCARDS	13
#define IFINERRORS	14
#define IFINUNKNOWNPROTOS 15
#define IFOUTOCTETS	16
#define IFOUTUCASTPKTS	17
#define IFOUTNUCASTPKTS 18
#define IFOUTDISCARDS	19
#define IFOUTERRORS	20
#define IFOUTQLEN	21
#define IFSPECIFIC	22

#define ATIFINDEX	0
#define ATPHYSADDRESS	1
#define ATNETADDRESS	2

#define IPFORWARDING	0
#define IPDEFAULTTTL	1
#define IPINRECEIVES	2
#define IPINHDRERRORS	3
#define IPINADDRERRORS	4
#define IPFORWDATAGRAMS 5
#define IPINUNKNOWNPROTOS 6
#define IPINDISCARDS	7
#define IPINDELIVERS	8
#define IPOUTREQUESTS	9
#define IPOUTDISCARDS	10
#define IPOUTNOROUTES	11
#define IPREASMTIMEOUT	12
#define IPREASMREQDS	13
#define IPREASMOKS	14
#define IPREASMFAILS	15
#define IPFRAGOKS	16
#define IPFRAGFAILS	17
#define IPFRAGCREATES	18

#define IPADADDR	1
#define IPADIFINDEX	2
#define IPADNETMASK	3
#define IPADBCASTADDR	4
#define IPADENTREASMMAXSIZE	5

#ifndef linux
#define IPROUTEDEST	0
#define IPROUTEIFINDEX	1
#define IPROUTEMETRIC1	2
#define IPROUTEMETRIC2	3
#define IPROUTEMETRIC3	4
#define IPROUTEMETRIC4	5
#define IPROUTENEXTHOP	6
#define IPROUTETYPE	7
#define IPROUTEPROTO	8
#define IPROUTEAGE	9
#else
/* XXX */
#define IPROUTEDEST	1
#define IPROUTEIFINDEX	2
#define IPROUTEMETRIC1	3
#define IPROUTEMETRIC2	4
#define IPROUTEMETRIC3	5
#define IPROUTEMETRIC4	6
#define IPROUTENEXTHOP	7
#define IPROUTETYPE	8
#define IPROUTEPROTO	9
#define IPROUTEAGE	10
#define IPROUTEMASK	11
#define IPROUTEMETRIC5	12
#define IPROUTEINFO	13
#endif

#define IPNETTOMEDIAIFINDEX	1
#define IPNETTOMEDIAPHYSADDR	2
#define IPNETTOMEDIANETADDR	3
#define IPNETTOMEDIATYPE	4

#define ICMPINMSGS	     0
#define ICMPINERRORS	     1
#define ICMPINDESTUNREACHS   2
#define ICMPINTIMEEXCDS      3
#define ICMPINPARMPROBS      4
#define ICMPINSRCQUENCHS     5
#define ICMPINREDIRECTS      6
#define ICMPINECHOS	     7
#define ICMPINECHOREPS	     8
#define ICMPINTIMESTAMPS     9
#define ICMPINTIMESTAMPREPS 10
#define ICMPINADDRMASKS     11
#define ICMPINADDRMASKREPS  12
#define ICMPOUTMSGS	    13
#define ICMPOUTERRORS	    14
#define ICMPOUTDESTUNREACHS 15
#define ICMPOUTTIMEEXCDS    16
#define ICMPOUTPARMPROBS    17
#define ICMPOUTSRCQUENCHS   18
#define ICMPOUTREDIRECTS    19
#define ICMPOUTECHOS	    20
#define ICMPOUTECHOREPS     21
#define ICMPOUTTIMESTAMPS   22
#define ICMPOUTTIMESTAMPREPS 23
#define ICMPOUTADDRMASKS    24
#define ICMPOUTADDRMASKREPS 25

#define TCPRTOALGORITHM      1
#define TCPRTOMIN	     2
#define TCPRTOMAX	     3
#define TCPMAXCONN	     4
#define TCPACTIVEOPENS	     5
#define TCPPASSIVEOPENS      6
#define TCPATTEMPTFAILS      7
#define TCPESTABRESETS	     8
#define TCPCURRESTAB	     9
#define TCPINSEGS	    10
#define TCPOUTSEGS	    11
#define TCPRETRANSSEGS	    12
#define TCPCONNSTATE	    13
#define TCPCONNLOCALADDRESS 14
#define TCPCONNLOCALPORT    15
#define TCPCONNREMADDRESS   16
#define TCPCONNREMPORT	    17

#define UDPINDATAGRAMS	    0
#define UDPNOPORTS	    1
#define UDPINERRORS	    2
#define UDPOUTDATAGRAMS     3
#ifdef linux
#define UDPLOCALADDRESS	    4
#define UDPLOCALPORT	    5
#endif /* linux */

#define SNMPINPKTS		1
#define SNMPOUTPKTS		2
#define SNMPINBADVERSIONS	3
#define SNMPINBADCOMMUNITYNAMES	4
#define SNMPINBADCOMMUNITYUSES	5
#define SNMPINASNPARSEERRORS	6
#define SNMPINTOOBIGS		8
#define SNMPINNOSUCHNAMES	9
#define SNMPINBADVALUES		10
#define SNMPINREADONLYS		11
#define SNMPINGENERRS		12
#define SNMPINTOTALREQVARS	13
#define SNMPINTOTALSETVARS	14
#define SNMPINGETREQUESTS	15
#define SNMPINGETNEXTS		16
#define SNMPINSETREQUESTS	17
#define SNMPINGETRESPONSES	18
#define SNMPINTRAPS		19
#define SNMPOUTTOOBIGS		20
#define SNMPOUTNOSUCHNAMES	21
#define SNMPOUTBADVALUES	22
#define SNMPOUTGENERRS		24
#define SNMPOUTGETREQUESTS	25
#define SNMPOUTGETNEXTS		26
#define SNMPOUTSETREQUESTS	27
#define SNMPOUTGETRESPONSES	28
#define SNMPOUTTRAPS		29
#define SNMPENABLEAUTHENTRAPS	30


/*
 * for tcp-connection list access: 
 */
#include <netinet/in.h>

#ifdef linux
struct inpcb {
    struct inpcb *inp_next;	/* pointers to other pcb's */
    struct in_addr inp_faddr;	/* foreign host table entry */
    u_short inp_fport;		/* foreign port */
    struct in_addr inp_laddr;	/* local host table entry */
    u_short inp_lport;		/* local port */
    int inp_state;
    int uid;			/* owner of the connection */
};

#endif

extern void TCP_Scan_Init();
extern int TCP_Scan_Next();

typedef struct variable variable;
typedef int SNMPWM(int, u_char *, u_char, int, u_char *, oid *, int);
typedef u_char *SNMPFV(variable *, oid *, int *, int, int *, SNMPWM **);

struct variable {
    u_char magic;		/* passed to function as a hint */
    char type;			/* type of variable */
/* See important comment in snmp_vars.c relating to acl */
    u_short acl;		/* access control list for variable */
    SNMPFV *findVar;		/* function that finds variable */
    u_char namelen;		/* length of above */
    oid name[32];		/* object identifier of variable */
};

extern int compare();
extern void Interface_Scan_Init();
extern int Interface_Scan_Next();

#endif
