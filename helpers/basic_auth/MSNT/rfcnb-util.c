/* UNIX RFCNB (RFC1001/RFC1002) NetBIOS implementation
 * 
 * Version 1.0
 * RFCNB Utility Routines ...
 * 
 * Copyright (C) Richard Sharpe 1996
 * 
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "std-includes.h"
#include "rfcnb-priv.h"
#include "rfcnb-util.h"
#include "rfcnb-io.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

const char *RFCNB_Error_Strings[] =
{

    "RFCNBE_OK: Routine completed successfully.",
    "RFCNBE_NoSpace: No space available for a malloc call.",
    "RFCNBE_BadName: NetBIOS name could not be translated to IP address.",
    "RFCNBE_BadRead: Read system call returned an error. Check errno.",
    "RFCNBE_BadWrite: Write system call returned an error. Check errno.",
    "RFCNBE_ProtErr: A protocol error has occurred.",
    "RFCNBE_ConGone: Connection dropped during a read or write system call.",
    "RFCNBE_BadHandle: Bad connection handle passed.",
    "RFCNBE_BadSocket: Problems creating socket.",
    "RFCNBE_ConnectFailed: Connection failed. See errno.",
    "RFCNBE_CallRejNLOCN: Call rejected. Not listening on called name.",
    "RFCNBE_CallRejNLFCN: Call rejected. Not listening for called name.",
    "RFCNBE_CallRejCNNP: Call rejected. Called name not present.",
    "RFCNBE_CallRejInfRes: Call rejected. Name present, but insufficient resources.",
    "RFCNBE_CallRejUnSpec: Call rejected. Unspecified error.",
    "RFCNBE_BadParam: Bad parameters passed to a routine.",
    "RFCNBE_Timeout: IO Operation timed out ..."

};

#ifdef RFCNB_DEBUG
extern void (*Prot_Print_Routine) ();	/* Pointer to protocol print routine */
#endif

/* Convert name and pad to 16 chars as needed */
/* Name 1 is a C string with null termination, name 2 may not be */
/* If SysName is true, then put a <00> on end, else space>       */

void
RFCNB_CvtPad_Name(char *name1, char *name2)
{
    char c, c1, c2;
    int i, len;

    len = strlen(name1);

    for (i = 0; i < 16; i++) {

	if (i >= len) {

	    c1 = 'C';
	    c2 = 'A';		/* CA is a space */

	} else {

	    c = name1[i];
	    c1 = (char) ((int) c / 16 + (int) 'A');
	    c2 = (char) ((int) c % 16 + (int) 'A');
	}

	name2[i * 2] = c1;
	name2[i * 2 + 1] = c2;

    }

    name2[32] = 0;		/* Put in the nll ... */

}

/* Converts an Ascii NB Name (16 chars) to an RFCNB Name (32 chars)
 * Uses the encoding in RFC1001. Each nibble of byte is added to 'A'
 * to produce the next byte in the name.
 * 
 * This routine assumes that AName is 16 bytes long and that NBName has 
 * space for 32 chars, so be careful ... 
 * 
 */

void
RFCNB_AName_To_NBName(char *AName, char *NBName)
{
    char c, c1, c2;
    int i;

    for (i = 0; i < 16; i++) {

	c = AName[i];

	c1 = (char) ((c >> 4) + 'A');
	c2 = (char) ((c & 0xF) + 'A');

	NBName[i * 2] = c1;
	NBName[i * 2 + 1] = c2;
    }

    NBName[32] = 0;		/* Put in a null */

}

/* Do the reverse of the above ... */

void
RFCNB_NBName_To_AName(char *NBName, char *AName)
{
    char c, c1, c2;
    int i;

    for (i = 0; i < 16; i++) {

	c1 = NBName[i * 2];
	c2 = NBName[i * 2 + 1];

	c = (char) (((int) c1 - (int) 'A') * 16 + ((int) c2 - (int) 'A'));

	AName[i] = c;

    }

    AName[i] = 0;		/* Put a null on the end ... */

}

#ifdef RFCNB_DEBUG
/* Print a string of bytes in HEX etc */

void
RFCNB_Print_Hex(FILE * fd, struct RFCNB_Pkt *pkt, int Offset, int Len)
{
    char c1, c2, outbuf1[33];
    unsigned char c;
    int i, j;
    struct RFCNB_Pkt *pkt_ptr = pkt;
    static char Hex_List[17] = "0123456789ABCDEF";

    j = 0;

    /* We only want to print as much as sepcified in Len */

    while (pkt_ptr != NULL) {

	for (i = 0;
	    i < ((Len > (pkt_ptr->len) ? pkt_ptr->len : Len) - Offset);
	    i++) {

	    c = pkt_ptr->data[i + Offset];
	    c1 = Hex_List[c >> 4];
	    c2 = Hex_List[c & 0xF];

	    outbuf1[j++] = c1;
	    outbuf1[j++] = c2;

	    if (j == 32) {	/* Print and reset */
		outbuf1[j] = 0;
		fprintf(fd, "    %s\n", outbuf1);
		j = 0;
	    }
	}

	Offset = 0;
	Len = Len - pkt_ptr->len;	/* Reduce amount by this much */
	pkt_ptr = pkt_ptr->next;

    }

    /* Print last lot in the buffer ... */

    if (j > 0) {

	outbuf1[j] = 0;
	fprintf(fd, "    %s\n", outbuf1);

    }
    fprintf(fd, "\n");

}
#endif

/* Get a packet of size n */

struct RFCNB_Pkt *
RFCNB_Alloc_Pkt(int n)
{
    RFCNB_Pkt *pkt;

    if ((pkt = malloc(sizeof(struct RFCNB_Pkt))) == NULL) {
	RFCNB_errno = RFCNBE_NoSpace;
	RFCNB_saved_errno = errno;
	return (NULL);
    }
    pkt->next = NULL;
    pkt->len = n;

    if (n == 0)
	return (pkt);

    if ((pkt->data = malloc(n)) == NULL) {
	RFCNB_errno = RFCNBE_NoSpace;
	RFCNB_saved_errno = errno;
	free(pkt);
	return (NULL);
    }
    return (pkt);

}

/* Free up a packet */

void
RFCNB_Free_Pkt(struct RFCNB_Pkt *pkt)
{
    struct RFCNB_Pkt *pkt_next;

    while (pkt != NULL) {

	pkt_next = pkt->next;

	if (pkt->data != NULL)
	    free(pkt->data);

	free(pkt);

	pkt = pkt_next;

    }

}

#ifdef RFCNB_DEBUG
/* Print an RFCNB packet */

void
RFCNB_Print_Pkt(FILE * fd, char *dirn, struct RFCNB_Pkt *pkt, int len)
{
    char lname[17];

    /* We assume that the first fragment is the RFCNB Header  */
    /* We should loop through the fragments printing them out */

    fprintf(fd, "RFCNB Pkt %s:", dirn);

    switch (RFCNB_Pkt_Type(pkt->data)) {

    case RFCNB_SESSION_MESSAGE:

	fprintf(fd, "SESSION MESSAGE: Length = %i\n", RFCNB_Pkt_Len(pkt->data));
	RFCNB_Print_Hex(fd, pkt, RFCNB_Pkt_Hdr_Len,
#ifdef RFCNB_PRINT_DATA
	    RFCNB_Pkt_Len(pkt->data) - RFCNB_Pkt_Hdr_Len);
#else
	    40);
#endif

	if (Prot_Print_Routine != 0) {	/* Print the rest of the packet */

	    Prot_Print_Routine(fd, strcmp(dirn, "sent"), pkt, RFCNB_Pkt_Hdr_Len,
		RFCNB_Pkt_Len(pkt->data) - RFCNB_Pkt_Hdr_Len);

	}
	break;

    case RFCNB_SESSION_REQUEST:

	fprintf(fd, "SESSION REQUEST: Length = %i\n",
	    RFCNB_Pkt_Len(pkt->data));
	RFCNB_NBName_To_AName((char *) (pkt->data + RFCNB_Pkt_Called_Offset), lname);
	fprintf(fd, "  Called Name: %s\n", lname);
	RFCNB_NBName_To_AName((char *) (pkt->data + RFCNB_Pkt_Calling_Offset), lname);
	fprintf(fd, "  Calling Name: %s\n", lname);

	break;

    case RFCNB_SESSION_ACK:

	fprintf(fd, "RFCNB SESSION ACK: Length = %i\n",
	    RFCNB_Pkt_Len(pkt->data));

	break;

    case RFCNB_SESSION_REJ:
	fprintf(fd, "RFCNB SESSION REJECT: Length = %i\n",
	    RFCNB_Pkt_Len(pkt->data));

	if (RFCNB_Pkt_Len(pkt->data) < 1) {
	    fprintf(fd, "   Protocol Error, short Reject packet!\n");
	} else {
	    fprintf(fd, "   Error = %x\n", CVAL(pkt->data, RFCNB_Pkt_Error_Offset));
	}

	break;

    case RFCNB_SESSION_RETARGET:

	fprintf(fd, "RFCNB SESSION RETARGET: Length = %i\n",
	    RFCNB_Pkt_Len(pkt->data));

	/* Print out the IP address etc and the port? */

	break;

    case RFCNB_SESSION_KEEP_ALIVE:

	fprintf(fd, "RFCNB SESSION KEEP ALIVE: Length = %i\n",
	    RFCNB_Pkt_Len(pkt->data));
	break;

    default:

	break;
    }

}
#endif

/* Resolve a name into an address */

int
RFCNB_Name_To_IP(char *host, struct in_addr *Dest_IP)
{
    int addr;			/* Assumes IP4, 32 bit network addresses */
    struct hostent *hp;

    /* Use inet_addr to try to convert the address */

    if ((addr = inet_addr(host)) == INADDR_NONE) {	/* Oh well, a good try :-) */

	/* Now try a name look up with gethostbyname */

	if ((hp = gethostbyname(host)) == NULL) {	/* Not in DNS */

	    /* Try NetBIOS name lookup, how the hell do we do that? */

	    RFCNB_errno = RFCNBE_BadName;	/* Is this right? */
	    RFCNB_saved_errno = errno;
	    return (RFCNBE_Bad);

	} else {		/* We got a name */

	    memcpy((void *) Dest_IP, (void *) hp->h_addr_list[0], sizeof(struct in_addr));

	}
    } else {			/* It was an IP address */

	memcpy((void *) Dest_IP, (void *) &addr, sizeof(struct in_addr));

    }

    return 0;

}

/* Disconnect the TCP connection to the server */

int
RFCNB_Close(int socket)
{

    close(socket);

    /* If we want to do error recovery, here is where we put it */

    return 0;

}

/* Connect to the server specified in the IP address.
 * Not sure how to handle socket options etc.         */

int
RFCNB_IP_Connect(struct in_addr Dest_IP, int port)
{
    struct sockaddr_in Socket;
    int fd;

    /* Create a socket */

    if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {	/* Handle the error */

	RFCNB_errno = RFCNBE_BadSocket;
	RFCNB_saved_errno = errno;
	return (RFCNBE_Bad);
    }
    memset((char *) &Socket, 0, sizeof(Socket));
    memcpy((char *) &Socket.sin_addr, (char *) &Dest_IP, sizeof(Dest_IP));

    Socket.sin_port = htons(port);
    Socket.sin_family = PF_INET;

    /* Now connect to the destination */

    if (connect(fd, (struct sockaddr *) &Socket, sizeof(Socket)) < 0) {		/* Error */

	close(fd);
	RFCNB_errno = RFCNBE_ConnectFailed;
	RFCNB_saved_errno = errno;
	return (RFCNBE_Bad);
    }
    return (fd);

}

/* handle the details of establishing the RFCNB session with remote 
 * end 
 * 
 */

int
RFCNB_Session_Req(struct RFCNB_Con *con,
    char *Called_Name,
    char *Calling_Name,
    BOOL * redirect,
    struct in_addr *Dest_IP,
    int *port)
{
    char *sess_pkt;

    /* Response packet should be no more than 9 bytes, make 16 jic */

    char resp[16];
    int len;
    struct RFCNB_Pkt *pkt, res_pkt;

    /* We build and send the session request, then read the response */

    pkt = RFCNB_Alloc_Pkt(RFCNB_Pkt_Sess_Len);

    if (pkt == NULL) {

	return (RFCNBE_Bad);	/* Leave the error that RFCNB_Alloc_Pkt gives) */

    }
    sess_pkt = pkt->data;	/* Get pointer to packet proper */

    sess_pkt[RFCNB_Pkt_Type_Offset] = RFCNB_SESSION_REQUEST;
    RFCNB_Put_Pkt_Len(sess_pkt, (RFCNB_Pkt_Sess_Len - RFCNB_Pkt_Hdr_Len));
    sess_pkt[RFCNB_Pkt_N1Len_Offset] = 32;
    sess_pkt[RFCNB_Pkt_N2Len_Offset] = 32;

    RFCNB_CvtPad_Name(Called_Name, (sess_pkt + RFCNB_Pkt_Called_Offset));
    RFCNB_CvtPad_Name(Calling_Name, (sess_pkt + RFCNB_Pkt_Calling_Offset));

    /* Now send the packet */

#ifdef RFCNB_DEBUG

    fprintf(stderr, "Sending packet: ");

#endif

    if ((len = RFCNB_Put_Pkt(con, pkt, RFCNB_Pkt_Sess_Len)) < 0) {

	return (RFCNBE_Bad);	/* Should be able to write that lot ... */

    }
#ifdef RFCNB_DEBUG

    fprintf(stderr, "Getting packet.\n");

#endif

    res_pkt.data = resp;
    res_pkt.len = sizeof(resp);
    res_pkt.next = NULL;

    if ((len = RFCNB_Get_Pkt(con, &res_pkt, sizeof(resp))) < 0) {

	return (RFCNBE_Bad);

    }
    /* Now analyze the packet ... */

    switch (RFCNB_Pkt_Type(resp)) {

    case RFCNB_SESSION_REJ:	/* Didnt like us ... too bad */

	/* Why did we get rejected ? */

	switch (CVAL(resp, RFCNB_Pkt_Error_Offset)) {

	case 0x80:
	    RFCNB_errno = RFCNBE_CallRejNLOCN;
	    break;
	case 0x81:
	    RFCNB_errno = RFCNBE_CallRejNLFCN;
	    break;
	case 0x82:
	    RFCNB_errno = RFCNBE_CallRejCNNP;
	    break;
	case 0x83:
	    RFCNB_errno = RFCNBE_CallRejInfRes;
	    break;
	case 0x8F:
	    RFCNB_errno = RFCNBE_CallRejUnSpec;
	    break;
	default:
	    RFCNB_errno = RFCNBE_ProtErr;
	    break;
	}

	return (RFCNBE_Bad);
	break;

    case RFCNB_SESSION_ACK:	/* Got what we wanted ...      */

	return (0);
	break;

    case RFCNB_SESSION_RETARGET:	/* Go elsewhere                */

	*redirect = TRUE;	/* Copy port and ip addr       */

	memcpy(Dest_IP, (resp + RFCNB_Pkt_IP_Offset), sizeof(struct in_addr));
	*port = SVAL(resp, RFCNB_Pkt_Port_Offset);

	return (0);
	break;

    default:			/* A protocol error */

	RFCNB_errno = RFCNBE_ProtErr;
	return (RFCNBE_Bad);
	break;
    }
}
