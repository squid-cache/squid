/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* UNIX RFCNB (RFC1001/RFC1002) NetBIOS implementation
 *
 * Version 1.0
 * Session Routines ...
 *
 * Copyright (C) Richard Sharpe 1996
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

#include "squid.h"

int RFCNB_errno = 0;
int RFCNB_saved_errno = 0;
#define RFCNB_ERRNO

#include "rfcnb/std-includes.h"
#include <netinet/tcp.h>
#include "rfcnb/rfcnb-io.h"
#include "rfcnb/rfcnb-priv.h"
#include "rfcnb/rfcnb-util.h"
#include "rfcnb/rfcnb.h"

#if HAVE_STRING_H
#include <string.h>
#endif

int RFCNB_Stats[RFCNB_MAX_STATS];

RFCNB_Prot_Print_Routine *Prot_Print_Routine = NULL;   /* Pointer to protocol print routine */

/* Set up a session with a remote name. We are passed Called_Name as a
 * string which we convert to a NetBIOS name, ie space terminated, up to
 * 16 characters only if we need to. If Called_Address is not empty, then
 * we use it to connect to the remote end, but put in Called_Name ... Called
 * Address can be a DNS based name, or a TCP/IP address ...
 */

void *
RFCNB_Call(char *Called_Name, char *Calling_Name, char *Called_Address, int port)
{
    struct RFCNB_Con *con;
    struct in_addr Dest_IP;
    int Client;
    BOOL redirect;
    struct redirect_addr *redir_addr;
    char *Service_Address;

    /* Now, we really should look up the port in /etc/services ... */

    if (port == 0)
        port = RFCNB_Default_Port;

    /* Create a connection structure first */

    if ((con = (struct RFCNB_Con *) malloc(sizeof(struct RFCNB_Con))) == NULL) {        /* Error in size */

        RFCNB_errno = RFCNBE_NoSpace;
        RFCNB_saved_errno = errno;
        return (NULL);

    }
    con->fd = -0;               /* no descriptor yet */
    con->errn = 0;              /* no error yet */
    con->timeout = 0;           /* no timeout   */
    con->redirects = 0;
    con->redirect_list = con->last_addr = NULL;

    /* Resolve that name into an IP address */

    Service_Address = Called_Name;
    if (strlen(Called_Address) != 0) {      /* If the Called Address = "" */
        Service_Address = Called_Address;
    }
    if ((errno = RFCNB_Name_To_IP(Service_Address, &Dest_IP)) < 0) {    /* Error */

        /* No need to modify RFCNB_errno as it was done by RFCNB_Name_To_IP */
        free(con);
        return (NULL);

    }
    /* Now connect to the remote end */

    redirect = TRUE;            /* Fudge this one so we go once through */

    while (redirect) {          /* Connect and get session info etc */

        redirect = FALSE;       /* Assume all OK */

        /* Build the redirect info. First one is first addr called */
        /* And tack it onto the list of addresses we called        */

        if ((redir_addr = (struct redirect_addr *) malloc(sizeof(struct redirect_addr))) == NULL) {     /* Could not get space */

            RFCNB_errno = RFCNBE_NoSpace;
            RFCNB_saved_errno = errno;
            free(con);
            return (NULL);

        }
        memcpy((char *) &(redir_addr->ip_addr), (char *) &Dest_IP, sizeof(Dest_IP));
        redir_addr->port = port;
        redir_addr->next = NULL;

        if (con->redirect_list == NULL) {       /* Stick on head */

            con->redirect_list = con->last_addr = redir_addr;

        } else {

            con->last_addr->next = redir_addr;
            con->last_addr = redir_addr;

        }

        /* Now, make that connection */

        if ((Client = RFCNB_IP_Connect(Dest_IP, port)) < 0) {   /* Error */

            /* No need to modify RFCNB_errno as it was done by RFCNB_IP_Connect */
            free(con);
            return (NULL);

        }
        con->fd = Client;

        /* Now send and handle the RFCNB session request              */
        /* If we get a redirect, we will comeback with redirect true
         * and a new IP address in DEST_IP                            */

        if ((errno = RFCNB_Session_Req(con,
                                       Called_Name,
                                       Calling_Name,
                                       &redirect, &Dest_IP, &port)) < 0) {

            /* No need to modify RFCNB_errno as it was done by RFCNB_Session.. */

            RFCNB_Close(con->fd);       /* Close it */
            free(con);
            return (NULL);

        }
        if (redirect) {

            /* We have to close the connection, and then try again */

            (con->redirects)++;

            RFCNB_Close(con->fd);       /* Close it */

        }
    }

    return (con);
}

/* We send a packet to the other end ... for the moment, we treat the
 * data as a series of pointers to blocks of data ... we should check the
 * length ... */
int
RFCNB_Send(struct RFCNB_Con *Con_Handle, struct RFCNB_Pkt *udata, int Length)
{
    struct RFCNB_Pkt *pkt;
    char *hdr;
    int len;

    /* Plug in the header and send the data */

    pkt = RFCNB_Alloc_Pkt(RFCNB_Pkt_Hdr_Len);

    if (pkt == NULL) {

        RFCNB_errno = RFCNBE_NoSpace;
        RFCNB_saved_errno = errno;
        return (RFCNBE_Bad);

    }
    pkt->next = udata;          /* The user data we want to send */

    hdr = pkt->data;

    /* Following crap is for portability across multiple UNIX machines */

    *(hdr + RFCNB_Pkt_Type_Offset) = RFCNB_SESSION_MESSAGE;
    RFCNB_Put_Pkt_Len(hdr, Length);

#ifdef RFCNB_DEBUG

    fprintf(stderr, "Sending packet: ");

#endif

    if ((len = RFCNB_Put_Pkt(Con_Handle, pkt, Length + RFCNB_Pkt_Hdr_Len)) < 0) {

        /* No need to change RFCNB_errno as it was done by put_pkt ...     */

        RFCNB_Free_Pkt(pkt);
        return (RFCNBE_Bad);    /* Should be able to write that lot ... */

    }
    /* Now we have sent that lot, let's get rid of the RFCNB Header and return */

    pkt->next = NULL;

    RFCNB_Free_Pkt(pkt);

    return (len);
}

/* We pick up a message from the internet ... We have to worry about
 * non-message packets ...                                           */
int
RFCNB_Recv(void *con_Handle, struct RFCNB_Pkt *Data, int Length)
{
    struct RFCNB_Pkt *pkt;
//    struct RFCNB_Hdr *hdr;
    int ret_len;

    if (con_Handle == NULL) {

        RFCNB_errno = RFCNBE_BadHandle;
        RFCNB_saved_errno = errno;
        return (RFCNBE_Bad);

    }
    /* Now get a packet from below. We allocate a header first */

    /* Plug in the header and send the data */

    pkt = RFCNB_Alloc_Pkt(RFCNB_Pkt_Hdr_Len);

    if (pkt == NULL) {

        RFCNB_errno = RFCNBE_NoSpace;
        RFCNB_saved_errno = errno;
        return (RFCNBE_Bad);

    }
    pkt->next = Data;           /* Plug in the data portion */

    if ((ret_len = RFCNB_Get_Pkt(con_Handle, pkt, Length + RFCNB_Pkt_Hdr_Len)) < 0) {

#ifdef RFCNB_DEBUG
        fprintf(stderr, "Bad packet return in RFCNB_Recv... \n");
#endif
        RFCNB_Free_Pkt(pkt);
        return (RFCNBE_Bad);

    }
    /* We should check that we go a message and not a keep alive */

    pkt->next = NULL;

    RFCNB_Free_Pkt(pkt);

    return (ret_len);
}

/* We just disconnect from the other end, as there is nothing in the RFCNB */
/* protocol that specifies any exchange as far as I can see                */
int
RFCNB_Hangup(struct RFCNB_Con *con_Handle)
{

    if (con_Handle != NULL) {
        RFCNB_Close(con_Handle->fd);    /* Could this fail? */
        free(con_Handle);
    }
    return 0;
}

/* Set TCP_NODELAY on the socket                                          */
int
RFCNB_Set_Sock_NoDelay(struct RFCNB_Con *con_Handle, BOOL yn)
{

    return (setsockopt(con_Handle->fd, IPPROTO_TCP, TCP_NODELAY,
                       (char *) &yn, sizeof(yn)));
}

#if NOT_IMPLEMENTED
/* Listen for a connection on a port???, when                             */
/* the connection comes in, we return with the connection                 */
void *
RFCNB_Listen()
{
}

#endif

/* Pick up the last error response as a string, hmmm, this routine should */
/* have been different ...                                                */
void
RFCNB_Get_Error(char *buffer, int buf_len)
{

    if (RFCNB_saved_errno <= 0) {
        snprintf(buffer, (buf_len - 1), "%s", RFCNB_Error_Strings[RFCNB_errno]);
    } else {
        snprintf(buffer, (buf_len - 1), "%s\n\terrno:%s", RFCNB_Error_Strings[RFCNB_errno],
                 strerror(RFCNB_saved_errno));
    }
}

/* Pick up the last error response and returns as a code                 */
int
RFCNB_Get_Last_Error()
{
    return (RFCNB_errno);
}

