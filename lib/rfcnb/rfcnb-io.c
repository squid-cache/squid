/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* UNIX RFCNB (RFC1001/RFC1002) NEtBIOS implementation
 *
 * Version 1.0
 * RFCNB IO Routines ...
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
#include "rfcnb/rfcnb-io.h"
#include "rfcnb/rfcnb-priv.h"
#include "rfcnb/rfcnb-util.h"
#include "rfcnb/std-includes.h"

#if HAVE_SIGNAL_H
#include <signal.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#include <sys/uio.h>

int RFCNB_Timeout = 0;          /* Timeout in seconds ... */

static int RFCNB_Discard_Rest(struct RFCNB_Con *con, int len);

#ifdef NOT_USED
void
rfcnb_alarm(int sig)
{

    fprintf(stderr, "IO Timed out ...\n");

}

#endif /* NOT_USED */

#ifdef NOT_USED
/* Set timeout value and setup signal handling */
int
RFCNB_Set_Timeout(int seconds)
{
    /* If we are on a Bezerkeley system, use sigvec, else sigaction */

#if ORIGINAL_SAMBA_CODE
#ifndef SA_RESTART
    struct sigvec invec, outvec;
#else
    struct sigaction inact, outact;
#endif

    RFCNB_Timeout = seconds;

    if (RFCNB_Timeout > 0) {    /* Set up handler to ignore but not restart */

#ifndef SA_RESTART
        invec.sv_handler = (void (*)()) rfcnb_alarm;
        invec.sv_mask = 0;
        invec.sv_flags = SV_INTERRUPT;

        if (sigvec(SIGALRM, &invec, &outvec) < 0)
            return (-1);
#else /* !SA_RESTART */
        inact.sa_handler = (void (*)()) rfcnb_alarm;
#ifdef Solaris
        /* Solaris seems to have an array of vectors ... */
        inact.sa_mask.__sigbits[0] = 0;
        inact.sa_mask.__sigbits[1] = 0;
        inact.sa_mask.__sigbits[2] = 0;
        inact.sa_mask.__sigbits[3] = 0;
#else /* !Solaris */
        inact.sa_mask = (sigset_t) 0;
#endif /* Solaris */
        inact.sa_flags = 0;     /* Don't restart */

        if (sigaction(SIGALRM, &inact, &outact) < 0)
            return (-1);

#endif /* !SA_RESTART */

    }
#else /* !ORIGINAL_SAMBA_CODE ADAPTED SQUID CODE */
#if HAVE_SIGACTION
    struct sigaction inact, outact;
#else
    struct sigvec invec, outvec;
#endif

    RFCNB_Timeout = seconds;

    if (RFCNB_Timeout > 0) {    /* Set up handler to ignore but not restart */

#if HAVE_SIGACTION
        inact.sa_handler = (void (*)()) rfcnb_alarm;
        sigemptyset(&inact.sa_mask);
        inact.sa_flags = 0;     /* Don't restart */

        if (sigaction(SIGALRM, &inact, &outact) < 0)
            return (-1);
#else /* !HAVE_SIGACTION */
        invec.sv_handler = (void (*)()) rfcnb_alarm;
        invec.sv_mask = 0;
        invec.sv_flags = SV_INTERRUPT;

        if (sigvec(SIGALRM, &invec, &outvec) < 0)
            return (-1);
#endif /* !HAVE_SIGACTION */
    }
#endif /* !ORIGINAL_SAMBA_CODE ADAPTED SQUID CODE */
    return (0);
}
#endif /* NOT_USED */

/* Discard the rest of an incoming packet as we do not have space for it
 * in the buffer we allocated or were passed ...                         */

int
RFCNB_Discard_Rest(struct RFCNB_Con *con, int len)
{
    char temp[100];             /* Read into here */
    int rest, this_read, bytes_read;

    /* len is the amount we should read */

#ifdef RFCNB_DEBUG
    fprintf(stderr, "Discard_Rest called to discard: %i\n", len);
#endif

    rest = len;

    while (rest > 0) {

        this_read = (rest > sizeof(temp) ? sizeof(temp) : rest);

        bytes_read = read(con->fd, temp, this_read);

        if (bytes_read <= 0) {  /* Error so return */

            if (bytes_read < 0)
                RFCNB_errno = RFCNBE_BadRead;
            else
                RFCNB_errno = RFCNBE_ConGone;

            RFCNB_saved_errno = errno;
            return (RFCNBE_Bad);

        }
        rest = rest - bytes_read;

    }

    return (0);

}

/* Send an RFCNB packet to the connection.
 *
 * We just send each of the blocks linked together ...
 *
 * If we can, try to send it as one iovec ...
 *
 */

int
RFCNB_Put_Pkt(struct RFCNB_Con *con, struct RFCNB_Pkt *pkt, int len)
{
    int len_sent, tot_sent, this_len;
    struct RFCNB_Pkt *pkt_ptr;
    char *this_data;
    int i;
    struct iovec io_list[10];   /* We should never have more      */
    /* If we do, this will blow up ... */

    /* Try to send the data ... We only send as many bytes as len claims */
    /* We should try to stuff it into an IOVEC and send as one write     */

    pkt_ptr = pkt;
    len_sent = tot_sent = 0;    /* Nothing sent so far */
    i = 0;

    while ((pkt_ptr != NULL) & (i < 10)) {      /* Watch that magic number! */

        this_len = pkt_ptr->len;
        this_data = pkt_ptr->data;
        if ((tot_sent + this_len) > len)
            this_len = len - tot_sent;  /* Adjust so we don't send too much */

        /* Now plug into the iovec ... */

        io_list[i].iov_len = this_len;
        io_list[i].iov_base = this_data;
        i++;

        tot_sent += this_len;

        if (tot_sent == len)
            break;              /* Let's not send too much */

        pkt_ptr = pkt_ptr->next;

    }

#ifdef RFCNB_DEBUG
    fprintf(stderr, "Frags = %i, tot_sent = %i\n", i, tot_sent);
#endif

    /* Set up an alarm if timeouts are set ... */

    if (RFCNB_Timeout > 0)
        alarm(RFCNB_Timeout);

    if ((len_sent = writev(con->fd, io_list, i)) < 0) {         /* An error */

        con->errn = errno;
        if (errno == EINTR)     /* We were interrupted ... */
            RFCNB_errno = RFCNBE_Timeout;
        else
            RFCNB_errno = RFCNBE_BadWrite;
        RFCNB_saved_errno = errno;
        return (RFCNBE_Bad);

    }
    if (len_sent < tot_sent) {  /* Less than we wanted */
        if (errno == EINTR)     /* We were interrupted */
            RFCNB_errno = RFCNBE_Timeout;
        else
            RFCNB_errno = RFCNBE_BadWrite;
        RFCNB_saved_errno = errno;
        return (RFCNBE_Bad);
    }
    if (RFCNB_Timeout > 0)
        alarm(0);               /* Reset that sucker */

#ifdef RFCNB_DEBUG

    fprintf(stderr, "Len sent = %i ...\n", len_sent);
    RFCNB_Print_Pkt(stderr, "sent", pkt, len_sent);     /* Print what send ... */

#endif

    return (len_sent);

}

/* Read an RFCNB packet off the connection.
 *
 * We read the first 4 bytes, that tells us the length, then read the
 * rest. We should implement a timeout, but we don't just yet
 *
 */

int
RFCNB_Get_Pkt(struct RFCNB_Con *con, struct RFCNB_Pkt *pkt, int len)
{
    int read_len, pkt_len;
    char hdr[RFCNB_Pkt_Hdr_Len];        /* Local space for the header */
    struct RFCNB_Pkt *pkt_frag;
    int more, this_time, offset, frag_len, this_len;
    BOOL seen_keep_alive = TRUE;

    /* Read that header straight into the buffer */

    if (len < RFCNB_Pkt_Hdr_Len) {      /* What a bozo */

#ifdef RFCNB_DEBUG
        fprintf(stderr, "Trying to read less than a packet:");
        perror("");
#endif
        RFCNB_errno = RFCNBE_BadParam;
        return (RFCNBE_Bad);

    }
    /* We discard keep alives here ... */

    if (RFCNB_Timeout > 0)
        alarm(RFCNB_Timeout);

    while (seen_keep_alive) {

        if ((read_len = read(con->fd, hdr, sizeof(hdr))) < 0) {         /* Problems */
#ifdef RFCNB_DEBUG
            fprintf(stderr, "Reading the packet, we got:");
            perror("");
#endif
            if (errno == EINTR)
                RFCNB_errno = RFCNBE_Timeout;
            else
                RFCNB_errno = RFCNBE_BadRead;
            RFCNB_saved_errno = errno;
            return (RFCNBE_Bad);

        }
        /* Now we check out what we got */

        if (read_len == 0) {    /* Connection closed, send back eof?  */

#ifdef RFCNB_DEBUG
            fprintf(stderr, "Connection closed reading\n");
#endif

            if (errno == EINTR)
                RFCNB_errno = RFCNBE_Timeout;
            else
                RFCNB_errno = RFCNBE_ConGone;
            RFCNB_saved_errno = errno;
            return (RFCNBE_Bad);

        }
        if (RFCNB_Pkt_Type(hdr) == RFCNB_SESSION_KEEP_ALIVE) {

#ifdef RFCNB_DEBUG
            fprintf(stderr, "RFCNB KEEP ALIVE received\n");
#endif

        } else {
            seen_keep_alive = FALSE;
        }

    }

    /* What if we got less than or equal to a hdr size in bytes? */

    if (read_len < sizeof(hdr)) {       /* We got a small packet */

        /* Now we need to copy the hdr portion we got into the supplied packet */

        memcpy(pkt->data, hdr, read_len);       /*Copy data */

#ifdef RFCNB_DEBUG
        RFCNB_Print_Pkt(stderr, "rcvd", pkt, read_len);
#endif

        return (read_len);

    }
    /* Now, if we got at least a hdr size, alloc space for rest, if we need it */

    pkt_len = RFCNB_Pkt_Len(hdr);

#ifdef RFCNB_DEBUG
    fprintf(stderr, "Reading Pkt: Length = %i\n", pkt_len);
#endif

    /* Now copy in the hdr */

    memcpy(pkt->data, hdr, sizeof(hdr));

    /* Get the rest of the packet ... first figure out how big our buf is? */
    /* And make sure that we handle the fragments properly ... Sure should */
    /* use an iovec ...                                                    */

    if (len < pkt_len)          /* Only get as much as we have space for */
        more = len - RFCNB_Pkt_Hdr_Len;
    else
        more = pkt_len;

    this_time = 0;

    /* We read for each fragment ... */

    if (pkt->len == read_len) { /* If this frag was exact size */
        pkt_frag = pkt->next;   /* Stick next lot in next frag */
        offset = 0;             /* then we start at 0 in next  */
    } else {
        pkt_frag = pkt;         /* Otherwise use rest of this frag */
        offset = RFCNB_Pkt_Hdr_Len;     /* Otherwise skip the header       */
    }

    frag_len = (pkt_frag ? pkt_frag->len : 0);

    if (more <= frag_len)       /* If len left to get less than frag space */
        this_len = more;        /* Get the rest ...                        */
    else
        this_len = frag_len - offset;

    while (more > 0) {

        if ((this_time = read(con->fd, (pkt_frag->data) + offset, this_len)) <= 0) {    /* Problems */

            if (errno == EINTR) {

                RFCNB_errno = RFCNB_Timeout;

            } else {
                if (this_time < 0)
                    RFCNB_errno = RFCNBE_BadRead;
                else
                    RFCNB_errno = RFCNBE_ConGone;
            }

            RFCNB_saved_errno = errno;
            return (RFCNBE_Bad);

        }
#ifdef RFCNB_DEBUG
        fprintf(stderr, "Frag_Len = %i, this_time = %i, this_len = %i, more = %i\n", frag_len,
                this_time, this_len, more);
#endif

        read_len = read_len + this_time;        /* How much have we read ... */

        /* Now set up the next part */

        if (pkt_frag->next == NULL)
            break;              /* That's it here */

        pkt_frag = pkt_frag->next;
        this_len = pkt_frag->len;
        offset = 0;

        more = more - this_time;

    }

#ifdef RFCNB_DEBUG
    fprintf(stderr, "Pkt Len = %i, read_len = %i\n", pkt_len, read_len);
    RFCNB_Print_Pkt(stderr, "rcvd", pkt, read_len + sizeof(hdr));
#endif

    if (read_len < (pkt_len + sizeof(hdr))) {   /* Discard the rest */

        return (RFCNB_Discard_Rest(con, (pkt_len + sizeof(hdr)) - read_len));

    }
    if (RFCNB_Timeout > 0)
        alarm(0);               /* Reset that sucker */

    return (read_len + sizeof(RFCNB_Hdr));
}

