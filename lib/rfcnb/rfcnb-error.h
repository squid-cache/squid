/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* UNIX RFCNB (RFC1001/RFC1002) NetBIOS implementation
 *
 * Version 1.0
 * RFCNB Error Response Defines
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

#ifndef _RFCNB_ERROR_H_
#define _RFCNB_ERROR_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Error responses */

#define RFCNBE_Bad -1           /* Bad response */
#define RFCNBE_OK 0

/* these should follow the spec ... is there one ? */

#define RFCNBE_NoSpace 1        /* Could not allocate space for a struct */
#define RFCNBE_BadName 2        /* Could not translate a name            */
#define RFCNBE_BadRead 3        /* Read sys call failed                  */
#define RFCNBE_BadWrite 4       /* Write Sys call failed                 */
#define RFCNBE_ProtErr 5        /* Protocol Error                        */
#define RFCNBE_ConGone 6        /* Connection dropped                    */
#define RFCNBE_BadHandle 7      /* Handle passed was bad                 */
#define RFCNBE_BadSocket 8      /* Problems creating socket              */
#define RFCNBE_ConnectFailed 9  /* Connect failed                        */
#define RFCNBE_CallRejNLOCN 10  /* Call rejected, not listening on CN    */
#define RFCNBE_CallRejNLFCN 11  /* Call rejected, not listening for CN   */
#define RFCNBE_CallRejCNNP  12  /* Call rejected, called name not present */
#define RFCNBE_CallRejInfRes 13 /* Call rejetced, name ok, no resources   */
#define RFCNBE_CallRejUnSpec 14 /* Call rejected, unspecified error      */
#define RFCNBE_BadParam      15 /* Bad parameters passed ...             */
#define RFCNBE_Timeout       16 /* IO Timed out                          */

/* Text strings for the error responses                                 */

extern const char *RFCNB_Error_Strings[];

#ifdef __cplusplus
}

#endif
#endif                          /* _RFCNB_ERROR_H_ */

