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
 * RFCNB Defines
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

#ifndef _RFCNB_RFCNB_H
#define _RFCNB_RFCNB_H

/* Error responses */

#include "rfcnb/rfcnb-common.h"
#include "rfcnb/rfcnb-error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Defines we need */

#define RFCNB_Default_Port 139

struct RFCNB_Con;

/* Definition of routines we define */

void *RFCNB_Call(char *Called_Name, char *Calling_Name, char *Called_Address,
                 int port);

int RFCNB_Send(struct RFCNB_Con *Con_Handle, struct RFCNB_Pkt *udata, int Length);

int RFCNB_Recv(void *Con_Handle, struct RFCNB_Pkt *Data, int Length);

int RFCNB_Hangup(struct RFCNB_Con *con_Handle);

void *RFCNB_Listen(void);

void RFCNB_Get_Error(char *buffer, int buf_len);

int RFCNB_Get_Last_Error(void);

void RFCNB_Free_Pkt(struct RFCNB_Pkt *pkt);

int RFCNB_Set_Sock_NoDelay(struct RFCNB_Con *con_Handle, int yn);

struct RFCNB_Pkt *RFCNB_Alloc_Pkt(int n);

#ifdef __cplusplus
}

#endif
#endif                          /* _RFCNB_RFCNB_H */

