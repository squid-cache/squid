/*
 * DEBUG: section 80    WCCP Support
 * AUTHOR: Steven Wilton
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


#ifndef SQUID_WCCP2_H_
#define SQUID_WCCP2_H_

#if USE_WCCPv2

class StoreEntry;

extern void wccp2Init(void);
extern void wccp2ConnectionOpen(void);
extern void wccp2ConnectionClose(void);
extern void parse_wccp2_method(int *v);
extern void free_wccp2_method(int *v);
extern void dump_wccp2_method(StoreEntry * e, const char *label, int v);
extern void parse_wccp2_amethod(int *v);
extern void free_wccp2_amethod(int *v);
extern void dump_wccp2_amethod(StoreEntry * e, const char *label, int v);

extern void parse_wccp2_service(void *v);
extern void free_wccp2_service(void *v);
extern void dump_wccp2_service(StoreEntry * e, const char *label, void *v);

extern int check_null_wccp2_service(void *v);

extern void parse_wccp2_service_info(void *v);

extern void free_wccp2_service_info(void *v);

extern void dump_wccp2_service_info(StoreEntry * e, const char *label, void *v);
#endif /* USE_WCCPv2 */

#endif /* WCCP2_H_ */
