static char rcsid[] = "$Id: mime.cc,v 1.1 1996/02/22 06:23:55 wessels Exp $";
/* 
 *  File:         mime.c
 *  Description:  Mime Module 
 *  Author:       Anawat Chankhunthod, USC
 *  Created:      Mon Dec 12 16:09:40 PST 1994
 *  Language:     C
 **********************************************************************
 *  Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *    The Harvest software was developed by the Internet Research Task
 *    Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *          Mic Bowman of Transarc Corporation.
 *          Peter Danzig of the University of Southern California.
 *          Darren R. Hardy of the University of Colorado at Boulder.
 *          Udi Manber of the University of Arizona.
 *          Michael F. Schwartz of the University of Colorado at Boulder.
 *          Duane Wessels of the University of Colorado at Boulder.
 *  
 *    This copyright notice applies to software in the Harvest
 *    ``src/'' directory only.  Users should consult the individual
 *    copyright notices in the ``components/'' subdirectories for
 *    copyright information about other software bundled with the
 *    Harvest source code distribution.
 *  
 *  TERMS OF USE
 *    
 *    The Harvest software may be used and re-distributed without
 *    charge, provided that the software origin and research team are
 *    cited in any use of the system.  Most commonly this is
 *    accomplished by including a link to the Harvest Home Page
 *    (http://harvest.cs.colorado.edu/) from the query page of any
 *    Broker you deploy, as well as in the query result pages.  These
 *    links are generated automatically by the standard Broker
 *    software distribution.
 *    
 *    The Harvest software is provided ``as is'', without express or
 *    implied warranty, and with no support nor obligation to assist
 *    in its use, correction, modification or enhancement.  We assume
 *    no liability with respect to the infringement of copyrights,
 *    trade secrets, or any patents, and are not responsible for
 *    consequential damages.  Proper use of the Harvest software is
 *    entirely the responsibility of the user.
 *  
 *  DERIVATIVE WORKS
 *  
 *    Users may make derivative works from the Harvest software, subject 
 *    to the following constraints:
 *  
 *      - You must include the above copyright notice and these 
 *        accompanying paragraphs in all forms of derivative works, 
 *        and any documentation and other materials related to such 
 *        distribution and use acknowledge that the software was 
 *        developed at the above institutions.
 *  
 *      - You must notify IRTF-RD regarding your distribution of 
 *        the derivative work.
 *  
 *      - You must clearly notify users that your are distributing 
 *        a modified version and not the original Harvest software.
 *  
 *      - Any derivative product is also subject to these copyright 
 *        and use restrictions.
 *  
 *    Note that the Harvest software is NOT in the public domain.  We
 *    retain copyright, as specified above.
 *  
 *  HISTORY OF FREE SOFTWARE STATUS
 *  
 *    Originally we required sites to license the software in cases
 *    where they were going to build commercial products/services
 *    around Harvest.  In June 1995 we changed this policy.  We now
 *    allow people to use the core Harvest software (the code found in
 *    the Harvest ``src/'' directory) for free.  We made this change
 *    in the interest of encouraging the widest possible deployment of
 *    the technology.  The Harvest software is really a reference
 *    implementation of a set of protocols and formats, some of which
 *    we intend to standardize.  We encourage commercial
 *    re-implementations of code complying to this set of standards.  
 *  
 *  
 */
#include "config.h"
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

#include "ansihelp.h"		/* goes first */
#include "debug.h"
#include "mime.h"
#include "mime_table.h"

extern time_t cached_curtime;

int mime_refresh_request(mime)
     char *mime;
{
    if (strstr(mime, "no-cache"))
	return 1;

    return 0;
}

ext_table_entry *
                mime_ext_to_type(extension)
     char *extension;
{
    int i, low, high, comp;
    char ext[16], *cp;

    if (!extension || strlen(extension) >= (sizeof(ext) - 1))
	return NULL;
    strcpy(ext, extension);
    for (cp = ext; *cp; cp++)
	if (isupper(*cp))
	    *cp = tolower(*cp);
    low = 0;
    high = EXT_TABLE_LEN - 1;
    while (low <= high) {
	i = (low + high) / 2;
	if ((comp = strcmp(ext, ext_mime_table[i].name)) == 0)
	    return &ext_mime_table[i];
	if (comp > 0)
	    low = i + 1;
	else
	    high = i - 1;
    }
    return NULL;
}

/*
 *  mk_mime_hdr - Generates a MIME header using the given parameters.
 *  You can call mk_mime_hdr with a 'lmt = time(NULL) - ttl' to
 *  generate a fake Last-Modified-Time for the header.
 *  'ttl' is the number of seconds relative to the current time
 *  that the object is valid.
 *
 *  Returns the MIME header in the provided 'result' buffer, and
 *  returns non-zero on error, or 0 on success.
 */
int mk_mime_hdr(result, ttl, size, lmt, type)
     char *result, *type;
     int size;
     time_t ttl, lmt;
{
    extern char *mkrfc850();
    time_t expiretime;
    time_t t;
    char date[100];
    char expire[100];
    char last_modified_time[100];

    if (result == NULL)
	return 1;

    t = cached_curtime;
    expiretime = t + ttl;

    date[0] = expire[0] = last_modified_time[0] = result[0] = '\0';
    strncpy(date, mkrfc850(&t), 100);
    strncpy(expire, mkrfc850(&expiretime), 100);
    strncpy(last_modified_time, mkrfc850(&lmt), 100);

    sprintf(result, "Content-Type: %s\r\nContent-Size: %d\r\nDate: %s\r\nExpires: %s\r\nLast-Modified-Time: %s\r\n", type, size, date, expire, last_modified_time);
    return 0;
}
