static char rcsid[] = "$Id: url.cc,v 1.1 1996/02/22 06:23:56 wessels Exp $";
/* 
 *  File:         url.c
 *  Description:  General Routine for url processing
 *  Author:       Anawat Chankhunthod, USC
 *  Created:      Tue May 24 
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "comm.h"
#include "proto.h"
#include "store.h"		/* for the_url() */
#include "url.h"
#include "util.h"


int url_acceptable[256];
int url_acceptable_init = 0;
char hex[17] = "0123456789abcdef";

/* convert %xx in url string to a character 
 * Allocate a new string and return a pointer to converted string */

char *url_convert_hex(org_url)
     char *org_url;
{
    int i;
    char temp[MAX_URL], hexstr[MAX_URL];
    static char *url;

    url = (char *) xcalloc(1, MAX_URL);
    strncpy(url, org_url, MAX_URL);

    i = 0;
    while (i < (int) (strlen(url) - 2)) {
	if (url[i] == '%') {
	    /* found %xx, convert it to char */
	    strncpy(temp, url, i);
	    strncpy(hexstr, url + i + 1, 2);
	    hexstr[2] = '\0';
	    temp[i] = (char) ((int) strtol(hexstr, (char **) NULL, 16));
	    temp[i + 1] = '\0';
	    strncat(temp, url + i + 3, MAX_URL);
	    strcpy(url, temp);
	}
	i++;
    }

    return url;
}


/* INIT Acceptable table. 
 * Borrow from libwww2 with Mosaic2.4 Distribution   */
void init_url_acceptable()
{
    unsigned int i;
    char *good =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./-_$";
    for (i = 0; i < 256; i++)
	url_acceptable[i] = 0;
    for (; *good; good++)
	url_acceptable[(unsigned int) *good] = 1;
    url_acceptable_init = 1;
}


/* Encode prohibited char in string */
/* return the pointer to new (allocated) string */
char *url_escape(url)
     char *url;
{
    char *p, *q;
    char *tmpline = xcalloc(1, MAX_URL);

    if (!url_acceptable_init)
	init_url_acceptable();

    q = tmpline;
    for (p = url; *p; p++) {
	if (url_acceptable[(int) (*p)])
	    *q++ = *p;
	else {
	    *q++ = '%';		/* Means hex coming */
	    *q++ = hex[(int) ((*p) >> 4)];
	    *q++ = hex[(int) ((*p) & 15)];
	}
    }
    *q++ = '\0';
    return tmpline;
}


/*
 * Strip the url from e->key, return a pointer to a static copy of it.
 * Planning ahead for removing e->url from meta-data
 */
char *the_url(e)
     StoreEntry *e;
{
    char *URL;
    char *token;
    static char line_in[MAX_URL + 1];
    static char delim[] = "/";
    int i;

    strcpy(line_in, e->key);
    token = strtok(line_in, delim);

    if (!(e->flag & CACHABLE) && (sscanf(token, "%d", &i))) {
	URL = strtok(NULL, "~");	/* Non_CACHABLE, key = /%d/url */
	return URL;
    }
    if ((e->flag & KEY_CHANGE) && (sscanf(token, "x%d", &i))) {
	/* key is changed, key = /x%d/url or /x%d/head/url or /x%d/post/url */
	/* Now key is url or head/url or post/url */
	token = strtok(NULL, "~");
    } else {
	/* key is url or /head/url or /post/url */
	strcpy(token, e->key);
    }

    if (e->type_id == REQUEST_OP_GET) {
	/* key is url */
	return token;
    } else if ((e->type_id == REQUEST_OP_POST) &&
	(!(strncmp(token, "post/", 5)) || !(strncmp(token, "/post/", 6)))) {
	URL = strtok(token, delim);
	URL = strtok(NULL, "~");
	/* discard "/post/" or "post/" from the key and get url */
	return URL;
    } else if ((e->type_id == REQUEST_OP_HEAD) &&
	(!(strncmp(token, "head/", 5)) || !(strncmp(token, "/head/", 6)))) {
	URL = strtok(token, delim);
	URL = strtok(NULL, "~");
	/* discard "/head/" or "head/" from the key and get url */
	return URL;
    } else {
	debug(0, "Should not be here. Unknown format of the key: %s\n",
	    e->key);
	return (NULL);
    }
}
