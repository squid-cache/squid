
/*
 * $Id: delay_pools.cc,v 1.1 1998/07/31 00:15:40 wessels Exp $
 *
 * DEBUG: section 77    Delay Pools
 * AUTHOR: David Luyer <luyer@ucs.uwa.edu.au>
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

#include "config.h"

#if DELAY_POOLS
#include "squid.h"

struct _delayData {
    int class1_aggregate;
    int class2_aggregate;
    /* 254 entries + 1 terminator byte */
    unsigned char class2_individual_map[255];
    /* 254 entries */
    int class2_individual[254];
    int class3_aggregate;
    /* 255 entries + 1 terminator byte */
    unsigned char class3_network_map[256];
    /* 255 entries */
    int class3_network[255];
    /* 255 sets of (254 entries + 1 terminator byte) */
    unsigned char class3_individual_map[255][255];
    /* largest entry = (254<<8)+253 = 65277 */
    int class3_individual[65278];
};

static struct _delayData delay_data;
static OBJH delayPoolStats;

int
delayClient(clientHttpRequest * http)
{
    aclCheck_t ch;
    int i, j;
    unsigned int host;
    unsigned char net;

    memset(&ch, '\0', sizeof(ch));
    ch.src_addr = http->conn->peer.sin_addr;
    ch.request = http->request;
    if (aclCheckFast(Config.Delay.class1.access, &ch)) {
	http->request->delay.class = 1;
	return 1;
    }
    if (aclCheckFast(Config.Delay.class2.access, &ch)) {
	http->request->delay.class = 2;
	host = ntohl(ch.src_addr.s_addr) & 0xff;
	if (host == 255 || !host) {
	    debug(77, 0) ("ARGH: Delay requested for host %s\n", inet_ntoa(ch.src_addr));
	    http->request->delay.class = 0;
	    return 0;
	}
	for (i = 0;; i++) {
	    if (delay_data.class2_individual_map[i] == host)
		break;
	    if (delay_data.class2_individual_map[i] == 255) {
		delay_data.class2_individual_map[i] = host;
		delay_data.class2_individual_map[i + 1] = 255;
		delay_data.class2_individual[i] = Config.Delay.class2.individual.restore_bps;
		break;
	    }
	}
	http->request->delay.position = i;
	return 1;
    }
    if (aclCheckFast(Config.Delay.class3.access, &ch)) {
	http->request->delay.class = 3;
	host = ntohl(ch.src_addr.s_addr) & 0xffff;
	net = host >> 8;
	host &= 0xff;
	if (host == 255 || !host || net == 255) {
	    debug(77, 0) ("ARGH: Delay requested for host %s\n", inet_ntoa(ch.src_addr));
	    http->request->delay.class = 0;
	    return 0;
	}
	for (i = 0;; i++) {
	    if (delay_data.class3_network_map[i] == net)
		break;
	    if (delay_data.class3_network_map[i] == 255) {
		delay_data.class3_network_map[i] = net;
		delay_data.class3_network_map[i + 1] = 255;
		delay_data.class3_network[i] = Config.Delay.class3.network.restore_bps;
		break;
	    }
	}
	http->request->delay.position = i << 8;
	for (j = 0;; j++) {
	    if (delay_data.class3_individual_map[i][j] == host) {
		http->request->delay.position |= j;
		break;
	    }
	    if (delay_data.class3_individual_map[i][j] == 255) {
		delay_data.class3_individual_map[i][j] = host;
		delay_data.class3_individual_map[i][j + 1] = 255;
		delay_data.class3_individual[http->request->delay.position |= j] =
		    Config.Delay.class3.individual.restore_bps;
		break;
	    }
	}
	return 1;
    }
    http->request->delay.class = 0;
    return 0;
}


void
delayPoolsUpdate(int incr)
{
    int i;
    int j;
    int mpos;
    int individual_restore_bytes;
    int network_restore_bytes;
    /* Increment 3 aggregate pools */
    if (Config.Delay.class1.aggregate.restore_bps != -1 &&
	(delay_data.class1_aggregate +=
	    Config.Delay.class1.aggregate.restore_bps * incr) >
	Config.Delay.class1.aggregate.max_bytes)
	delay_data.class1_aggregate = Config.Delay.class1.aggregate.max_bytes;
    if (Config.Delay.class2.aggregate.restore_bps != -1 &&
	(delay_data.class2_aggregate +=
	    Config.Delay.class2.aggregate.restore_bps * incr) >
	Config.Delay.class2.aggregate.max_bytes)
	delay_data.class2_aggregate = Config.Delay.class2.aggregate.max_bytes;
    if (Config.Delay.class3.aggregate.restore_bps != -1 &&
	(delay_data.class3_aggregate +=
	    Config.Delay.class3.aggregate.restore_bps * incr) >
	Config.Delay.class3.aggregate.max_bytes)
	delay_data.class3_aggregate = Config.Delay.class3.aggregate.max_bytes;
    /* Increment class 2 individual pools */
    if ((individual_restore_bytes = Config.Delay.class2.individual.restore_bps) != -1) {
	individual_restore_bytes *= incr;
	for (i = 0;; i++) {
	    if (delay_data.class2_individual_map[i] == 255)
		break;
	    if (delay_data.class2_individual[i] == Config.Delay.class2.individual.max_bytes)
		continue;
	    if ((delay_data.class2_individual[i] += individual_restore_bytes) >
		Config.Delay.class2.individual.max_bytes)
		delay_data.class2_individual[i] = Config.Delay.class2.individual.max_bytes;
	}
    }
    /* Increment class 3 individual and network pools */
    if ((network_restore_bytes = Config.Delay.class3.network.restore_bps) != -1 ||
	(individual_restore_bytes = Config.Delay.class3.individual.restore_bps) != -1) {
	individual_restore_bytes *= incr;
	network_restore_bytes *= incr;
	for (i = 0;; i++) {
	    if (delay_data.class3_network_map[i] == 255)
		break;
	    if (individual_restore_bytes != -incr) {
		for (j = 0, mpos = (i << 8);; j++, mpos++) {
		    if (delay_data.class3_individual_map[i][j] == 255)
			break;
		    if (delay_data.class3_individual[mpos] == Config.Delay.class3.individual.max_bytes)
			continue;
		    if ((delay_data.class3_individual[mpos] += individual_restore_bytes) >
			Config.Delay.class3.individual.max_bytes)
			delay_data.class3_individual[mpos] = Config.Delay.class3.individual.max_bytes;
		}
	    }
	    if (network_restore_bytes == -incr ||
		delay_data.class3_network[i] == Config.Delay.class3.network.max_bytes)
		continue;
	    if ((delay_data.class3_network[i] += network_restore_bytes) >
		Config.Delay.class3.network.max_bytes)
		delay_data.class3_network[i] = Config.Delay.class3.network.max_bytes;
	}
    }
}

static void
delayPoolStats(StoreEntry * sentry)
{
    int i;
    int j;
    storeAppendPrintf(sentry, "Class 1 Delay Pool Statistics:\n");
    storeAppendPrintf(sentry, "\n\tAggregate:\n");
    storeAppendPrintf(sentry, "\t\tMax: %d\n", Config.Delay.class1.aggregate.max_bytes);
    storeAppendPrintf(sentry, "\t\tRate: %d\n", Config.Delay.class1.aggregate.restore_bps);
    storeAppendPrintf(sentry, "\t\tCurrent: %d\n", delay_data.class1_aggregate);
    storeAppendPrintf(sentry, "\nClass 2 Delay Pool Statistics:\n");
    storeAppendPrintf(sentry, "\n\tAggregate:\n");
    storeAppendPrintf(sentry, "\t\tMax: %d\n", Config.Delay.class2.aggregate.max_bytes);
    storeAppendPrintf(sentry, "\t\tRate: %d\n", Config.Delay.class2.aggregate.restore_bps);
    storeAppendPrintf(sentry, "\t\tCurrent: %d\n", delay_data.class2_aggregate);
    storeAppendPrintf(sentry, "\n\tIndividual:\n");
    storeAppendPrintf(sentry, "\t\tMax: %d\n", Config.Delay.class2.individual.max_bytes);
    storeAppendPrintf(sentry, "\t\tRate: %d\n", Config.Delay.class2.individual.restore_bps);
    storeAppendPrintf(sentry, "\t\tCurrent: ");
    for (i = 0;; i++) {
	if (delay_data.class2_individual_map[i] == 255)
	    break;
	storeAppendPrintf(sentry, "%d:%d ", delay_data.class2_individual_map[i],
	    delay_data.class2_individual[i]);
    }
    storeAppendPrintf(sentry, "\n\nClass 3 Delay Pool Statistics:\n");
    storeAppendPrintf(sentry, "\n\tAggregate:\n");
    storeAppendPrintf(sentry, "\t\tMax: %d\n", Config.Delay.class3.aggregate.max_bytes);
    storeAppendPrintf(sentry, "\t\tRate: %d\n", Config.Delay.class3.aggregate.restore_bps);
    storeAppendPrintf(sentry, "\t\tCurrent: %d\n", delay_data.class3_aggregate);
    storeAppendPrintf(sentry, "\n\tNetwork:\n");
    storeAppendPrintf(sentry, "\t\tMax: %d\n", Config.Delay.class3.network.max_bytes);
    storeAppendPrintf(sentry, "\t\tRate: %d\n", Config.Delay.class3.network.restore_bps);
    storeAppendPrintf(sentry, "\t\tCurrent: ");
    for (i = 0;; i++) {
	if (delay_data.class3_network_map[i] == 255)
	    break;
	storeAppendPrintf(sentry, "%d:%d ", delay_data.class3_network_map[i],
	    delay_data.class3_network[i]);
    }
    storeAppendPrintf(sentry, "\n\n\tIndividual:\n");
    storeAppendPrintf(sentry, "\t\tMax: %d\n", Config.Delay.class3.individual.max_bytes);
    storeAppendPrintf(sentry, "\t\tRate: %d\n", Config.Delay.class3.individual.restore_bps);
    for (i = 0;; i++) {
	if (delay_data.class3_network_map[i] == 255)
	    break;
	storeAppendPrintf(sentry, "\t\tCurrent [Network %d]: ",
	    delay_data.class3_network_map[i]);
	for (j = 0;; j++) {
	    if (delay_data.class3_individual_map[i][j] == 255)
		break;
	    storeAppendPrintf(sentry, "%d:%d ", delay_data.class3_individual_map[i][j],
		delay_data.class3_individual[(i << 8) + j]);
	}
	storeAppendPrintf(sentry, "\n");
    }
    storeAppendPrintf(sentry, "\n");
}

void
delayPoolsInit(void)
{
    delay_pools_last_update = getCurrentTime();
    delay_data.class1_aggregate = Config.Delay.class1.aggregate.restore_bps;
    delay_data.class2_aggregate = Config.Delay.class2.aggregate.restore_bps;
    delay_data.class2_individual_map[0] = 255;
    delay_data.class3_aggregate = Config.Delay.class3.aggregate.restore_bps;
    delay_data.class3_network_map[0] = 255;
    cachemgrRegister("delay", "Delay Pool Levels", delayPoolStats, 0, 1);
}

#endif
