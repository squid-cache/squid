
/*
 * $Id: delay_pools.cc,v 1.2 1998/08/14 09:22:34 wessels Exp $
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
static delay_id delayId(unsigned char class, int position);

static delay_id
delayId(unsigned char class, int position)
{
    assert(class <= 3);
    return (class << 16) | (position & 0xFFFF);
}

int
delayClient(clientHttpRequest * http)
{
    aclCheck_t ch;
    int i, j;
    unsigned int host;
    unsigned char net;
    unsigned char class = 0;
    int position = 0;
    request_t *r = http->request;

    memset(&ch, '\0', sizeof(ch));
    ch.src_addr = http->conn->peer.sin_addr;
    ch.request = r;
    if (aclCheckFast(Config.Delay.class1.access, &ch)) {
	class = 1;
	r->delay_id = delayId(class, position);
	return 1;
    }
    if (aclCheckFast(Config.Delay.class2.access, &ch)) {
	class = 2;
	host = ntohl(ch.src_addr.s_addr) & 0xff;
	if (host == 255 || !host) {
	    debug(77, 0) ("ARGH: Delay requested for host %s\n", inet_ntoa(ch.src_addr));
	    class = 0;
	    r->delay_id = delayId(class, position);
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
	position = i;
	r->delay_id = delayId(class, position);
	return 1;
    }
    if (aclCheckFast(Config.Delay.class3.access, &ch)) {
	class = 3;
	host = ntohl(ch.src_addr.s_addr) & 0xffff;
	net = host >> 8;
	host &= 0xff;
	if (host == 255 || !host || net == 255) {
	    debug(77, 0) ("ARGH: Delay requested for host %s\n", inet_ntoa(ch.src_addr));
	    class = 0;
	    r->delay_id = delayId(class, position);
	    return 0;
	}
	for (i = 0;; i++) {
	    if (delay_data.class3_network_map[i] == net)
		break;
	    if (delay_data.class3_network_map[i] == 255) {
		delay_data.class3_network_map[i] = net;
		delay_data.class3_individual_map[i][0] = 255;
		delay_data.class3_network_map[i + 1] = 255;
		delay_data.class3_network[i] = Config.Delay.class3.network.restore_bps;
		break;
	    }
	}
	position = i << 8;
	for (j = 0;; j++) {
	    if (delay_data.class3_individual_map[i][j] == host) {
		position |= j;
		break;
	    }
	    if (delay_data.class3_individual_map[i][j] == 255) {
		delay_data.class3_individual_map[i][j] = host;
		delay_data.class3_individual_map[i][j + 1] = 255;
		delay_data.class3_individual[position |= j] =
		    Config.Delay.class3.individual.restore_bps;
		break;
	    }
	}
	r->delay_id = delayId(class, position);
	return 1;
    }
    class = 0;
    r->delay_id = delayId(class, position);
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
    if (Config.Delay.class1.aggregate.restore_bps != -1) {
	storeAppendPrintf(sentry, "\n\tAggregate:\n");
	storeAppendPrintf(sentry, "\t\tMax: %d\n",
	    Config.Delay.class1.aggregate.max_bytes);
	storeAppendPrintf(sentry, "\t\tRate: %d\n",
	    Config.Delay.class1.aggregate.restore_bps);
	storeAppendPrintf(sentry, "\t\tCurrent: %d\n",
	    delay_data.class1_aggregate);
    } else {
	storeAppendPrintf(sentry, "\n\tAggregate:\n\tDisabled.\n");
    }
    storeAppendPrintf(sentry, "\nClass 2 Delay Pool Statistics:\n");
    if (Config.Delay.class2.aggregate.restore_bps != -1) {
	storeAppendPrintf(sentry, "\n\tAggregate:\n");
	storeAppendPrintf(sentry, "\t\tMax: %d\n",
	    Config.Delay.class2.aggregate.max_bytes);
	storeAppendPrintf(sentry, "\t\tRate: %d\n",
	    Config.Delay.class2.aggregate.restore_bps);
	storeAppendPrintf(sentry, "\t\tCurrent: %d\n",
	    delay_data.class2_aggregate);
    } else {
	storeAppendPrintf(sentry, "\n\tAggregate:\n\tDisabled.\n");
    }
    if (Config.Delay.class2.individual.restore_bps != -1) {
	storeAppendPrintf(sentry, "\n\tIndividual:\n");
	storeAppendPrintf(sentry, "\t\tMax: %d\n",
	    Config.Delay.class2.individual.max_bytes);
	storeAppendPrintf(sentry, "\t\tRate: %d\n",
	    Config.Delay.class2.individual.restore_bps);
	storeAppendPrintf(sentry, "\t\tCurrent: ");
	for (i = 0;; i++) {
	    if (delay_data.class2_individual_map[i] == 255)
		break;
	    storeAppendPrintf(sentry, "%d:%d ",
		delay_data.class2_individual_map[i],
		delay_data.class2_individual[i]);
	}
    } else {
	storeAppendPrintf(sentry, "\n\tIndividual:\n\tDisabled.");
    }
    storeAppendPrintf(sentry, "\n\nClass 3 Delay Pool Statistics:\n");
    if (Config.Delay.class3.aggregate.restore_bps != -1) {
	storeAppendPrintf(sentry, "\n\tAggregate:\n");
	storeAppendPrintf(sentry, "\t\tMax: %d\n",
	    Config.Delay.class3.aggregate.max_bytes);
	storeAppendPrintf(sentry, "\t\tRate: %d\n",
	    Config.Delay.class3.aggregate.restore_bps);
	storeAppendPrintf(sentry, "\t\tCurrent: %d\n",
	    delay_data.class3_aggregate);
    } else {
	storeAppendPrintf(sentry, "\n\tAggregate:\n\tDisabled.\n");
    }
    if (Config.Delay.class3.network.restore_bps != -1) {
	storeAppendPrintf(sentry, "\n\tNetwork:\n");
	storeAppendPrintf(sentry, "\t\tMax: %d\n",
	    Config.Delay.class3.network.max_bytes);
	storeAppendPrintf(sentry, "\t\tRate: %d\n",
	    Config.Delay.class3.network.restore_bps);
	storeAppendPrintf(sentry, "\t\tCurrent: ");
	for (i = 0;; i++) {
	    if (delay_data.class3_network_map[i] == 255)
		break;
	    storeAppendPrintf(sentry, "%d:%d ",
		delay_data.class3_network_map[i],
		delay_data.class3_network[i]);
	}
    } else {
	storeAppendPrintf(sentry, "\n\tNetwork:\n\tDisabled.");
    }
    if (Config.Delay.class3.individual.restore_bps != -1) {
	storeAppendPrintf(sentry, "\n\n\tIndividual:\n");
	storeAppendPrintf(sentry, "\t\tMax: %d\n",
	    Config.Delay.class3.individual.max_bytes);
	storeAppendPrintf(sentry, "\t\tRate: %d\n",
	    Config.Delay.class3.individual.restore_bps);
	for (i = 0;; i++) {
	    if (delay_data.class3_network_map[i] == 255)
		break;
	    storeAppendPrintf(sentry, "\t\tCurrent [Network %d]: ",
		delay_data.class3_network_map[i]);
	    for (j = 0;; j++) {
		if (delay_data.class3_individual_map[i][j] == 255)
		    break;
		storeAppendPrintf(sentry, "%d:%d ",
		    delay_data.class3_individual_map[i][j],
		    delay_data.class3_individual[(i << 8) + j]);
	    }
	    storeAppendPrintf(sentry, "\n");
	}
    } else {
	storeAppendPrintf(sentry, "\n\n\tIndividual:\n\tDisabled.\n");
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

/*
 * this returns the number of bytes the client is permitted. it does not take
 * into account bytes already buffered - that is up to the caller.
 */
int
delayBytesWanted(delay_id d, int max)
{
    int position = d & 0xFFFF;
    unsigned char class = (d & 0xFF0000) >> 16;
    int nbytes = max;
    switch (class) {
    case 0:
	break;

    case 1:
	if (Config.Delay.class1.aggregate.restore_bps != -1)
	    nbytes = XMIN(nbytes, delay_data.class1_aggregate);
	break;

    case 2:
	if (Config.Delay.class2.aggregate.restore_bps != -1)
	    nbytes = XMIN(nbytes, delay_data.class2_aggregate);
	if (Config.Delay.class2.individual.restore_bps != -1)
	    nbytes = XMIN(nbytes, delay_data.class2_individual[position]);
	break;

    case 3:
	if (Config.Delay.class3.aggregate.restore_bps != -1)
	    nbytes = XMIN(nbytes, delay_data.class3_aggregate);
	if (Config.Delay.class3.individual.restore_bps != -1)
	    nbytes = XMIN(nbytes, delay_data.class3_individual[position]);
	if (Config.Delay.class3.network.restore_bps != -1)
	    nbytes = XMIN(nbytes, delay_data.class3_network[position >> 8]);
	break;

    default:
	fatalf("delayBytesWanted: Invalid class %d\n", class);
	break;
    }
    assert(nbytes > 0);
    assert(nbytes <= max);
    return nbytes;
}

/*
 * this records actual bytes recieved.  always recorded, even if the
 * class is disabled - see above for all the cases which would be needed
 * to efficiently not record it, so it's just ignored if not wanted.
 */
void
delayBytesIn(delay_id d, int qty)
{
    int position = d & 0xFFFF;
    unsigned char class = (d & 0xFF0000) >> 16;
    if (class == 0)
	return;
    if (class == 1) {
	delay_data.class1_aggregate -= qty;
	return;
    }
    if (class == 2) {
	delay_data.class2_aggregate -= qty;
	delay_data.class3_individual[position] -= qty;
	return;
    }
    if (class == 3) {
	delay_data.class3_aggregate -= qty;
	delay_data.class3_network[position >> 8] -= qty;
	delay_data.class3_individual[position] -= qty;
	return;
    }
    assert(0);
}

int
delayMostBytesWanted(const MemObject * mem, int max)
{
    int i = 0;
    store_client *sc;
    for (sc = mem->clients; sc; sc = sc->next) {
	if (sc->callback_data == NULL)	/* open slot */
	    continue;
	if (sc->type != STORE_MEM_CLIENT)
	    continue;
	i = XMAX(delayBytesWanted(sc->delay_id, max), i);
    }
    return i;
}

delay_id
delayMostBytesAllowed(const MemObject * mem)
{
    int j;
    int jmax = 0;
    store_client *sc;
    delay_id d = 0;
    for (sc = mem->clients; sc; sc = sc->next) {
	if (sc->callback_data == NULL)	/* open slot */
	    continue;
	if (sc->type != STORE_MEM_CLIENT)
	    continue;
	j = delayBytesWanted(sc->delay_id, SQUID_TCP_SO_RCVBUF);
	if (j > jmax) {
	    jmax = j;
	    d = sc->delay_id;
	}
    }
    return d;
}

void
delaySetStoreClient(StoreEntry * e, void *data, delay_id delay_id)
{
    store_client *sc = storeClientListSearch(e->mem_obj, data);
    assert(sc != NULL);
    sc->delay_id = delay_id;
}

#endif
