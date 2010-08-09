/* squid_edir_iplookup - Copyright (C) 2009, 2010 Chad E. Naugle
 *
 ********************************************************************************
 *
 *  This file is part of squid_edir_iplookup.
 *
 *  squid_edir_iplookup is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  squid_edir_iplookup is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with squid_edir_iplookup.  If not, see <http://www.gnu.org/licenses/>.
 *
 ********************************************************************************
 *
 * iplookup.c --
 *
 * ldap_t data struct manipulation, and LDAP server communication.
 *
 */

#include "main.h"
#include "util.h"
#include "iplookup.h"

/* InitLDAP() - <ldap_t>
 *
 * Initalize LDAP structure for use, zeroing out all variables.
 *
 */
void InitLDAP(ldap_t *l)
{
    if (l == NULL) return;			/* Duh! */

    l->lp = NULL;
    if (l->lm != NULL)
        ldap_msgfree(l->lm);
    if (l->val != NULL)
        ldap_value_free_len(l->val);
    l->lm = NULL;
    l->val = NULL;
    memset(l->basedn, '\0', sizeof(l->basedn));
    memset(l->host, '\0', sizeof(l->host));
    memset(l->dn, '\0', sizeof(l->dn));
    memset(l->passwd, '\0', sizeof(l->passwd));
    memset(l->search_filter, '\0', sizeof(l->search_filter));
    memset(l->search_ip, '\0', sizeof(l->search_ip));
    memset(l->userid, '\0', sizeof(l->userid));
    l->status = 0;
    l->status |= LDAP_INIT_S;
    l->port = 0;
    l->scope = -1;
    l->type = 0;
    l->err = -1;					/* Set error to LDAP_SUCCESS by default */
    l->ver = 0;
    l->idle_time = 0;
    l->num_ent = 0;				/* Number of entries in l->lm */
    l->num_val = 0;				/* Number of entries in l->val */

    /* Set default settings from conf */
    if (conf.basedn[0] != '\0')
        strncpy(l->basedn, conf.basedn, sizeof(l->basedn));
    if (conf.host[0] != '\0')
        strncpy(l->host, conf.host, sizeof(l->host));
    if (conf.port != 0)
        l->port = conf.port;
    if (conf.dn[0] != '\0')
        strncpy(l->dn, conf.dn, sizeof(l->dn));
    if (conf.passwd[0] != '\0')
        strncpy(l->passwd, conf.passwd, sizeof(l->passwd));
    if (conf.search_filter[0] != '\0')
        strncpy(l->search_filter, conf.search_filter, sizeof(l->search_filter));
    if (!(conf.scope < 0))
        l->scope = conf.scope;
    if (conf.mode & MODE_IPV4)
        l->status |= LDAP_IPV4_S;
    if (conf.mode & MODE_IPV6)
        l->status |= LDAP_IPV6_S;
}

/* OpenLDAP() - <ldap_t> <host> <port>
 *
 * Build LDAP struct with hostname and port, and ready it for binding.
 *
 */
int OpenLDAP(ldap_t *l, char *h, unsigned int p)
{
    if ((l == NULL) || (h == NULL)) return LDAP_ERR_NULL;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;		/* Not initalized, or might be in use */
    if (l->status & LDAP_OPEN_S) return LDAP_ERR_OPEN;		/* Already open */
    if (l->status & LDAP_BIND_S) return LDAP_ERR_BIND;		/* Already bound */

    strncpy(l->host, h, sizeof(l->host));
    if (p > 0)
        l->port = p;
    else
        l->port = LDAP_PORT;				/* Default is port 389 */

#ifdef NETSCAPE_SSL
    if (l->port == LDAPS_PORT)
        l->status |= (LDAP_SSL_S | LDAP_TLS_S);		/* SSL Port: 636 */
#endif

#ifdef USE_LDAP_INIT
    l->lp = ldap_init(l->host, l->port);
#else
    l->lp = ldap_open(l->host, l->port);
#endif
    if (l->lp == NULL) {
        l->err = LDAP_CONNECT_ERROR;
        return LDAP_ERR_CONNECT;				/* Unable to connect */
    } else {
        /* set status */
//    l->status &= ~(LDAP_INIT_S);
        l->status |= LDAP_OPEN_S;
        l->err = LDAP_SUCCESS;
        return LDAP_ERR_SUCCESS;
    }
}

/* CloseLDAP() - <ldap_t>
 *
 * Close LDAP connection, and clean up data structure.
 *
 */
int CloseLDAP(ldap_t *l)
{
    int s;
    if (l == NULL) return LDAP_ERR_NULL;
    if (l->lp == NULL) return LDAP_ERR_NULL;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;		/* Connection not initalized */
    if (!(l->status & LDAP_OPEN_S)) return LDAP_ERR_OPEN;		/* Connection not open */

    if (l->lm != NULL) {
        ldap_msgfree(l->lm);
        l->lm = NULL;
    }
    if (l->val != NULL) {
        ldap_value_free_len(l->val);
        l->val = NULL;
    }

    /* okay, so it's open, close it - No need to check other criteria */
    s = ldap_unbind(l->lp);
    if (s == LDAP_SUCCESS) {
        l->status &= ~(LDAP_OPEN_S | LDAP_BIND_S);
        l->idle_time = 0;
        l->err = s;							/* Set LDAP error code */
        return LDAP_ERR_SUCCESS;
    } else {
        l->err = s;							/* Set LDAP error code */
        return LDAP_ERR_FAILED;
    }
}

/* SetVerLDAP() - <ldap_t> <version>
 *
 * Set LDAP version number for connection to <version> of 1, 2, or 3
 *
 */
int SetVerLDAP(ldap_t *l, int v)
{
    int x;
    if (l == NULL) return LDAP_ERR_NULL;
    if ((v > 3) || (v < 1)) return LDAP_ERR_PARAM;
    if (l->lp == NULL) return LDAP_ERR_POINTER;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;		/* Not initalized */
    if (!(l->status & LDAP_OPEN_S)) return LDAP_ERR_OPEN;		/* Not open */
    if (l->status & LDAP_BIND_S) return LDAP_ERR_BIND;		/* Already bound */

    /* set version */
    x = ldap_set_option(l->lp, LDAP_OPT_PROTOCOL_VERSION, &v);
    if (x == LDAP_SUCCESS) {
        l->ver = v;
        l->err = x;							/* Set LDAP error code */
        return LDAP_ERR_SUCCESS;
    } else {
        l->err = x;							/* Set LDAP error code */
        return LDAP_ERR_FAILED;
    }
}

/* BindLDAP() - <ldap_t> <use-dn> <use-password> <type>
 *
 * Bind LDAP connection (Open) using optional dn and password, of <type>
 *
 */
int BindLDAP(ldap_t *l, char *dn, char *pw, unsigned int t)
{
    int s;
    if (l == NULL) return LDAP_ERR_NULL;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;		/* Not initalized */
    if (!(l->status & LDAP_OPEN_S)) return LDAP_ERR_OPEN;		/* Not open */
    if (l->status & LDAP_BIND_S) return LDAP_ERR_BIND;		/* Already bound */
    if (l->lp == NULL) return LDAP_ERR_POINTER;			/* Error */

    /* Copy details - dn and pw CAN be NULL for anonymous and/or TLS */
    if (dn != NULL) {
        if ((l->basedn[0] != '\0') && (strstr(dn, l->basedn) == NULL)) {
            /* We got a basedn, but it's not part of dn */
            strncpy(l->dn, dn, sizeof(l->dn));
            strcat(l->dn, ",");
            strncat(l->dn, l->basedn, sizeof(l->dn));
        } else
            strncpy(l->dn, dn, sizeof(l->dn));
    }
    if (pw != NULL)
        strncpy(l->passwd, pw, sizeof(l->passwd));

    /* Type ? */
    switch (t) {
    case LDAP_AUTH_NONE:
        l->type = t;
        break;
    case LDAP_AUTH_SIMPLE:
        l->type = t;
        break;
    case LDAP_AUTH_SASL:
        l->type = t;
        break;
    case LDAP_AUTH_KRBV4:
        l->type = t;
        break;
    case LDAP_AUTH_KRBV41:
        l->type = t;
        break;
    case LDAP_AUTH_KRBV42:
        l->type = t;
        break;
#ifdef LDAP_AUTH_TLS
    case LDAP_AUTH_TLS:					/* Added for chicken switch to TLS-enabled without using SSL */
        l->type = t;
        break;
#endif
    default:
        l->type = LDAP_AUTH_NONE;
        break;						/* Default to anonymous bind */
    }

    /* Bind */
#ifdef NETSCAPE_SSL
    if (l->type == LDAP_AUTH_TLS)
        s = ldap_start_tls_s(l->lp, NULL, NULL);
    else
#endif
        s = ldap_bind_s(l->lp, l->dn, l->passwd, l->type);
    if (s == LDAP_SUCCESS) {
        l->status |= LDAP_BIND_S;				/* Success */
        l->err = s;						/* Set LDAP error code */
        return LDAP_ERR_SUCCESS;
    } else {
        l->err = s;						/* Set LDAP error code */
        return LDAP_ERR_FAILED;
    }
}

/*
 * ConvertIP() - <ldap_t> <ip>
 *
 * Take an IPv4 address in dot-decimal or IPv6 notation, and convert to 2-digit HEX stored in l->search_ip
 * This is the networkAddress that we search LDAP for.
 *
 */
int ConvertIP(ldap_t *l, char *ip)
{
    char bufa[MAXLEN], bufb[MAXLEN], obj[MAXLEN];
    char hexc[4], *p;
    size_t s;
    long x;
    int i, j, t, swi;							/* IPv6 "::" cut over toggle */
    if (l == NULL) return LDAP_ERR_NULL;
    if (ip == NULL) return LDAP_ERR_PARAM;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;			/* Not initalized */
    if (!(l->status & LDAP_OPEN_S)) return LDAP_ERR_OPEN;			/* Not open */
    if (!(l->status & LDAP_BIND_S)) return LDAP_ERR_BIND;			/* Not bound */

    s = strlen(ip);
    memset(bufa, '\0', sizeof(bufa));
    memset(bufb, '\0', sizeof(bufb));
    memset(obj, '\0', sizeof(obj));
    /* SplitString() will zero out bufa & obj at each call */
    memset(l->search_ip, '\0', sizeof(l->search_ip));
    strncpy(bufa, ip, s);							/* To avoid segfaults, use bufa instead of ip */
    swi = 0;

    if ((conf.mode & MODE_IPV6) && (conf.mode & MODE_IPV4)) {
        if (strcasestr(bufa, ":FFFF:") == NULL)
            return LDAP_ERR_INVALID;						/* Unable to find IPv4-in-IPv6 notation */
    }
    if (conf.mode & MODE_IPV6) {
        /* Search for :: in string */
        if ((bufa[0] == ':') && (bufa[1] == ':')) {
            /* bufa starts with a ::, so just copy and clear */
            strncpy(bufb, bufa, sizeof(bufa));
            memset(bufa, '\0', strlen(bufa));
            swi++;								/* Indicates that there is a bufb */
        } else if ((bufa[0] == ':') && (bufa[1] != ':')) {
            /* bufa starts with a :, a typo so just fill in a ':', cat and clear */
            bufb[0] = ':';
            strncat(bufb, bufa, sizeof(bufa));
            memset(bufa, '\0', strlen(bufa));
            swi++;								/* Indicates that there is a bufb */
        } else {
            p = strstr(bufa, "::");
            if (p != NULL) {
                /* Found it, break bufa down and split into bufb here */
                memset(bufb, '\0', strlen(bufb));
                i = strlen(p);
                memcpy(bufb, p, i);
                *p = '\0';
                bufb[i] = '\0';
                swi++;								/* Indicates that there is a bufb */
            }
        }
    }
    s = strlen(bufa);
    if (s < 1)
        s = strlen(bufb);
    while (s > 0) {
        if ((conf.mode & MODE_IPV4) && (conf.mode & MODE_IPV6) && (swi > 1)) {
            if (strchr(bufb, ':') != NULL) {
                /* Split Off leading :ffff: */
                t = SplitString(bufb, s, ':', obj, sizeof(obj));
                if (t > 0) {
                    strcpy(hexc, "FFFF");
                    strncat(l->search_ip, hexc, sizeof(l->search_ip));
                } else
                    break;							/* reached end */
            } else {
                /* Break down IPv4 address nested in the IPv6 address */
                t = SplitString(bufb, s, '.', obj, sizeof(obj));
                if (t > 0) {
                    errno = 0;
                    x = strtol(obj, (char **)NULL, 10);
                    if (((x < 0) || (x > 255)) || ((errno != 0) && (x == 0)) || ((obj[0] != '0') && (x == 0)))
                        return LDAP_ERR_OOB;					/* Out of bounds -- Invalid address */
                    memset(hexc, '\0', sizeof(hexc));
                    snprintf(hexc, sizeof(hexc), "%.2X", (int)x);
                    strncat(l->search_ip, hexc, sizeof(l->search_ip));
                } else
                    break;							/* reached end of octet */
            }
        } else if ((conf.mode & MODE_IPV4) && (swi == 0)) {
            /* Break down IPv4 address  */
            t = SplitString(bufa, s, '.', obj, sizeof(obj));
            if (t > 0) {
                errno = 0;
                x = strtol(obj, (char **)NULL, 10);
                if (((x < 0) || (x > 255)) || ((errno != 0) && (x == 0)) || ((obj[0] != '0') && (x == 0)))
                    return LDAP_ERR_OOB;						/* Out of bounds -- Invalid address */
                memset(hexc, '\0', sizeof(hexc));
                snprintf(hexc, sizeof(hexc), "%.2X", (int)x);
                strncat(l->search_ip, hexc, sizeof(l->search_ip));
            } else
                break;								/* reached end of octet */
        } else if (conf.mode & MODE_IPV6) {
            /* Break down IPv6 address */
            if (swi > 1)
                t = SplitString(bufb, s, ':', obj, sizeof(obj));		/* After "::" */
            else
                t = SplitString(bufa, s, ':', obj, sizeof(obj));		/* Before "::" */
            /* Convert octet by size (t) - and fill 0's */
            switch (t) {							/* IPv6 is already in HEX, copy contents */
            case 4:
                hexc[0] = (char) toupper((int)obj[0]);
                i = (int)hexc[0];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[1] = (char) toupper((int)obj[1]);
                i = (int)hexc[1];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[2] = '\0';
                strncat(l->search_ip, hexc, sizeof(l->search_ip));
                hexc[0] = (char) toupper((int)obj[2]);
                i = (int)hexc[0];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[1] = (char) toupper((int)obj[3]);
                i = (int)hexc[1];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[2] = '\0';
                strncat(l->search_ip, hexc, sizeof(l->search_ip));
                break;
            case 3:
                hexc[0] = '0';
                hexc[1] = (char) toupper((int)obj[0]);
                i = (int)hexc[1];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[2] = '\0';
                strncat(l->search_ip, hexc, sizeof(l->search_ip));
                hexc[0] = (char) toupper((int)obj[1]);
                i = (int)hexc[0];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[1] = (char) toupper((int)obj[2]);
                i = (int)hexc[1];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[2] = '\0';
                strncat(l->search_ip, hexc, sizeof(l->search_ip));
                break;
            case 2:
                strncat(l->search_ip, "00", sizeof(l->search_ip));
                hexc[0] = (char) toupper((int)obj[0]);
                i = (int)hexc[0];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[1] = (char) toupper((int)obj[1]);
                i = (int)hexc[1];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[2] = '\0';
                strncat(l->search_ip, hexc, sizeof(l->search_ip));
                break;
            case 1:
                strncat(l->search_ip, "00", sizeof(l->search_ip));
                hexc[0] = '0';
                hexc[1] = (char) toupper((int)obj[0]);
                i = (int)hexc[1];
                if (!isxdigit(i))
                    return LDAP_ERR_OOB;					/* Out of bounds */
                hexc[2] = '\0';
                strncat(l->search_ip, hexc, sizeof(l->search_ip));
                break;
            default:
                if (t > 4)
                    return LDAP_ERR_OOB;
                break;
            }
            /* Code to pad the address with 0's between a '::' */
            if ((strlen(bufa) == 0) && (swi == 1)) {
                /* We are *AT* the split, pad in some 0000 */
                if ((conf.mode & MODE_IPV4) && (conf.mode & MODE_IPV6))
                    t = 5;							/* IPv4-in-IPv6 mode, 5 blocks only */
                else {
                    t = strlen(bufb);
                    /* How many ':' exist in bufb ? */
                    j = 0;
                    for (i = 0; i < t; i++) {
                        if (bufb[i] == ':')
                            j++;
                    }
                    j--;								/* Preceeding "::" doesn't count */
                    t = 8 - (strlen(l->search_ip) / 4) - j;			/* Remainder */
                }
                if (t > 0) {
                    for (i = 0; i < t; i++)
                        strncat(l->search_ip, "0000", sizeof(l->search_ip));
                }
            }
        }
        if ((bufa[0] == '\0') && (swi > 0)) {
            s = strlen(bufb);
            swi++;
        } else
            s = strlen(bufa);
    }
    s = strlen(l->search_ip);

    /* CHECK sizes of address, truncate or pad */
    /* if "::" is at end of ip, then pad another block or two */
    while ((conf.mode & MODE_IPV6) && (s < 32)) {
        strncat(l->search_ip, "0000", sizeof(l->search_ip));
        s = strlen(l->search_ip);
    }
    if ((conf.mode & MODE_IPV6) && (s > 32)) {
        /* Too long, truncate */
        l->search_ip[32] = '\0';
        s = strlen(l->search_ip);
    }
    /* If at end of ip, and its not long enough, then pad another block or two */
    while ((conf.mode & MODE_IPV4) && (s < 8)) {
        strncat(l->search_ip, "00", sizeof(l->search_ip));
        s = strlen(l->search_ip);
    }
    if ((conf.mode & MODE_IPV4) && !(conf.mode & MODE_IPV6) && (s > 8)) {
        /* Too long, truncate */
        l->search_ip[8] = '\0';
        s = strlen(l->search_ip);
    }

    /* Completed, s is length of address in HEX */
    return s;
}

/*
 * SearchFilterLDAP() - <ldap_t> <IP> <group>
 *
 * Build LDAP Search Filter string and copy to l->search_filter
 *
 */
int SearchFilterLDAP(ldap_t *l, char *group)
{
    size_t i, j, s;
    int swi;
    char bufa[MAXLEN], bufb[MAXLEN], bufc[MAXLEN], bufd[MAXLEN], bufg[MAXLEN];
    if (l == NULL) return LDAP_ERR_NULL;
//  if (group == NULL) return LDAP_ERR_PARAM;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;			/* Not initalized */
    if (!(l->status & LDAP_OPEN_S)) return LDAP_ERR_OPEN;			/* Not open */
    if (!(l->status & LDAP_BIND_S)) return LDAP_ERR_BIND;			/* Not Bound */
    if (l->search_ip[0] == '\0') return LDAP_ERR_DATA;			/* Search IP is required */

    /* Zero out if not already */
    memset(bufa, '\0', strlen(bufa));
    memset(bufb, '\0', strlen(bufb));
    memset(bufc, '\0', strlen(bufc));
    memset(bufd, '\0', strlen(bufd));
    memset(bufg, '\0', strlen(bufg));

//  debug("SearchFilterLDAP", "Building... (Adding '\\' to IP...) ");
    s = strlen(l->search_ip);
    bufc[0] = '\134';
    swi = 0;
    j = 1;
    for (i = 0; i < s; i++) {
        if (swi == 2) {
            bufc[j] = '\134';
            j++;
            bufc[j] = l->search_ip[i];
            j++;
            swi = 1;
        } else {
            bufc[j] = l->search_ip[i];
            j++;
            swi++;
        }
    }
    if (group == NULL) {
        /* No groupMembership= to add, yay! */
        strcpy(bufa, "(&");
        strncat(bufa, conf.search_filter, sizeof(bufa));
        /* networkAddress */
        snprintf(bufb, sizeof(bufb), "(|(networkAddress=1\\23%s)(networkAddress=8\\23\\00\\00%s)(networkAddress=9\\23\\00\\00%s)", \
                 bufc, bufc, bufc);
        if (conf.mode & MODE_IPV6) {
            snprintf(bufd, sizeof(bufd), "(networkAddress=10\\23\\00\\00%s)(networkAddress=11\\23\\00\\00%s))", \
                     bufc, bufc);
            strncat(bufb, bufd, sizeof(bufb));
        } else
            strncat(bufb, ")", sizeof(bufb));
//    debug("SearchFilterLDAP", "bufb: %s\n", bufb);
        strncat(bufa, bufb, sizeof(bufa));
        strncat(bufa, ")", sizeof(bufa));
    } else {
        /* Needs groupMembership= to add... */
        strcpy(bufa, "(&(&");
        strncat(bufa, conf.search_filter, sizeof(bufa));
        /* groupMembership */
        snprintf(bufg, sizeof(bufg), "(groupMembership=cn=%s", group);
        if ((l->basedn[0] != '\0') && (strstr(group, l->basedn) == NULL)) {
            strncat(bufg, ",", sizeof(bufg));
            strncat(bufg, l->basedn, sizeof(bufg));
        }
        strncat(bufg, ")", sizeof(bufg));
//    debug("SearchFilterLDAP", "bufg: %s\n", bufg);
        strncat(bufa, bufg, sizeof(bufa));
        /* networkAddress */
        snprintf(bufb, sizeof(bufb), "(|(networkAddress=1\\23%s)(networkAddress=8\\23\\00\\00%s)(networkAddress=9\\23\\00\\00%s)", \
                 bufc, bufc, bufc);
        if (conf.mode & MODE_IPV6) {
            snprintf(bufd, sizeof(bufd), "(networkAddress=10\\23\\00\\00%s)(networkAddress=11\\23\\00\\00%s))", \
                     bufc, bufc);
            strncat(bufb, bufd, sizeof(bufb));
        } else
            strncat(bufb, ")", sizeof(bufb));
//    debug("SearchFilterLDAP", "bufb: %s\n", bufb);
        strncat(bufa, bufb, sizeof(bufa));
        strncat(bufa, "))", sizeof(bufa));
    }
    s = strlen(bufa);
    strcpy(l->search_filter, bufa);
    return s;
}

/*
 * SearchLDAP() - <ldap_t> <scope> <filter> <attrib>
 *
 * Initate LDAP query, under <scope> levels, filtering matches with <filter> and optionally <attrib>
 * <attrib> will generally be networkAddress ...
 *
 */
int SearchLDAP(ldap_t *l, int scope, char *filter, char **attrs)
{
    int s;
    char ft[MAXLEN];
    if (l == NULL) return LDAP_ERR_NULL;
    if ((scope < 0) || (filter == NULL)) return LDAP_ERR_PARAM;		/* If attrs is NULL, then all attrs will return */
    if (l->lp == NULL) return LDAP_ERR_POINTER;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;			/* Not initalized */
    if (!(l->status & LDAP_OPEN_S)) return LDAP_ERR_OPEN;			/* Not open */
    if (!(l->status & LDAP_BIND_S)) return LDAP_ERR_BIND;			/* Not bound */
    if (l->status & LDAP_SEARCH_S) return LDAP_ERR_SEARCHED;		/* Already searching */
    if (l->basedn[0] == '\0') return LDAP_ERR_DATA;			/* We require a basedn */
    if (l->lm != NULL)
        ldap_msgfree(l->lm);						/* Make sure l->lm is empty */

    if (filter == NULL)							/* if filter is NULL, then return ALL networkAddress */
        strcpy(ft, "(&(objectClass=User)(networkAddress=*))");
    else
        strncpy(ft, filter, sizeof(ft));

    /* We have a binded connection, with a free l->lm, so let's get this done */
    switch (scope) {
    case 0:
        s = ldap_search_s(l->lp, l->basedn, LDAP_SCOPE_BASE, ft, attrs, 0, &(l->lm));
        break;
    case 1:
        s = ldap_search_s(l->lp, l->basedn, LDAP_SCOPE_ONELEVEL, ft, attrs, 0, &(l->lm));
        break;
    case 2:
        s = ldap_search_s(l->lp, l->basedn, LDAP_SCOPE_SUBTREE, ft, attrs, 0, &(l->lm));
        break;
    default:
        /* Only search BASE by default */
        s = ldap_search_s(l->lp, l->basedn, LDAP_SCOPE_BASE, ft, attrs, 0, &(l->lm));
        break;
    }
    if (s == LDAP_SUCCESS) {
        l->status |= (LDAP_SEARCH_S);					/* Mark as searched */
        l->err = s;
        l->idle_time = 0;							/* Connection in use, reset idle timer */
        l->num_ent = ldap_count_entries(l->lp, l->lm);			/* Counted */
        return LDAP_ERR_SUCCESS;
    } else {
        l->err = s;
        l->num_ent = (-1);
        return LDAP_ERR_FAILED;
    }
}

/*
 * GetValLDAP() - <ldap_t> <search-attr>
 *
 * Scan LDAP and look for search-attr, then return results in l->val
 *
 */
int GetValLDAP(ldap_t *l, char *attr)
{
    ber_len_t x;
    /*
      ber_len_t i, j;
      int c;
    */
    LDAPMessage *ent;
    if (l == NULL) return LDAP_ERR_NULL;
    if (attr == NULL) return LDAP_ERR_PARAM;
    if (l->lp == NULL) return LDAP_ERR_POINTER;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;			/* Not initalized */
    if (!(l->status & LDAP_OPEN_S)) return LDAP_ERR_OPEN;			/* Not open */
    if (!(l->status & LDAP_BIND_S)) return LDAP_ERR_BIND;			/* Not bound */
    if (!(l->status & LDAP_SEARCH_S)) return LDAP_ERR_NOT_SEARCHED;	/* Not searched */
    if (l->num_ent <= 0) return LDAP_ERR_DATA;				/* No entries found */
    if (l->val != NULL)
        ldap_value_free_len(l->val);					/* Clear data before populating */
    l->num_val = 0;
    if (l->status & LDAP_VAL_S)
        l->status &= ~(LDAP_VAL_S);						/* Clear VAL bit */

    /* Sift through entries -- Look for matches */
    for (ent = ldap_first_entry(l->lp, l->lm); ent != NULL; ent = ldap_next_entry(l->lp, ent)) {
        l->val = ldap_get_values_len(l->lp, ent, attr);
        if (l->val != NULL) {
            x = ldap_count_values_len(l->val);				/* We got x values ... */
            l->num_val = x;
            if (x > 0) {
                /* Display all values */
                /*
                	for (i = 0; i < x; i++) {
                	  debug("GetValLDAP", "value[%zd]: \"%s\"\n", i, l->val[i]->bv_val);
                	  debug("GetValLDAP", "value[%zd]: ", i);
                	  for (j = 0; j < (l->val[i]->bv_len); j++) {
                	    c = (int) l->val[i]->bv_val[j];
                	    if (c < 0)
                	      c = c + 256;
                	    debugx("%.2X", c);
                	  }
                	  debugx("\n");
                	}
                */
                /*	CRASHES?!?!
                	if (ent != NULL)
                	  ldap_msgfree(ent);
                */
                if (l->lm != NULL) {
                    ldap_msgfree(l->lm);
                    l->lm = NULL;
                }
                l->num_ent = 0;
                l->status &= ~(LDAP_SEARCH_S);
                l->status |= LDAP_VAL_S;
                l->err = LDAP_SUCCESS;
                return LDAP_ERR_SUCCESS;					/* Found it */
            }
        }
        /* Attr not found, continue */
    }
    /* No entries found using attr */
    if (l->val != NULL)
        ldap_value_free_len(l->val);
    /*
      if (ent != NULL)
        ldap_msgfree(ent);
    */
    if (l->lm != NULL) {
        ldap_msgfree(l->lm);
        l->lm = NULL;
    }
    l->num_ent = 0;
    l->num_val = 0;
    l->err = LDAP_NO_SUCH_OBJECT;
    l->status &= ~(LDAP_SEARCH_S);
    return LDAP_ERR_NOTFOUND;						/* Not found */
}

/*
 * SearchIPLDAP() - <ldap_t> <result-uid>
 *
 * Scan LDAP and get all networkAddress Values, and see if they match l->search_ip
 * Actual IP matching routine for eDirectory
 *
 */
int SearchIPLDAP(ldap_t *l, char *uid)
{
    ber_len_t i, x;
    ber_len_t j, k;
    ber_len_t y, z;
    int c;
    char bufa[MAXLEN], bufb[MAXLEN], hexc[4];
    LDAPMessage *ent;
    struct berval **ber;
    if (l == NULL) return LDAP_ERR_NULL;
    if (uid == NULL) return LDAP_ERR_PARAM;
    if (l->lp == NULL) return LDAP_ERR_POINTER;
    if (!(l->status & LDAP_INIT_S)) return LDAP_ERR_INIT;			/* Not initalized */
    if (!(l->status & LDAP_OPEN_S)) return LDAP_ERR_OPEN;			/* Not open */
    if (!(l->status & LDAP_BIND_S)) return LDAP_ERR_BIND;			/* Not bound */
    if (!(l->status & LDAP_SEARCH_S)) return LDAP_ERR_NOT_SEARCHED;	/* Not searched */
    if (l->num_ent <= 0) return LDAP_ERR_DATA;				/* No entries found */
    if (l->val != NULL)
        ldap_value_free_len(l->val);					/* Clear data before populating */
    l->num_val = 0;
    if (l->status & LDAP_VAL_S)
        l->status &= ~(LDAP_VAL_S);						/* Clear VAL bit */

    /* Sift through entries */
    for (ent = ldap_first_entry(l->lp, l->lm); ent != NULL; ent = ldap_next_entry(l->lp, ent)) {
        l->val = ldap_get_values_len(l->lp, ent, "networkAddress");
        ber = ldap_get_values_len(l->lp, ent, conf.attrib);			/* conf.attrib is the <userid> mapping */
        if (l->val != NULL) {
            x = ldap_count_values_len(l->val);				/* We got x values ... */
            l->num_val = x;
            if (x > 0) {
                /* Display all values */
                for (i = 0; i < x; i++) {
                    j = l->val[i]->bv_len;
                    memcpy(bufa, l->val[i]->bv_val, j);
                    z = SplitString(bufa, j, '#', bufb, sizeof(bufb));
                    /*
                    	  debug("SearchIPLDAP", "value[%zd]: SplitString(", i);
                    	  for (k = 0; k < z; k++) {
                    	    c = (int) bufb[k];
                    	    if (c < 0)
                    	      c = c + 256;
                    	    debugx("%.2X", c);
                    	  }
                    	  debugx(", ");
                    	  for (k = 0; k < (j - z - 1); k++) {
                    	    c = (int) bufa[k];
                    	    if (c < 0)
                    	      c = c + 256;
                    	    debugx("%.2X", c);
                    	  }
                    	  debugx("): %zd\n", z);
                    */
                    z = j - z - 1;
                    j = atoi(bufb);
                    switch (j) {
                    case 0:							/* IPX address (We don't support these right now) */
                        break;
                    case 1:							/* IPv4 address (eDirectory 8.7 and below) */
                        /* bufa is the address, just compare it */
                        if (!(l->status & LDAP_IPV4_S) || (l->status & LDAP_IPV6_S))
                            break;							/* Not looking for IPv4 */
                        for (k = 0; k < z; k++) {
                            c = (int) bufa[k];
                            if (c < 0)
                                c = c + 256;
                            snprintf(hexc, sizeof(hexc), "%.2X", c);
                            if (k == 0)
                                strncpy(bufb, hexc, sizeof(bufb));
                            else
                                strncat(bufb, hexc, sizeof(bufb));
                        }
                        y = strlen(bufb);
                        /* Compare value with IP */
                        if (bcmp(l->search_ip, bufb, y) == 0) {
                            /* We got a match! - Scan 'ber' for 'cn' values */
                            z = ldap_count_values_len(ber);
                            for (j = 0; j < z; j++)
                                strncpy(uid, ber[j]->bv_val, ber[j]->bv_len);
                            ldap_value_free_len(l->val);
                            l->val = NULL;
                            ldap_value_free_len(ber);
                            ber = NULL;
                            l->num_val = 0;
                            l->err = LDAP_SUCCESS;
                            l->status &= ~(LDAP_SEARCH_S);
                            return LDAP_ERR_SUCCESS;				/* We got our userid */
                        }
                        /* Not matched, continue */
                        break;
                    case 8:							/* IPv4 (UDP) address (eDirectory 8.8 and higher) */
                        /* bufa + 2 is the address (skip 2 digit port) */
                        if (!(l->status & LDAP_IPV4_S) || (l->status & LDAP_IPV6_S))
                            break;							/* Not looking for IPv4 */
                        for (k = 2; k < z; k++) {
                            c = (int) bufa[k];
                            if (c < 0)
                                c = c + 256;
                            snprintf(hexc, sizeof(hexc), "%.2X", c);
                            if (k == 2)
                                strncpy(bufb, hexc, sizeof(bufb));
                            else
                                strncat(bufb, hexc, sizeof(bufb));
                        }
                        y = strlen(bufb);
                        /* Compare value with IP */
                        if (bcmp(l->search_ip, bufb, y) == 0) {
                            /* We got a match! - Scan 'ber' for 'cn' values */
                            z = ldap_count_values_len(ber);
                            for (j = 0; j < z; j++)
                                strncpy(uid, ber[j]->bv_val, ber[j]->bv_len);
                            ldap_value_free_len(l->val);
                            l->val = NULL;
                            ldap_value_free_len(ber);
                            ber = NULL;
                            l->num_val = 0;
                            l->err = LDAP_SUCCESS;
                            l->status &= ~(LDAP_SEARCH_S);
                            return LDAP_ERR_SUCCESS;				/* We got our userid */
                        }
                        /* Not matched, continue */
                        break;
                    case 9:							/* IPv4 (TCP) address (eDirectory 8.8 and higher) */
                        /* bufa + 2 is the address (skip 2 digit port) */
                        if (!(l->status & LDAP_IPV4_S) || (l->status & LDAP_IPV6_S))
                            break;							/* Not looking for IPv4 */
                        for (k = 2; k < z; k++) {
                            c = (int) bufa[k];
                            if (c < 0)
                                c = c + 256;
                            snprintf(hexc, sizeof(hexc), "%.2X", c);
                            if (k == 2)
                                strncpy(bufb, hexc, sizeof(bufb));
                            else
                                strncat(bufb, hexc, sizeof(bufb));
                        }
                        y = strlen(bufb);
                        /* Compare value with IP */
                        if (bcmp(l->search_ip, bufb, y) == 0) {
                            /* We got a match! - Scan 'ber' for 'cn' values */
                            z = ldap_count_values_len(ber);
                            for (j = 0; j < z; j++)
                                strncpy(uid, ber[j]->bv_val, ber[j]->bv_len);
                            ldap_value_free_len(l->val);
                            l->val = NULL;
                            ldap_value_free_len(ber);
                            ber = NULL;
                            l->num_val = 0;
                            l->err = LDAP_SUCCESS;
                            l->status &= ~(LDAP_SEARCH_S);
                            return LDAP_ERR_SUCCESS;				/* We got our userid */
                        }
                        /* Not matched, continue */
                        break;
                    case 10:							/* IPv6 (UDP) address (eDirectory 8.8 and higher) */
                        /* bufa + 2 is the address (skip 2 digit port) */
                        if (!(l->status & LDAP_IPV6_S))
                            break;							/* Not looking for IPv6 */
                        for (k = 2; k < z; k++) {
                            c = (int) bufa[k];
                            if (c < 0)
                                c = c + 256;
                            snprintf(hexc, sizeof(hexc), "%.2X", c);
                            if (k == 2)
                                strncpy(bufb, hexc, sizeof(bufb));
                            else
                                strncat(bufb, hexc, sizeof(bufb));
                        }
                        y = strlen(bufb);
                        /* Compare value with IP */
                        if (bcmp(l->search_ip, bufb, y) == 0) {
                            /* We got a match! - Scan 'ber' for 'cn' values */
                            z = ldap_count_values_len(ber);
                            for (j = 0; j < z; j++)
                                strncpy(uid, ber[j]->bv_val, ber[j]->bv_len);
                            ldap_value_free_len(l->val);
                            l->val = NULL;
                            ldap_value_free_len(ber);
                            ber = NULL;
                            l->num_val = 0;
                            l->err = LDAP_SUCCESS;
                            l->status &= ~(LDAP_SEARCH_S);
                            return LDAP_ERR_SUCCESS;				/* We got our userid */
                        }
                        /* Not matched, continue */
                        break;
                    case 11:							/* IPv6 (TCP) address (eDirectory 8.8 and higher) */
                        /* bufa + 2 is the address (skip 2 digit port) */
                        if (!(l->status & LDAP_IPV6_S))
                            break;							/* Not looking for IPv6 */
                        for (k = 2; k < z; k++) {
                            c = (int) bufa[k];
                            if (c < 0)
                                c = c + 256;
                            snprintf(hexc, sizeof(hexc), "%.2X", c);
                            if (k == 2)
                                strncpy(bufb, hexc, sizeof(bufb));
                            else
                                strncat(bufb, hexc, sizeof(bufb));
                        }
                        y = strlen(bufb);
                        /* Compare value with IP */
                        if (bcmp(l->search_ip, bufb, y) == 0) {
                            /* We got a match! - Scan 'ber' for 'cn' values */
                            z = ldap_count_values_len(ber);
                            for (j = 0; j < z; j++)
                                strncpy(uid, ber[j]->bv_val, ber[j]->bv_len);
                            ldap_value_free_len(l->val);
                            l->val = NULL;
                            ldap_value_free_len(ber);
                            ber = NULL;
                            l->num_val = 0;
                            l->err = LDAP_SUCCESS;
                            l->status &= ~(LDAP_SEARCH_S);
                            return LDAP_ERR_SUCCESS;				/* We gout our userid */
                        }
                        /* Not matched, continue */
                        break;
                    default:							/* Other, unsupported */
                        break;
                    }
                }
                if (ber != NULL) {
                    ldap_value_free_len(ber);
                    ber = NULL;
                }
            }
            ldap_value_free_len(l->val);
            l->val = NULL;
        }
        if (ber != NULL) {
            ldap_value_free_len(ber);
            ber = NULL;
        }
        /* Attr not found, continue */
    }
    /* No entries found using given attr */
    if (l->val != NULL) {
        ldap_value_free_len(l->val);
        l->val = NULL;
    }
    if (ber != NULL) {
        ldap_value_free_len(ber);
        ber = NULL;
    }
    if (ent != NULL) {
        ldap_msgfree(ent);
        ent = NULL;
    }
    if (l->lm != NULL) {
        ldap_msgfree(l->lm);
        l->lm = NULL;
    }
    l->num_ent = 0;
    l->num_val = 0;
    l->err = LDAP_NO_SUCH_OBJECT;
    l->status &= ~(LDAP_SEARCH_S);
    return LDAP_ERR_NOTFOUND;						/* Not found ... Sorry :) */
}

char *ErrLDAP(int e)
{
    switch (e) {
    case LDAP_ERR_NULL:
        return "Null pointer provided";
    case LDAP_ERR_POINTER:
        return "Null LDAP pointer";
    case LDAP_ERR_PARAM:
        return "Null or Missing paremeter(s)";
    case LDAP_ERR_INIT:
        return "LDAP data not initalized";
    case LDAP_ERR_OPEN:
        return "LDAP connection is not active";
    case LDAP_ERR_CONNECT:
        return "Unable to connect to LDAP host";
    case LDAP_ERR_BIND:
        return "LDAP connection is not bound";
    case LDAP_ERR_SEARCHED:
        return "LDAP connection has already been searched";
    case LDAP_ERR_NOT_SEARCHED:
        return "LDAP connection has not been searched";
    case LDAP_ERR_INVALID:
        return "Invalid paremeters";
    case LDAP_ERR_OOB:
        return "Paremeter is out of bounds";
    case LDAP_ERR_PERSIST:
        return "Persistent mode is not active";
    case LDAP_ERR_DATA:
        return "Required data has not been found";
    case LDAP_ERR_NOTFOUND:
        return "Item or object has not been found";
    case LDAP_ERR_OTHER:
        return "An unknown error has occured";
    case LDAP_ERR_FAILED:
        return "Operation has failed";
    case LDAP_ERR_SUCCESS:
        return "Operation is successful";
    default:
        return "An unknown error has occured";
    }
}
