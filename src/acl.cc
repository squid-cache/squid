
/*
 * $Id: acl.cc,v 1.262 2001/10/17 10:59:08 adrian Exp $
 *
 * DEBUG: section 28    Access Control
 * AUTHOR: Duane Wessels
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

#include "squid.h"
#include "splay.h"

static int aclFromFile = 0;
static FILE *aclFile;

static void aclParseDomainList (void *curlist);
static void aclParseUserList (void **current);
static void aclParseIpList (void *curlist);
static void aclParseIntlist (void *curlist);
#if SQUID_SNMP
static void aclParseWordList (void *curlist);
#endif
static void aclParseProtoList (void *curlist);
static void aclParseMethodList (void *curlist);
static void aclParseTimeSpec (void *curlist);
static void aclParseIntRange (void *curlist);
static char *strtokFile (void);
static void aclDestroyTimeList (acl_time_data * data);
static void aclDestroyIntRange (intrange *);
static void aclLookupProxyAuthStart (aclCheck_t * checklist);
static void aclLookupProxyAuthDone (void *data, char *result);
static struct _acl *aclFindByName (const char *name);
static int aclMatchAcl (struct _acl *, aclCheck_t *);
static int aclMatchTime (acl_time_data * data, time_t when);
static int aclMatchUser (void *proxyauth_acl, char *user);
static int aclMatchIp (void *dataptr, struct in_addr c);
static int aclMatchDomainList (void *dataptr, const char *);
static int aclMatchIntegerRange (intrange * data, int i);
#if SQUID_SNMP
static int aclMatchWordList (wordlist *, const char *);
#endif
static void aclParseUserMaxIP (void *data);
static void aclDestroyUserMaxIP (void *data);
static wordlist *aclDumpUserMaxIP (void *data);
static int aclMatchUserMaxIP (void *, auth_user_request_t *, struct in_addr);
static squid_acl aclStrToType (const char *s);
static int decode_addr (const char *, struct in_addr *, struct in_addr *);
static void aclCheck (aclCheck_t * checklist);
static void aclCheckCallback (aclCheck_t * checklist, allow_t answer);
#if USE_IDENT
static IDCB aclLookupIdentDone;
#endif
static IPH aclLookupDstIPDone;
static IPH aclLookupDstIPforASNDone;
static FQDNH aclLookupSrcFQDNDone;
static FQDNH aclLookupDstFQDNDone;
static wordlist *aclDumpIpList (void *);
static wordlist *aclDumpDomainList (void *data);
static wordlist *aclDumpTimeSpecList (acl_time_data *);
static wordlist *aclDumpRegexList (relist * data);
static wordlist *aclDumpIntlistList (intlist * data);
static wordlist *aclDumpIntRangeList (intrange * data);
static wordlist *aclDumpProtoList (intlist * data);
static wordlist *aclDumpMethodList (intlist * data);
static SPLAYCMP aclIpNetworkCompare;
static SPLAYCMP aclHostDomainCompare;
static SPLAYCMP aclDomainCompare;
static SPLAYWALKEE aclDumpIpListWalkee;
static SPLAYWALKEE aclDumpDomainListWalkee;
static SPLAYFREE aclFreeIpData;

#if USE_ARP_ACL
static void aclParseArpList (void *curlist);
static int decode_eth (const char *asc, char *eth);
static int aclMatchArp (void *dataptr, struct in_addr c);
static wordlist *aclDumpArpList (void *);
static SPLAYCMP aclArpCompare;
static SPLAYWALKEE aclDumpArpListWalkee;
#endif
static int aclCacheMatchAcl (dlink_list * cache, squid_acl acltype, void *data, char *MatchParam);

static char *
strtokFile (void)
{
  char *t, *fn;
  LOCAL_ARRAY (char, buf, 256);

strtok_again:
  if (!aclFromFile)
    {
      t = (strtok (NULL, w_space));
      if (t && (*t == '\"' || *t == '\''))
	{
	  /* quote found, start reading from file */
	  fn = ++t;
	  while (*t && *t != '\"' && *t != '\'')
	    t++;
	  *t = '\0';
	  if ((aclFile = fopen (fn, "r")) == NULL)
	    {
	      debug (28, 0) ("strtokFile: %s not found\n", fn);
	      return (NULL);
	    }
#if defined(_SQUID_CYGWIN_)
	  setmode (fileno (aclFile), O_TEXT);
#endif
	  aclFromFile = 1;
	}
      else
	{
	  return t;
	}
    }
  /* aclFromFile */
  if (fgets (buf, 256, aclFile) == NULL)
    {
      /* stop reading from file */
      fclose (aclFile);
      aclFromFile = 0;
      goto strtok_again;
    }
  else
    {
      t = buf;
      /* skip leading and trailing white space */
      t += strspn (buf, w_space);
      t[strcspn (t, w_space)] = '\0';
      /* skip comments */
      if (*t == '#')
	goto strtok_again;
      /* skip blank lines */
      if (!*t)
	goto strtok_again;
      return t;
    }
}

static squid_acl
aclStrToType (const char *s)
{
  if (!strcmp (s, "src"))
    return ACL_SRC_IP;
  if (!strcmp (s, "dst"))
    return ACL_DST_IP;
  if (!strcmp (s, "myip"))
    return ACL_MY_IP;
  if (!strcmp (s, "domain"))
    return ACL_DST_DOMAIN;
  if (!strcmp (s, "dstdomain"))
    return ACL_DST_DOMAIN;
  if (!strcmp (s, "srcdomain"))
    return ACL_SRC_DOMAIN;
  if (!strcmp (s, "dstdom_regex"))
    return ACL_DST_DOM_REGEX;
  if (!strcmp (s, "srcdom_regex"))
    return ACL_SRC_DOM_REGEX;
  if (!strcmp (s, "time"))
    return ACL_TIME;
  if (!strcmp (s, "pattern"))
    return ACL_URLPATH_REGEX;
  if (!strcmp (s, "urlpath_regex"))
    return ACL_URLPATH_REGEX;
  if (!strcmp (s, "url_regex"))
    return ACL_URL_REGEX;
  if (!strcmp (s, "port"))
    return ACL_URL_PORT;
  if (!strcmp (s, "myport"))
    return ACL_MY_PORT;
  if (!strcmp (s, "maxconn"))
    return ACL_MAXCONN;
#if USE_IDENT
  if (!strcmp (s, "ident"))
    return ACL_IDENT;
  if (!strcmp (s, "ident_regex"))
    return ACL_IDENT_REGEX;
#endif
  if (!strncmp (s, "proto", 5))
    return ACL_PROTO;
  if (!strcmp (s, "method"))
    return ACL_METHOD;
  if (!strcmp (s, "browser"))
    return ACL_BROWSER;
  if (!strcmp (s, "proxy_auth"))
    return ACL_PROXY_AUTH;
  if (!strcmp (s, "proxy_auth_regex"))
    return ACL_PROXY_AUTH_REGEX;
  if (!strcmp (s, "src_as"))
    return ACL_SRC_ASN;
  if (!strcmp (s, "dst_as"))
    return ACL_DST_ASN;
#if SQUID_SNMP
  if (!strcmp (s, "snmp_community"))
    return ACL_SNMP_COMMUNITY;
#endif
#if SRC_RTT_NOT_YET_FINISHED
  if (!strcmp (s, "src_rtt"))
    return ACL_NETDB_SRC_RTT;
#endif
#if USE_ARP_ACL
  if (!strcmp (s, "arp"))
    return ACL_SRC_ARP;
#endif
  if (!strcmp (s, "req_mime_type"))
    return ACL_REQ_MIME_TYPE;
  if (!strcmp (s, "rep_mime_type"))
    return ACL_REP_MIME_TYPE;
  if (!strcmp (s, "max_user_ip"))
    return ACL_MAX_USER_IP;
  return ACL_NONE;
}

const char *
aclTypeToStr (squid_acl type)
{
  if (type == ACL_SRC_IP)
    return "src";
  if (type == ACL_DST_IP)
    return "dst";
  if (type == ACL_MY_IP)
    return "myip";
  if (type == ACL_DST_DOMAIN)
    return "dstdomain";
  if (type == ACL_SRC_DOMAIN)
    return "srcdomain";
  if (type == ACL_DST_DOM_REGEX)
    return "dstdom_regex";
  if (type == ACL_SRC_DOM_REGEX)
    return "srcdom_regex";
  if (type == ACL_TIME)
    return "time";
  if (type == ACL_URLPATH_REGEX)
    return "urlpath_regex";
  if (type == ACL_URL_REGEX)
    return "url_regex";
  if (type == ACL_URL_PORT)
    return "port";
  if (type == ACL_MY_PORT)
    return "myport";
  if (type == ACL_MAXCONN)
    return "maxconn";
#if USE_IDENT
  if (type == ACL_IDENT)
    return "ident";
  if (type == ACL_IDENT_REGEX)
    return "ident_regex";
#endif
  if (type == ACL_PROTO)
    return "proto";
  if (type == ACL_METHOD)
    return "method";
  if (type == ACL_BROWSER)
    return "browser";
  if (type == ACL_PROXY_AUTH)
    return "proxy_auth";
  if (type == ACL_PROXY_AUTH_REGEX)
    return "proxy_auth_regex";
  if (type == ACL_SRC_ASN)
    return "src_as";
  if (type == ACL_DST_ASN)
    return "dst_as";
#if SQUID_SNMP
  if (type == ACL_SNMP_COMMUNITY)
    return "snmp_community";
#endif
#if SRC_RTT_NOT_YET_FINISHED
  if (type == ACL_NETDB_SRC_RTT)
    return "src_rtt";
#endif
#if USE_ARP_ACL
  if (type == ACL_SRC_ARP)
    return "arp";
#endif
  if (type == ACL_REQ_MIME_TYPE)
    return "req_mime_type";
  if (type == ACL_REP_MIME_TYPE)
    return "rep_mime_type";
  if (type == ACL_MAX_USER_IP)
    return "max_user_ip";
  return "ERROR";
}

static acl *
aclFindByName (const char *name)
{
  acl *a;
  for (a = Config.aclList; a; a = a->next)
    if (!strcasecmp (a->name, name))
      return a;
  return NULL;
}

static void
aclParseIntlist (void *curlist)
{
  intlist **Tail;
  intlist *q = NULL;
  char *t = NULL;
  for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
  while ((t = strtokFile ()))
    {
      q = memAllocate (MEM_INTLIST);
      q->i = atoi (t);
      *(Tail) = q;
      Tail = &q->next;
    }
}

static void
aclParseIntRange (void *curlist)
{
  intrange **Tail;
  intrange *q = NULL;
  char *t = NULL;
  for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
  while ((t = strtokFile ()))
    {
      q = xcalloc (1, sizeof (intrange));
      q->i = atoi (t);
      t = strchr (t, '-');
      if (t && *(++t))
	q->j = atoi (t);
      else
	q->j = q->i;
      *(Tail) = q;
      Tail = &q->next;
    }
}

static void
aclParseProtoList (void *curlist)
{
  intlist **Tail;
  intlist *q = NULL;
  char *t = NULL;
  for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
  while ((t = strtokFile ()))
    {
      q = memAllocate (MEM_INTLIST);
      q->i = (int) urlParseProtocol (t);
      *(Tail) = q;
      Tail = &q->next;
    }
}

static void
aclParseMethodList (void *curlist)
{
  intlist **Tail;
  intlist *q = NULL;
  char *t = NULL;
  for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
  while ((t = strtokFile ()))
    {
      q = memAllocate (MEM_INTLIST);
      q->i = (int) urlParseMethod (t);
      *(Tail) = q;
      Tail = &q->next;
    }
}

/*
 * Decode a ascii representation (asc) of a IP adress, and place
 * adress and netmask information in addr and mask.
 * This function should NOT be called if 'asc' is a hostname!
 */
static int
decode_addr (const char *asc, struct in_addr *addr, struct in_addr *mask)
{
  u_num32 a;
  int a1 = 0, a2 = 0, a3 = 0, a4 = 0;

  switch (sscanf (asc, "%d.%d.%d.%d", &a1, &a2, &a3, &a4))
    {
    case 4:			/* a dotted quad */
      if (!safe_inet_addr (asc, addr))
	{
	  debug (28, 0) ("decode_addr: unsafe IP address: '%s'\n", asc);
	  fatal ("decode_addr: unsafe IP address");
	}
      break;
    case 1:			/* a significant bits value for a mask */
      if (a1 >= 0 && a1 < 33)
	{
	  addr->s_addr = a1 ? htonl (0xfffffffful << (32 - a1)) : 0;
	  break;
	}
    default:
      debug (28, 0) ("decode_addr: Invalid IP address '%s'\n", asc);
      return 0;			/* This is not valid address */
    }

  if (mask != NULL)
    {				/* mask == NULL if called to decode a netmask */

      /* Guess netmask */
      a = (u_num32) ntohl (addr->s_addr);
      if (!(a & 0xFFFFFFFFul))
	mask->s_addr = htonl (0x00000000ul);
      else if (!(a & 0x00FFFFFF))
	mask->s_addr = htonl (0xFF000000ul);
      else if (!(a & 0x0000FFFF))
	mask->s_addr = htonl (0xFFFF0000ul);
      else if (!(a & 0x000000FF))
	mask->s_addr = htonl (0xFFFFFF00ul);
      else
	mask->s_addr = htonl (0xFFFFFFFFul);
    }
  return 1;
}


#define SCAN_ACL1       "%[0123456789.]-%[0123456789.]/%[0123456789.]"
#define SCAN_ACL2       "%[0123456789.]-%[0123456789.]%c"
#define SCAN_ACL3       "%[0123456789.]/%[0123456789.]"
#define SCAN_ACL4       "%[0123456789.]%c"

static acl_ip_data *
aclParseIpData (const char *t)
{
  LOCAL_ARRAY (char, addr1, 256);
  LOCAL_ARRAY (char, addr2, 256);
  LOCAL_ARRAY (char, mask, 256);
  acl_ip_data *q = memAllocate (MEM_ACL_IP_DATA);
  acl_ip_data *r;
  acl_ip_data **Q;
  struct hostent *hp;
  char **x;
  char c;
  debug (28, 5) ("aclParseIpData: %s\n", t);
  if (!strcasecmp (t, "all"))
    {
      q->addr1.s_addr = 0;
      q->addr2.s_addr = 0;
      q->mask.s_addr = 0;
      return q;
    }
  if (sscanf (t, SCAN_ACL1, addr1, addr2, mask) == 3)
    {
      (void) 0;
    }
  else if (sscanf (t, SCAN_ACL2, addr1, addr2, &c) == 2)
    {
      mask[0] = '\0';
    }
  else if (sscanf (t, SCAN_ACL3, addr1, mask) == 2)
    {
      addr2[0] = '\0';
    }
  else if (sscanf (t, SCAN_ACL4, addr1, &c) == 1)
    {
      addr2[0] = '\0';
      mask[0] = '\0';
    }
  else if (sscanf (t, "%[^/]/%s", addr1, mask) == 2)
    {
      addr2[0] = '\0';
    }
  else if (sscanf (t, "%s", addr1) == 1)
    {
      /*
       * Note, must use plain gethostbyname() here because at startup
       * ipcache hasn't been initialized
       */
      if ((hp = gethostbyname (addr1)) == NULL)
	{
	  debug (28, 0) ("aclParseIpData: Bad host/IP: '%s'\n", t);
	  safe_free (q);
	  return NULL;
	}
      Q = &q;
      for (x = hp->h_addr_list; x != NULL && *x != NULL; x++)
	{
	  if ((r = *Q) == NULL)
	    r = *Q = memAllocate (MEM_ACL_IP_DATA);
	  xmemcpy (&r->addr1.s_addr, *x, sizeof (r->addr1.s_addr));
	  r->addr2.s_addr = 0;
	  r->mask.s_addr = no_addr.s_addr;	/* 255.255.255.255 */
	  Q = &r->next;
	  debug (28, 3) ("%s --> %s\n", addr1, inet_ntoa (r->addr1));
	}
      return q;
    }
  else
    {
      debug (28, 0) ("aclParseIpData: Bad host/IP: '%s'\n", t);
      safe_free (q);
      return NULL;
    }
  /* Decode addr1 */
  if (!decode_addr (addr1, &q->addr1, &q->mask))
    {
      debug (28, 0) ("%s line %d: %s\n",
		     cfg_filename, config_lineno, config_input_line);
      debug (28, 0) ("aclParseIpData: Ignoring invalid IP acl entry: unknown first address '%s'\n", addr1);
      safe_free (q);
      return NULL;
    }
  /* Decode addr2 */
  if (*addr2 && !decode_addr (addr2, &q->addr2, &q->mask))
    {
      debug (28, 0) ("%s line %d: %s\n",
		     cfg_filename, config_lineno, config_input_line);
      debug (28, 0) ("aclParseIpData: Ignoring invalid IP acl entry: unknown second address '%s'\n", addr2);
      safe_free (q);
      return NULL;
    }
  /* Decode mask */
  if (*mask && !decode_addr (mask, &q->mask, NULL))
    {
      debug (28, 0) ("%s line %d: %s\n",
		     cfg_filename, config_lineno, config_input_line);
      debug (28, 0) ("aclParseIpData: Ignoring invalid IP acl entry: unknown netmask '%s'\n", mask);
      safe_free (q);
      return NULL;
    }
  if ((q->addr1.s_addr & q->mask.s_addr) != q->addr1.s_addr ||
      (q->addr2.s_addr & q->mask.s_addr) != q->addr2.s_addr)
    debug (28, 0) ("aclParseIpData: WARNING: Netmask masks away part of the specified IP in '%s'\n", t);
  q->addr1.s_addr &= q->mask.s_addr;
  q->addr2.s_addr &= q->mask.s_addr;
  /* 1.2.3.4/255.255.255.0  --> 1.2.3.0 */
  return q;
}

/******************/
/* aclParseIpList */
/******************/

static void
aclParseIpList (void *curlist)
{
  char *t = NULL;
  splayNode **Top = curlist;
  acl_ip_data *q = NULL;
  while ((t = strtokFile ()))
    {
      q = aclParseIpData (t);
      while (q != NULL)
	{
	  *Top = splay_insert (q, *Top, aclIpNetworkCompare);
	  q = q->next;
	}
    }
}

static void
aclParseTimeSpec (void *curlist)
{
  acl_time_data *q = NULL;
  acl_time_data **Tail;
  int h1, m1, h2, m2;
  char *t = NULL;
  for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
  q = memAllocate (MEM_ACL_TIME_DATA);
  while ((t = strtokFile ()))
    {
      if (*t < '0' || *t > '9')
	{
	  /* assume its day-of-week spec */
	  while (*t)
	    {
	      switch (*t++)
		{
		case 'S':
		  q->weekbits |= ACL_SUNDAY;
		  break;
		case 'M':
		  q->weekbits |= ACL_MONDAY;
		  break;
		case 'T':
		  q->weekbits |= ACL_TUESDAY;
		  break;
		case 'W':
		  q->weekbits |= ACL_WEDNESDAY;
		  break;
		case 'H':
		  q->weekbits |= ACL_THURSDAY;
		  break;
		case 'F':
		  q->weekbits |= ACL_FRIDAY;
		  break;
		case 'A':
		  q->weekbits |= ACL_SATURDAY;
		  break;
		case 'D':
		  q->weekbits |= ACL_WEEKDAYS;
		  break;
		case '-':
		  /* ignore placeholder */
		  break;
		default:
		  debug (28, 0) ("%s line %d: %s\n",
			    cfg_filename, config_lineno, config_input_line);
		  debug (28, 0) ("aclParseTimeSpec: Bad Day '%c'\n", *t);
		  break;
		}
	    }
	}
      else
	{
	  /* assume its time-of-day spec */
	  if (sscanf (t, "%d:%d-%d:%d", &h1, &m1, &h2, &m2) < 4)
	    {
	      debug (28, 0) ("%s line %d: %s\n",
			     cfg_filename, config_lineno, config_input_line);
	      debug (28, 0) ("aclParseTimeSpec: IGNORING Bad time range\n");
	      memFree (q, MEM_ACL_TIME_DATA);
	      return;
	    }
	  q->start = h1 * 60 + m1;
	  q->stop = h2 * 60 + m2;
	  if (q->start > q->stop)
	    {
	      debug (28, 0) ("%s line %d: %s\n",
			     cfg_filename, config_lineno, config_input_line);
	      debug (28, 0) ("aclParseTimeSpec: IGNORING Reversed time range\n");
	      memFree (q, MEM_ACL_TIME_DATA);
	      return;
	    }
	}
    }
  if (q->start == 0 && q->stop == 0)
    q->stop = 23 * 60 + 59;
  if (q->weekbits == 0)
    q->weekbits = ACL_ALLWEEK;
  *(Tail) = q;
  Tail = &q->next;
}

void
aclParseRegexList (void *curlist)
{
  relist **Tail;
  relist *q = NULL;
  char *t = NULL;
  regex_t comp;
  int errcode;
  int flags = REG_EXTENDED | REG_NOSUB;
  for (Tail = curlist; *Tail; Tail = &((*Tail)->next));
  while ((t = strtokFile ()))
    {
      if (strcmp (t, "-i") == 0)
	{
	  flags |= REG_ICASE;
	  continue;
	}
      if (strcmp (t, "+i") == 0)
	{
	  flags &= ~REG_ICASE;
	  continue;
	}
      if ((errcode = regcomp (&comp, t, flags)) != 0)
	{
	  char errbuf[256];
	  regerror (errcode, &comp, errbuf, sizeof errbuf);
	  debug (28, 0) ("%s line %d: %s\n",
			 cfg_filename, config_lineno, config_input_line);
	  debug (28, 0) ("aclParseRegexList: Invalid regular expression '%s': %s\n",
			 t, errbuf);
	  continue;
	}
      q = memAllocate (MEM_RELIST);
      q->pattern = xstrdup (t);
      q->regex = comp;
      *(Tail) = q;
      Tail = &q->next;
    }
}

#if SQUID_SNMP
static void
aclParseWordList (void *curlist)
{
  char *t = NULL;
  while ((t = strtokFile ()))
    wordlistAdd (curlist, t);
}
#endif

static void
aclParseUserList (void **current)
{
  char *t = NULL;
  acl_user_data *data;
  splayNode *Top = NULL;

  debug (28, 2) ("aclParseUserList: parsing user list\n");
  if (*current == NULL)
    {
      debug (28, 3) ("aclParseUserList: current is null. Creating\n");
      *current = memAllocate (MEM_ACL_USER_DATA);
    }
  data = *current;
  Top = data->names;
  if ((t = strtokFile ()))
    {
      debug (28, 5) ("aclParseUserList: First token is %s\n", t);
      if (strcmp ("-i", t) == 0)
	{
	  debug (28, 5) ("aclParseUserList: Going case-insensitive\n");
	  data->flags.case_insensitive = 1;
	}
      else if (strcmp ("REQUIRED", t) == 0)
	{
	  debug (28, 5) ("aclParseUserList: REQUIRED-type enabled\n");
	  data->flags.required = 1;
	}
      else
	{
	  if (data->flags.case_insensitive)
	    Tolower (t);
	  Top = splay_insert (xstrdup (t), Top, (SPLAYCMP *) strcmp);
	}
    }
  debug (28, 3) ("aclParseUserList: Case-insensitive-switch is %d\n",
		 data->flags.case_insensitive);
  /* we might inherit from a previous declaration */

  debug (28, 4) ("aclParseUserList: parsing user list\n");
  while ((t = strtokFile ()))
    {
      debug (28, 6) ("aclParseUserList: Got token: %s\n", t);
      if (data->flags.case_insensitive)
	Tolower (t);
      Top = splay_insert (xstrdup (t), Top, (SPLAYCMP *) strcmp);
    }
  data->names = Top;
}


/**********************/
/* aclParseDomainList */
/**********************/

static void
aclParseDomainList (void *curlist)
{
  char *t = NULL;
  splayNode **Top = curlist;
  while ((t = strtokFile ()))
    {
      Tolower (t);
      *Top = splay_insert (xstrdup (t), *Top, aclDomainCompare);
    }
}

void
aclParseAclLine (acl ** head)
{
  /* we're already using strtok() to grok the line */
  char *t = NULL;
  acl *A = NULL;
  LOCAL_ARRAY (char, aclname, ACL_NAME_SZ);
  squid_acl acltype;
  int new_acl = 0;

  /* snarf the ACL name */
  if ((t = strtok (NULL, w_space)) == NULL)
    {
      debug (28, 0) ("%s line %d: %s\n",
		     cfg_filename, config_lineno, config_input_line);
      debug (28, 0) ("aclParseAclLine: missing ACL name.\n");
      return;
    }
  xstrncpy (aclname, t, ACL_NAME_SZ);
  /* snarf the ACL type */
  if ((t = strtok (NULL, w_space)) == NULL)
    {
      debug (28, 0) ("%s line %d: %s\n",
		     cfg_filename, config_lineno, config_input_line);
      debug (28, 0) ("aclParseAclLine: missing ACL type.\n");
      return;
    }
  if ((acltype = aclStrToType (t)) == ACL_NONE)
    {
      debug (28, 0) ("%s line %d: %s\n",
		     cfg_filename, config_lineno, config_input_line);
      debug (28, 0) ("aclParseAclLine: Invalid ACL type '%s'\n", t);
      return;
    }
  if ((A = aclFindByName (aclname)) == NULL)
    {
      debug (28, 3) ("aclParseAclLine: Creating ACL '%s'\n", aclname);
      A = memAllocate (MEM_ACL);
      xstrncpy (A->name, aclname, ACL_NAME_SZ);
      A->type = acltype;
      A->cfgline = xstrdup (config_input_line);
      new_acl = 1;
    }
  else
    {
      if (acltype != A->type)
	{
	  debug (28, 0) ("aclParseAclLine: ACL '%s' already exists with different type, skipping.\n", A->name);
	  return;
	}
      debug (28, 3) ("aclParseAclLine: Appending to '%s'\n", aclname);
      new_acl = 0;
    }
  /*
   * Here we set AclMatchedName in case we need to use it in a
   * warning message in aclDomainCompare().
   */
  AclMatchedName = aclname;	/* ugly */
  switch (A->type)
    {
    case ACL_SRC_IP:
    case ACL_DST_IP:
    case ACL_MY_IP:
      aclParseIpList (&A->data);
      break;
    case ACL_SRC_DOMAIN:
    case ACL_DST_DOMAIN:
      aclParseDomainList (&A->data);
      break;
    case ACL_TIME:
      aclParseTimeSpec (&A->data);
      break;
    case ACL_URL_REGEX:
    case ACL_URLPATH_REGEX:
    case ACL_BROWSER:
    case ACL_SRC_DOM_REGEX:
    case ACL_DST_DOM_REGEX:
    case ACL_REQ_MIME_TYPE:
    case ACL_REP_MIME_TYPE:
      aclParseRegexList (&A->data);
      break;
    case ACL_SRC_ASN:
    case ACL_MAXCONN:
    case ACL_DST_ASN:
      aclParseIntlist (&A->data);
      break;
    case ACL_MAX_USER_IP:
      aclParseUserMaxIP (&A->data);
      break;
#if SRC_RTT_NOT_YET_FINISHED
    case ACL_NETDB_SRC_RTT:
      aclParseIntlist (&A->data);
      break;
#endif
    case ACL_URL_PORT:
    case ACL_MY_PORT:
      aclParseIntRange (&A->data);
      break;
#if USE_IDENT
    case ACL_IDENT:
      aclParseUserList (&A->data);
      break;
    case ACL_IDENT_REGEX:
      aclParseRegexList (&A->data);
      break;
#endif
    case ACL_PROTO:
      aclParseProtoList (&A->data);
      break;
    case ACL_METHOD:
      aclParseMethodList (&A->data);
      break;
    case ACL_PROXY_AUTH:
      if (authenticateSchemeCount () == 0)
	{
	  debug (28, 0) ("aclParseAclLine: IGNORING: Proxy Auth ACL '%s' \
because no authentication schemes were compiled.\n", A->cfgline);
	}
      else if (authenticateActiveSchemeCount () == 0)
	{
	  debug (28, 0) ("aclParseAclLine: IGNORING: Proxy Auth ACL '%s' \
because no authentication schemes are fully configured.\n", A->cfgline);
	}
      else
	{
	  aclParseUserList (&A->data);
	}
      break;
    case ACL_PROXY_AUTH_REGEX:
      if (authenticateSchemeCount () == 0)
	{
	  debug (28, 0) ("aclParseAclLine: IGNORING: Proxy Auth ACL '%s' \
because no authentication schemes were compiled.\n", A->cfgline);
	}
      else if (authenticateActiveSchemeCount () == 0)
	{
	  debug (28, 0) ("aclParseAclLine: IGNORING: Proxy Auth ACL '%s' \
because no authentication schemes are fully configured.\n", A->cfgline);
	}
      else
	{
	  aclParseRegexList (&A->data);
	}
      break;
#if SQUID_SNMP
    case ACL_SNMP_COMMUNITY:
      aclParseWordList (&A->data);
      break;
#endif
#if USE_ARP_ACL
    case ACL_SRC_ARP:
      aclParseArpList (&A->data);
      break;
#endif
    case ACL_NONE:
    case ACL_ENUM_MAX:
      fatal ("Bad ACL type");
      break;
    }
  /*
   * Clear AclMatchedName from our temporary hack
   */
  AclMatchedName = NULL;	/* ugly */
  if (!new_acl)
    return;
  if (A->data == NULL)
    {
      debug (28, 0) ("aclParseAclLine: IGNORING invalid ACL: %s\n",
		     A->cfgline);
      memFree (A, MEM_ACL);
      return;
    }
  /* append */
  while (*head)
    head = &(*head)->next;
  *head = A;
}

/* does name lookup, returns page_id */
err_type
aclGetDenyInfoPage (acl_deny_info_list ** head, const char *name)
{
  acl_deny_info_list *A = NULL;
  acl_name_list *L = NULL;

  A = *head;
  if (NULL == *head)		/* empty list */
    return ERR_NONE;
  while (A)
    {
      L = A->acl_list;
      if (NULL == L)		/* empty list should never happen, but in case */
	continue;
      while (L)
	{
	  if (!strcmp (name, L->name))
	    return A->err_page_id;
	  L = L->next;
	}
      A = A->next;
    }
  return ERR_NONE;
}

/* does name lookup, returns if it is a proxy_auth acl */
int
aclIsProxyAuth (const char *name)
{
  acl *a;
  if (NULL == name)
    return 0;
  if ((a = aclFindByName (name)))
    return a->type == ACL_PROXY_AUTH;
  return 0;
}


/* maex@space.net (05.09.96)
 *    get the info for redirecting "access denied" to info pages
 *      TODO (probably ;-)
 *      currently there is no optimization for
 *      - more than one deny_info line with the same url
 *      - a check, whether the given acl really is defined
 *      - a check, whether an acl is added more than once for the same url
 */

void
aclParseDenyInfoLine (acl_deny_info_list ** head)
{
  char *t = NULL;
  acl_deny_info_list *A = NULL;
  acl_deny_info_list *B = NULL;
  acl_deny_info_list **T = NULL;
  acl_name_list *L = NULL;
  acl_name_list **Tail = NULL;

  /* first expect a page name */
  if ((t = strtok (NULL, w_space)) == NULL)
    {
      debug (28, 0) ("%s line %d: %s\n",
		     cfg_filename, config_lineno, config_input_line);
      debug (28, 0) ("aclParseDenyInfoLine: missing 'error page' parameter.\n");
      return;
    }
  A = memAllocate (MEM_ACL_DENY_INFO_LIST);
  A->err_page_id = errorReservePageId (t);
  A->err_page_name = xstrdup (t);
  A->next = (acl_deny_info_list *) NULL;
  /* next expect a list of ACL names */
  Tail = &A->acl_list;
  while ((t = strtok (NULL, w_space)))
    {
      L = memAllocate (MEM_ACL_NAME_LIST);
      xstrncpy (L->name, t, ACL_NAME_SZ);
      *Tail = L;
      Tail = &L->next;
    }
  if (A->acl_list == NULL)
    {
      debug (28, 0) ("%s line %d: %s\n",
		     cfg_filename, config_lineno, config_input_line);
      debug (28, 0) ("aclParseDenyInfoLine: deny_info line contains no ACL's, skipping\n");
      memFree (A, MEM_ACL_DENY_INFO_LIST);
      return;
    }
  for (B = *head, T = head; B; T = &B->next, B = B->next);	/* find the tail */
  *T = A;
}

void
aclParseAccessLine (acl_access ** head)
{
  char *t = NULL;
  acl_access *A = NULL;
  acl_access *B = NULL;
  acl_access **T = NULL;

  /* first expect either 'allow' or 'deny' */
  if ((t = strtok (NULL, w_space)) == NULL)
    {
      debug (28, 0) ("%s line %d: %s\n",
		     cfg_filename, config_lineno, config_input_line);
      debug (28, 0) ("aclParseAccessLine: missing 'allow' or 'deny'.\n");
      return;
    }
  A = cbdataAlloc (acl_access);

  if (!strcmp (t, "allow"))
    A->allow = 1;
  else if (!strcmp (t, "deny"))
    A->allow = 0;
  else
    {
      debug (28, 0) ("%s line %d: %s\n",
		     cfg_filename, config_lineno, config_input_line);
      debug (28, 0) ("aclParseAccessLine: expecting 'allow' or 'deny', got '%s'.\n", t);
      cbdataFree (A);
      return;
    }
  aclParseAclList (&A->acl_list);
  if (A->acl_list == NULL)
    {
      debug (28, 0) ("%s line %d: %s\n",
		     cfg_filename, config_lineno, config_input_line);
      debug (28, 0) ("aclParseAccessLine: Access line contains no ACL's, skipping\n");
      cbdataFree (A);
      return;
    }
  A->cfgline = xstrdup (config_input_line);
  /* Append to the end of this list */
  for (B = *head, T = head; B; T = &B->next, B = B->next);
  *T = A;
  /* We lock _acl_access structures in aclCheck() */
}

void
aclParseAclList (acl_list ** head)
{
  acl_list *L = NULL;
  acl_list **Tail = head;	/* sane name in the use below */
  acl *a = NULL;
  char *t;

  /* next expect a list of ACL names, possibly preceeded
   * by '!' for negation */
  while ((t = strtok (NULL, w_space)))
    {
      L = memAllocate (MEM_ACL_LIST);
      L->op = 1;		/* defaults to non-negated */
      if (*t == '!')
	{
	  /* negated ACL */
	  L->op = 0;
	  t++;
	}
      debug (28, 3) ("aclParseAccessLine: looking for ACL name '%s'\n", t);
      a = aclFindByName (t);
      if (a == NULL)
	{
	  debug (28, 0) ("%s line %d: %s\n",
			 cfg_filename, config_lineno, config_input_line);
	  debug (28, 0) ("aclParseAccessLine: ACL name '%s' not found.\n", t);
	  memFree (L, MEM_ACL_LIST);
	  continue;
	}
      L->acl = a;
      *Tail = L;
      Tail = &L->next;
    }
}

/**************/
/* aclMatchIp */
/**************/

static int
aclMatchIp (void *dataptr, struct in_addr c)
{
  splayNode **Top = dataptr;
  *Top = splay_splay (&c, *Top, aclIpNetworkCompare);
  debug (28, 3) ("aclMatchIp: '%s' %s\n",
		 inet_ntoa (c), splayLastResult ? "NOT found" : "found");
  return !splayLastResult;
}

/**********************/
/* aclMatchDomainList */
/**********************/

static int
aclMatchDomainList (void *dataptr, const char *host)
{
  splayNode **Top = dataptr;
  if (host == NULL)
    return 0;
  debug (28, 3) ("aclMatchDomainList: checking '%s'\n", host);
  *Top = splay_splay (host, *Top, aclHostDomainCompare);
  debug (28, 3) ("aclMatchDomainList: '%s' %s\n",
		 host, splayLastResult ? "NOT found" : "found");
  return !splayLastResult;
}

int
aclMatchRegex (relist * data, const char *word)
{
  relist *first, *prev;
  if (word == NULL)
    return 0;
  debug (28, 3) ("aclMatchRegex: checking '%s'\n", word);
  first = data;
  prev = NULL;
  while (data)
    {
      debug (28, 3) ("aclMatchRegex: looking for '%s'\n", data->pattern);
      if (regexec (&data->regex, word, 0, 0, 0) == 0)
	{
	  if (prev != NULL)
	    {
	      /* shift the element just found to the second position
	       * in the list */
	      prev->next = data->next;
	      data->next = first->next;
	      first->next = data;
	    }
	  return 1;
	}
      prev = data;
      data = data->next;
    }
  return 0;
}

static int
aclMatchUser (void *proxyauth_acl, char *user)
{
  acl_user_data *data = (acl_user_data *) proxyauth_acl;
  splayNode *Top = data->names;

  debug (28, 7) ("aclMatchUser: user is %s, case_insensitive is %d\n",
		 user, data->flags.case_insensitive);
  debug (28, 8) ("Top is %p, Top->data is %s\n", Top,
		 (Top != NULL ? (Top)->data : "Unavailable"));

  if (user == NULL)
    return 0;

  if (data->flags.required)
    {
      debug (28, 7) ("aclMatchUser: user REQUIRED and auth-info present.\n");
      return 1;
    }
  if (data->flags.case_insensitive)
    Top = splay_splay (user, Top, (SPLAYCMP *) strcasecmp);
  else
    Top = splay_splay (user, Top, (SPLAYCMP *) strcmp);
  /* Top=splay_splay(user,Top,(SPLAYCMP *)dumping_strcmp); */
  debug (28, 7) ("aclMatchUser: returning %d,Top is %p, Top->data is %s\n",
		 !splayLastResult, Top, (Top ? Top->data : "Unavailable"));
  data->names = Top;
  return !splayLastResult;
}

/* ACL result caching routines */

/*
 * we lookup an acl's cached results, and if we cannot find the acl being 
 * checked we check it and cache the result. This function is deliberatly 
 * generic to support caching of multiple acl types (but it needs to be more
 * generic still....
 * The Match Param and the cache MUST be tied together by the calling routine.
 * You have been warned :-]
 * Also only Matchxxx that are of the form (void *, void *) can be used.
 * probably some ugly overloading _could_ be done but I'll leave that as an
 * exercise for the reader. Note that caching of time based acl's is not
 * wise due to no expiry occuring to the cache entries until the user expires
 * or a reconfigure takes place. 
 * RBC
 */
static int
aclCacheMatchAcl (dlink_list * cache, squid_acl acltype, void *data,
		  char *MatchParam)
{
  int matchrv;
  acl_proxy_auth_match_cache *auth_match;
  dlink_node *link;
  link = cache->head;
  while (link)
    {
      auth_match = link->data;
      if (auth_match->acl_data == data)
	{
	  debug (28, 4) ("aclCacheMatchAcl: cache hit on acl '%d'\n", data);
	  return auth_match->matchrv;
	}
      link = link->next;
    }
  auth_match = NULL;
  /* match the user in the acl. They are not cached. */
  switch (acltype)
    {
    case ACL_PROXY_AUTH:
      matchrv = aclMatchUser (data, MatchParam);
      break;
    case ACL_PROXY_AUTH_REGEX:
      matchrv = aclMatchRegex (data, MatchParam);
    default:
      /* This is a fatal to ensure that aclCacheMatchAcl calls are _only_
       * made for supported acl types */
      fatal ("aclCacheMatchAcl: unknown or unexpected ACL type");
      return 0;			/* NOTREACHED */
    }
  auth_match = memAllocate (MEM_ACL_PROXY_AUTH_MATCH);
  auth_match->matchrv = matchrv;
  auth_match->acl_data = data;
  dlinkAddTail (auth_match, &auth_match->link, cache);
  return matchrv;
}

void
aclCacheMatchFlush (dlink_list * cache)
{
  acl_proxy_auth_match_cache *auth_match;
  dlink_node *link, *tmplink;
  link = cache->head;
  while (link)
    {
      auth_match = link->data;
      tmplink = link;
      link = link->next;
      dlinkDelete (tmplink, cache);
      memFree (auth_match, MEM_ACL_PROXY_AUTH_MATCH);
    }
}

/* aclMatchProxyAuth can return two exit codes:
 * 0 : Authorisation for this ACL failed. (Did not match)
 * 1 : Authorisation OK. (Matched)
 */
static int
aclMatchProxyAuth (void *data, http_hdr_type headertype,
	    auth_user_request_t * auth_user_request, aclCheck_t * checklist,
		   squid_acl acltype)
{
  /* checklist is used to register user name when identified, nothing else */

  /* General program flow in proxy_auth acls
   * 1. Consistency checks: are we getting sensible data
   * 2. Call the authenticate* functions to establish a authenticated user
   * 4. look up the username in acltype (and cache the result against the 
   *     username
   */

  /* for completeness */
  authenticateAuthUserRequestLock (auth_user_request);

  /* consistent parameters ? */
  assert (authenticateUserAuthenticated (auth_user_request));
  /* this ACL check completed */
  authenticateAuthUserRequestUnlock (auth_user_request);
  /* check to see if we have matched the user-acl before */
  return aclCacheMatchAcl (&auth_user_request->auth_user->
			   proxy_match_cache, acltype, data,
		       authenticateUserRequestUsername (auth_user_request));
}

CBDATA_TYPE (acl_user_ip_data);

void
aclParseUserMaxIP (void *data)
{
  acl_user_ip_data **acldata = data;
  char *t = NULL;
  CBDATA_INIT_TYPE (acl_user_ip_data);
  if (*acldata)
    {
      debug (28, 1) ("Attempting to alter already set User max IP acl\n");
      return;
    }
  *acldata = cbdataAlloc (acl_user_ip_data);
  if ((t = strtokFile ()))
    {
      debug (28, 5) ("aclParseUserMaxIP: First token is %s\n", t);
      if (strcmp ("-s", t) == 0)
	{
	  debug (28, 5) ("aclParseUserMaxIP: Going strict\n");
	  (*acldata)->flags.strict = 1;
	}
      else
	{
	  (*acldata)->max = atoi (t);
	  debug (28, 5) ("aclParseUserMaxIP: Max IP address's %d\n", (*acldata)->max);
	}
    }
  else
    fatal ("aclParseUserMaxIP: Malformed ACL %d\n");
}

void
aclDestroyUserMaxIP (void *data)
{
  acl_user_ip_data **acldata = data;
  if (*acldata)
    cbdataFree (*acldata);
  *acldata = NULL;
}

wordlist *
aclDumpUserMaxIP (void *data)
{
  acl_user_ip_data *acldata = data;
  wordlist *W = NULL;
  char buf[128];
  if (acldata->flags.strict)
    wordlistAdd (&W, "-s");
  snprintf (buf, sizeof (buf), "%d", acldata->max);
  wordlistAdd (&W, buf);
  return W;
}

/* aclMatchUserMaxIP - check for users logging in from multiple IP's 
 * 0 : No match
 * 1 : Match 
 */
int
aclMatchUserMaxIP (void *data, auth_user_request_t * auth_user_request,
		   struct in_addr src_addr)
{
/*
 * > the logic for flush the ip list when the limit is hit vs keep it sorted in most recent access order and just drop the oldest one off is currently undecided
 */
  acl_user_ip_data *acldata = data;

  if (authenticateAuthUserRequestIPCount (auth_user_request) <= acldata->max)
    return 0;

  /* this is a match */
  if (acldata->flags.strict)
    {
      /* simply deny access - the user name is already associated with
       * the request 
       */
      /* remove _this_ ip, as it is the culprit for going over the limit */
      authenticateAuthUserRequestRemoveIp (auth_user_request, src_addr);
      debug (28, 4) ("aclMatchUserMaxIP: Denying access in strict mode\n");
    }
  else
    {
      /* non-strict - remove some/all of the cached entries 
       * ie to allow the user to move machines easily
       */
      authenticateAuthUserRequestClearIp (auth_user_request);
      debug (28, 4) ("aclMatchUserMaxIP: Denying access in non-strict mode - flushing the user ip cache\n");
    }
  /* We had reports about the username being lost when denying due to 
   * IP limits. That should be fixed in the new lazy-proxy code, but
   * This note note is a reminder!
   */
  debug (28, 1) ("XXX aclMatchUserMaxIP returned 0, somebody "
		 "make sure the username gets logged to access.log.\n");
  debug (28, 1) ("XXX if it works, tell developers to remove this "
		 "message\n");

  return 1;
}

static void
aclLookupProxyAuthStart (aclCheck_t * checklist)
{
  auth_user_request_t *auth_user_request;
  assert (checklist->auth_user_request != NULL);	/* this is created for us */
  auth_user_request = checklist->auth_user_request;

  assert (authenticateValidateUser (auth_user_request));
  authenticateStart (auth_user_request, aclLookupProxyAuthDone, checklist);
}

static int
aclMatchInteger (intlist * data, int i)
{
  intlist *first, *prev;
  first = data;
  prev = NULL;
  while (data)
    {
      if (data->i == i)
	{
	  if (prev != NULL)
	    {
	      /* shift the element just found to the second position
	       * in the list */
	      prev->next = data->next;
	      data->next = first->next;
	      first->next = data;
	    }
	  return 1;
	}
      prev = data;
      data = data->next;
    }
  return 0;
}

static int
aclMatchIntegerRange (intrange * data, int i)
{
  intrange *first, *prev;
  first = data;
  prev = NULL;
  while (data)
    {
      if (i < data->i)
	{
	  (void) 0;
	}
      else if (i > data->j)
	{
	  (void) 0;
	}
      else
	{
	  /* matched */
	  if (prev != NULL)
	    {
	      /* shift the element just found to the second position
	       * in the list */
	      prev->next = data->next;
	      data->next = first->next;
	      first->next = data;
	    }
	  return 1;
	}
      prev = data;
      data = data->next;
    }
  return 0;
}

static int
aclMatchTime (acl_time_data * data, time_t when)
{
  static time_t last_when = 0;
  static struct tm tm;
  time_t t;
  assert (data != NULL);
  if (when != last_when)
    {
      last_when = when;
      xmemcpy (&tm, localtime (&when), sizeof (struct tm));
    }
  t = (time_t) (tm.tm_hour * 60 + tm.tm_min);
  debug (28, 3) ("aclMatchTime: checking %d in %d-%d, weekbits=%x\n",
	      (int) t, (int) data->start, (int) data->stop, data->weekbits);

  if (t < data->start || t > data->stop)
    return 0;
  return data->weekbits & (1 << tm.tm_wday) ? 1 : 0;
}

#if SQUID_SNMP
static int
aclMatchWordList (wordlist * w, const char *word)
{
  debug (28, 3) ("aclMatchWordList: looking for '%s'\n", word);
  while (w != NULL)
    {
      debug (28, 3) ("aclMatchWordList: checking '%s'\n", w->key);
      if (!strcmp (w->key, word))
	return 1;
      w = w->next;
    }
  return 0;
}
#endif

static int
aclMatchAcl (acl * ae, aclCheck_t * checklist)
{
  request_t *r = checklist->request;
  const ipcache_addrs *ia = NULL;
  const char *fqdn = NULL;
  char *esc_buf;
  const char *header;
  const char *browser;
  int k, ti;
  http_hdr_type headertype;
  if (!ae)
    return 0;
  switch (ae->type)
    {
    case ACL_DST_IP:
    case ACL_DST_DOMAIN:
    case ACL_DST_DOM_REGEX:
    case ACL_URLPATH_REGEX:
    case ACL_URL_PORT:
    case ACL_PROTO:
    case ACL_METHOD:
    case ACL_DST_ASN:
      /* These ACL types require checklist->request */
      if (NULL == r)
	{
	  debug (28, 1) ("WARNING: '%s' ACL is used but there is no"
			 " HTTP request -- access denied.\n", ae->name);
	  return 0;
	}
      break;
    default:
      break;
    }
  debug (28, 3) ("aclMatchAcl: checking '%s'\n", ae->cfgline);
  switch (ae->type)
    {
    case ACL_SRC_IP:
      return aclMatchIp (&ae->data, checklist->src_addr);
      /* NOTREACHED */
    case ACL_MY_IP:
      return aclMatchIp (&ae->data, checklist->my_addr);
      /* NOTREACHED */
    case ACL_DST_IP:
      ia = ipcache_gethostbyname (r->host, IP_LOOKUP_IF_MISS);
      if (ia)
	{
	  for (k = 0; k < (int) ia->count; k++)
	    {
	      if (aclMatchIp (&ae->data, ia->in_addrs[k]))
		return 1;
	    }
	  return 0;
	}
      else if (checklist->state[ACL_DST_IP] == ACL_LOOKUP_NONE)
	{
	  debug (28, 3) ("aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
			 ae->name, r->host);
	  checklist->state[ACL_DST_IP] = ACL_LOOKUP_NEEDED;
	  return 0;
	}
      else
	{
	  return aclMatchIp (&ae->data, no_addr);
	}
      /* NOTREACHED */
    case ACL_DST_DOMAIN:
      if ((ia = ipcacheCheckNumeric (r->host)) == NULL)
	return aclMatchDomainList (&ae->data, r->host);
      fqdn = fqdncache_gethostbyaddr (ia->in_addrs[0], FQDN_LOOKUP_IF_MISS);
      if (fqdn)
	return aclMatchDomainList (&ae->data, fqdn);
      if (checklist->state[ACL_DST_DOMAIN] == ACL_LOOKUP_NONE)
	{
	  debug (28, 3) ("aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
			 ae->name, inet_ntoa (ia->in_addrs[0]));
	  checklist->state[ACL_DST_DOMAIN] = ACL_LOOKUP_NEEDED;
	  return 0;
	}
      return aclMatchDomainList (&ae->data, "none");
      /* NOTREACHED */
    case ACL_SRC_DOMAIN:
      fqdn = fqdncache_gethostbyaddr (checklist->src_addr, FQDN_LOOKUP_IF_MISS);
      if (fqdn)
	{
	  return aclMatchDomainList (&ae->data, fqdn);
	}
      else if (checklist->state[ACL_SRC_DOMAIN] == ACL_LOOKUP_NONE)
	{
	  debug (28, 3) ("aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
			 ae->name, inet_ntoa (checklist->src_addr));
	  checklist->state[ACL_SRC_DOMAIN] = ACL_LOOKUP_NEEDED;
	  return 0;
	}
      return aclMatchDomainList (&ae->data, "none");
      /* NOTREACHED */
    case ACL_DST_DOM_REGEX:
      if ((ia = ipcacheCheckNumeric (r->host)) == NULL)
	return aclMatchRegex (ae->data, r->host);
      fqdn = fqdncache_gethostbyaddr (ia->in_addrs[0], FQDN_LOOKUP_IF_MISS);
      if (fqdn)
	return aclMatchRegex (ae->data, fqdn);
      if (checklist->state[ACL_DST_DOMAIN] == ACL_LOOKUP_NONE)
	{
	  debug (28, 3) ("aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
			 ae->name, inet_ntoa (ia->in_addrs[0]));
	  checklist->state[ACL_DST_DOMAIN] = ACL_LOOKUP_NEEDED;
	  return 0;
	}
      return aclMatchRegex (ae->data, "none");
      /* NOTREACHED */
    case ACL_SRC_DOM_REGEX:
      fqdn = fqdncache_gethostbyaddr (checklist->src_addr, FQDN_LOOKUP_IF_MISS);
      if (fqdn)
	{
	  return aclMatchRegex (ae->data, fqdn);
	}
      else if (checklist->state[ACL_SRC_DOMAIN] == ACL_LOOKUP_NONE)
	{
	  debug (28, 3) ("aclMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
			 ae->name, inet_ntoa (checklist->src_addr));
	  checklist->state[ACL_SRC_DOMAIN] = ACL_LOOKUP_NEEDED;
	  return 0;
	}
      return aclMatchRegex (ae->data, "none");
      /* NOTREACHED */
    case ACL_TIME:
      return aclMatchTime (ae->data, squid_curtime);
      /* NOTREACHED */
    case ACL_URLPATH_REGEX:
      esc_buf = xstrdup (strBuf (r->urlpath));
      rfc1738_unescape (esc_buf);
      k = aclMatchRegex (ae->data, esc_buf);
      safe_free (esc_buf);
      return k;
      /* NOTREACHED */
    case ACL_URL_REGEX:
      esc_buf = xstrdup (urlCanonical (r));
      rfc1738_unescape (esc_buf);
      k = aclMatchRegex (ae->data, esc_buf);
      safe_free (esc_buf);
      return k;
      /* NOTREACHED */
    case ACL_MAXCONN:
      k = clientdbEstablished (checklist->src_addr, 0);
      return ((k > ((intlist *) ae->data)->i) ? 1 : 0);
      /* NOTREACHED */
    case ACL_URL_PORT:
      return aclMatchIntegerRange (ae->data, (int) r->port);
      /* NOTREACHED */
    case ACL_MY_PORT:
      return aclMatchIntegerRange (ae->data, (int) checklist->my_port);
      /* NOTREACHED */
#if USE_IDENT
    case ACL_IDENT:
      if (checklist->rfc931[0])
	{
	  return aclMatchUser (ae->data, checklist->rfc931);
	}
      else
	{
	  checklist->state[ACL_IDENT] = ACL_LOOKUP_NEEDED;
	  return 0;
	}
      /* NOTREACHED */
    case ACL_IDENT_REGEX:
      if (checklist->rfc931[0])
	{
	  return aclMatchRegex (ae->data, checklist->rfc931);
	}
      else
	{
	  checklist->state[ACL_IDENT] = ACL_LOOKUP_NEEDED;
	  return 0;
	}
      /* NOTREACHED */
#endif
    case ACL_PROTO:
      return aclMatchInteger (ae->data, r->protocol);
      /* NOTREACHED */
    case ACL_METHOD:
      return aclMatchInteger (ae->data, r->method);
      /* NOTREACHED */
    case ACL_BROWSER:
      browser = httpHeaderGetStr (&checklist->request->header, HDR_USER_AGENT);
      if (NULL == browser)
	return 0;
      return aclMatchRegex (ae->data, browser);
      /* NOTREACHED */
    case ACL_PROXY_AUTH:
    case ACL_PROXY_AUTH_REGEX:
    case ACL_MAX_USER_IP:
      /* ALL authentication predicated ACL's live here */
      if (NULL == r)
	{
	  return -1;
	}
      else if (!r->flags.accelerated)
	{
	  /* Proxy authorization on proxy requests */
	  headertype = HDR_PROXY_AUTHORIZATION;
	}
      else if (r->flags.internal)
	{
	  /* WWW authorization on accelerated internal requests */
	  headertype = HDR_AUTHORIZATION;
	}
      else
	{
#if AUTH_ON_ACCELERATION
	  /* WWW authorization on accelerated requests */
	  headertype = HDR_AUTHORIZATION;
#else
	  debug (28, 1) ("aclMatchAcl: proxy_auth %s not applicable on accelerated requests.\n", ae->name);
	  return -1;
#endif
	}
      /* get authed here */
      if ((ti = authenticateAuthenticate (&checklist->auth_user_request, headertype, checklist->request, checklist->conn, checklist->src_addr)) != AUTH_AUTHENTICATED)
	{
	  switch (ti)
	    {
	    case 0:
	      /* Authenticated but not Authorised for this ACL */
	      debug (28, 4) ("aclMatchAcl: returning  0 user authenticated but not authorised.\n");
	      return 0;
	    case 1:
	      fatal ("AUTH_AUTHENTICATED == 1\n");
	      break;
	    case -1:
	      /* Send data to the helper */
	      debug (28, 4) ("aclMatchAcl: returning 0 sending authentication challenge.\n");
	      checklist->state[ACL_PROXY_AUTH] = ACL_LOOKUP_NEEDED;
	      return 0;
	    case -2:
	      /* Send a challenge to the client */
	      debug (28, 4) ("aclMatchAcl: returning 0 sending credentials to helper.\n");
	      checklist->state[ACL_PROXY_AUTH] = ACL_PROXY_AUTH_NEEDED;
	      return 0;
	    }
	}
      /* then, switch on type again to do the correct match routine :> */
      switch (ae->type)
	{
	case ACL_PROXY_AUTH:
	case ACL_PROXY_AUTH_REGEX:
	  ti = aclMatchProxyAuth (ae->data, headertype,
			 checklist->auth_user_request, checklist, ae->type);
	  break;
	case ACL_MAX_USER_IP:
	  ti = aclMatchUserMaxIP (ae->data, checklist->auth_user_request,
				  checklist->src_addr);
	  break;
	default:
	  /* Keep GCC happy */
	  break;
	}
      checklist->auth_user_request = NULL;
      /* Check the credentials */
      switch (ti)
	{
	case 0:
	  debug (28, 4) ("aclMatchAcl: returning  0 user authenticated but not authorised.\n");
	  /* Authenticated but not Authorised for this ACL */
	  return 0;
	case 1:
	  debug (28, 4) ("aclMatchAcl: returning  1 user authenticated and authorised.\n");
	  /* Authenticated and Authorised for this ACL */
	  return 1;
	case -2:
	case -1:
	  fatal ("Invalid response from match routine\n");
	  break;
	}

      /* NOTREACHED */
#if SQUID_SNMP
    case ACL_SNMP_COMMUNITY:
      return aclMatchWordList (ae->data, checklist->snmp_community);
#endif
    case ACL_SRC_ASN:
      return asnMatchIp (ae->data, checklist->src_addr);
    case ACL_DST_ASN:
      ia = ipcache_gethostbyname (r->host, IP_LOOKUP_IF_MISS);
      if (ia)
	{
	  for (k = 0; k < (int) ia->count; k++)
	    {
	      if (asnMatchIp (ae->data, ia->in_addrs[k]))
		return 1;
	    }
	  return 0;
	}
      else if (checklist->state[ACL_DST_ASN] == ACL_LOOKUP_NONE)
	{
	  debug (28, 3) ("asnMatchAcl: Can't yet compare '%s' ACL for '%s'\n",
			 ae->name, r->host);
	  checklist->state[ACL_DST_ASN] = ACL_LOOKUP_NEEDED;
	}
      else
	{
	  return asnMatchIp (ae->data, no_addr);
	}
      return 0;
#if USE_ARP_ACL
    case ACL_SRC_ARP:
      return aclMatchArp (&ae->data, checklist->src_addr);
#endif
    case ACL_REQ_MIME_TYPE:
      header = httpHeaderGetStr (&checklist->request->header,
				 HDR_CONTENT_TYPE);
      if (NULL == header)
	header = "";
      return aclMatchRegex (ae->data, header);
      /* NOTREACHED */
    case ACL_REP_MIME_TYPE:
      if (!checklist->reply)
	return 0;
      header = httpHeaderGetStr (&checklist->reply->header, HDR_CONTENT_TYPE);
      if (NULL == header)
	header = "";
      return aclMatchRegex (ae->data, header);
      /* NOTREACHED */
    case ACL_NONE:
    case ACL_ENUM_MAX:
      break;
    }
  debug (28, 0) ("aclMatchAcl: '%s' has bad type %d\n",
		 ae->name, ae->type);
  return 0;
}

int
aclMatchAclList (const acl_list * list, aclCheck_t * checklist)
{
  while (list)
    {
      AclMatchedName = list->acl->name;
      debug (28, 3) ("aclMatchAclList: checking %s%s\n",
		     list->op ? null_string : "!", list->acl->name);
      if (aclMatchAcl (list->acl, checklist) != list->op)
	{
	  debug (28, 3) ("aclMatchAclList: returning 0\n");
	  return 0;
	}
      list = list->next;
    }
  debug (28, 3) ("aclMatchAclList: returning 1\n");
  return 1;
}

int
aclCheckFast (const acl_access * A, aclCheck_t * checklist)
{
  allow_t allow = ACCESS_DENIED;
  debug (28, 5) ("aclCheckFast: list: %p\n", A);
  while (A)
    {
      allow = A->allow;
      if (aclMatchAclList (A->acl_list, checklist))
	return allow == ACCESS_ALLOWED;
      A = A->next;
    }
  debug (28, 5) ("aclCheckFast: no matches, returning: %d\n", allow == ACCESS_DENIED);
  return allow == ACCESS_DENIED;
}

static void
aclCheck (aclCheck_t * checklist)
{
  allow_t allow = ACCESS_DENIED;
  const acl_access *A;
  int match;
  ipcache_addrs *ia;
  while ((A = checklist->access_list) != NULL)
    {
      /*
       * If the _acl_access is no longer valid (i.e. its been
       * freed because of a reconfigure), then bail on this
       * access check.  For now, return ACCESS_DENIED.
       */
      if (!cbdataValid (A))
	{
	  cbdataUnlock (A);
	  break;
	}
      debug (28, 3) ("aclCheck: checking '%s'\n", A->cfgline);
      allow = A->allow;
      match = aclMatchAclList (A->acl_list, checklist);
      if (checklist->state[ACL_DST_IP] == ACL_LOOKUP_NEEDED)
	{
	  checklist->state[ACL_DST_IP] = ACL_LOOKUP_PENDING;
	  ipcache_nbgethostbyname (checklist->request->host,
				   aclLookupDstIPDone, checklist);
	  return;
	}
      else if (checklist->state[ACL_DST_ASN] == ACL_LOOKUP_NEEDED)
	{
	  checklist->state[ACL_DST_ASN] = ACL_LOOKUP_PENDING;
	  ipcache_nbgethostbyname (checklist->request->host,
				   aclLookupDstIPforASNDone, checklist);
	  return;
	}
      else if (checklist->state[ACL_SRC_DOMAIN] == ACL_LOOKUP_NEEDED)
	{
	  checklist->state[ACL_SRC_DOMAIN] = ACL_LOOKUP_PENDING;
	  fqdncache_nbgethostbyaddr (checklist->src_addr,
				     aclLookupSrcFQDNDone, checklist);
	  return;
	}
      else if (checklist->state[ACL_DST_DOMAIN] == ACL_LOOKUP_NEEDED)
	{
	  ia = ipcacheCheckNumeric (checklist->request->host);
	  if (ia == NULL)
	    {
	      checklist->state[ACL_DST_DOMAIN] = ACL_LOOKUP_DONE;
	      return;
	    }
	  checklist->dst_addr = ia->in_addrs[0];
	  checklist->state[ACL_DST_DOMAIN] = ACL_LOOKUP_PENDING;
	  fqdncache_nbgethostbyaddr (checklist->dst_addr,
				     aclLookupDstFQDNDone, checklist);
	  return;
	}
      else if (checklist->state[ACL_PROXY_AUTH] == ACL_LOOKUP_NEEDED)
	{
	  debug (28, 3)
	    ("aclCheck: checking password via authenticator\n");
	  aclLookupProxyAuthStart (checklist);
	  checklist->state[ACL_PROXY_AUTH] = ACL_LOOKUP_PENDING;
	  return;
	}
      else if (checklist->state[ACL_PROXY_AUTH] == ACL_PROXY_AUTH_NEEDED)
	{
	  /* Client is required to resend the request with correct authentication
	   * credentials. (This may be part of a stateful auth protocol.
	   * The request is denied.
	   */
	  debug (28, 6) ("aclCheck: requiring Proxy Auth header.\n");
	  allow = ACCESS_REQ_PROXY_AUTH;
	  match = -1;
	}
#if USE_IDENT
      else if (checklist->state[ACL_IDENT] == ACL_LOOKUP_NEEDED)
	{
	  debug (28, 3) ("aclCheck: Doing ident lookup\n");
	  if (cbdataValid (checklist->conn))
	    {
	      identStart (&checklist->conn->me, &checklist->conn->peer,
			  aclLookupIdentDone, checklist);
	      checklist->state[ACL_IDENT] = ACL_LOOKUP_PENDING;
	      return;
	    }
	  else
	    {
	      debug (28, 1) ("aclCheck: Can't start ident lookup. No client connection\n");
	      cbdataUnlock (checklist->conn);
	      checklist->conn = NULL;
	      allow = 0;
	      match = -1;
	    }
	}
#endif
      /*
       * We are done with this _acl_access entry.  Either the request
       * is allowed, denied, requires authentication, or we move on to
       * the next entry.
       */
      cbdataUnlock (A);
      if (match)
	{
	  debug (28, 3) ("aclCheck: match found, returning %d\n", allow);
	  aclCheckCallback (checklist, allow);
	  return;
	}
      checklist->access_list = A->next;
      /*
       * Lock the next _acl_access entry
       */
      if (A->next)
	cbdataLock (A->next);
    }
  debug (28, 3) ("aclCheck: NO match found, returning %d\n", allow != ACCESS_DENIED ? ACCESS_DENIED : ACCESS_ALLOWED);
  aclCheckCallback (checklist, allow != ACCESS_DENIED ? ACCESS_DENIED : ACCESS_ALLOWED);
}

void
aclChecklistFree (aclCheck_t * checklist)
{
  if (checklist->request)
    requestUnlink (checklist->request);
  checklist->request = NULL;
  if (checklist->conn)
    {
      cbdataUnlock (checklist->conn);
      checklist->conn = NULL;
    }
  cbdataFree (checklist);
}

static void
aclCheckCallback (aclCheck_t * checklist, allow_t answer)
{
  debug (28, 3) ("aclCheckCallback: answer=%d\n", answer);
  /* During reconfigure, we can end up not finishing call sequences into the auth code */
  if (checklist->auth_user_request)
    {
      /* the checklist lock */
      authenticateAuthUserRequestUnlock (checklist->auth_user_request);
      /* it might have been connection based */
      assert (checklist->conn);
      checklist->conn->auth_user_request = NULL;
      checklist->conn->auth_type = AUTH_BROKEN;
      checklist->auth_user_request = NULL;
    }
  if (cbdataValid (checklist->callback_data))
    checklist->callback (answer, checklist->callback_data);
  cbdataUnlock (checklist->callback_data);
  checklist->callback = NULL;
  checklist->callback_data = NULL;
  aclChecklistFree (checklist);
}

#if USE_IDENT
static void
aclLookupIdentDone (const char *ident, void *data)
{
  aclCheck_t *checklist = data;
  if (ident)
    {
      xstrncpy (checklist->rfc931, ident, USER_IDENT_SZ);
#if DONT
      xstrncpy (checklist->request->authuser, ident, USER_IDENT_SZ);
#endif
    }
  else
    {
      xstrncpy (checklist->rfc931, dash_str, USER_IDENT_SZ);
    }
  /*
   * Cache the ident result in the connection, to avoid redoing ident lookup
   * over and over on persistent connections
   */
  if (cbdataValid (checklist->conn) && !checklist->conn->rfc931[0])
    xstrncpy (checklist->conn->rfc931, checklist->rfc931, USER_IDENT_SZ);
  aclCheck (checklist);
}
#endif

static void
aclLookupDstIPDone (const ipcache_addrs * ia, void *data)
{
  aclCheck_t *checklist = data;
  checklist->state[ACL_DST_IP] = ACL_LOOKUP_DONE;
  aclCheck (checklist);
}

static void
aclLookupDstIPforASNDone (const ipcache_addrs * ia, void *data)
{
  aclCheck_t *checklist = data;
  checklist->state[ACL_DST_ASN] = ACL_LOOKUP_DONE;
  aclCheck (checklist);
}

static void
aclLookupSrcFQDNDone (const char *fqdn, void *data)
{
  aclCheck_t *checklist = data;
  checklist->state[ACL_SRC_DOMAIN] = ACL_LOOKUP_DONE;
  aclCheck (checklist);
}

static void
aclLookupDstFQDNDone (const char *fqdn, void *data)
{
  aclCheck_t *checklist = data;
  checklist->state[ACL_DST_DOMAIN] = ACL_LOOKUP_DONE;
  aclCheck (checklist);
}

static void
aclLookupProxyAuthDone (void *data, char *result)
{
  aclCheck_t *checklist = data;
  checklist->state[ACL_PROXY_AUTH] = ACL_LOOKUP_DONE;
  if (result != NULL)
    fatal ("AclLookupProxyAuthDone: Old code floating around somewhere.\nMake clean and if that doesn't work, report a bug to the squid developers.\n");
  if (!authenticateValidateUser (checklist->auth_user_request) || checklist->conn == NULL)
    {
      /* credentials could not be checked either way
       * restart the whole process */
      /* OR the connection was closed, there's no way to continue */
      authenticateAuthUserRequestUnlock (checklist->auth_user_request);
      if (checklist->conn)
	{
	  checklist->conn->auth_user_request = NULL;
	  checklist->conn->auth_type = AUTH_BROKEN;
	}
      checklist->auth_user_request = NULL;
    }
  aclCheck (checklist);
}

aclCheck_t *
aclChecklistCreate (const acl_access * A, request_t * request, const char *ident)
{
  int i;
  aclCheck_t *checklist;
  checklist = cbdataAlloc (aclCheck_t);
  checklist->access_list = A;
  /*
   * aclCheck() makes sure checklist->access_list is a valid
   * pointer, so lock it.
   */
  cbdataLock (A);
  if (request != NULL)
    {
      checklist->request = requestLink (request);
      checklist->src_addr = request->client_addr;
      checklist->my_addr = request->my_addr;
      checklist->my_port = request->my_port;
    }
  for (i = 0; i < ACL_ENUM_MAX; i++)
    checklist->state[i] = ACL_LOOKUP_NONE;
#if USE_IDENT
  if (ident)
    xstrncpy (checklist->rfc931, ident, USER_IDENT_SZ);
#endif
  checklist->auth_user_request = NULL;
  return checklist;
}

void
aclNBCheck (aclCheck_t * checklist, PF * callback, void *callback_data)
{
  checklist->callback = callback;
  checklist->callback_data = callback_data;
  cbdataLock (callback_data);
  aclCheck (checklist);
}







/*********************/
/* Destroy functions */
/*********************/

static void
aclDestroyTimeList (acl_time_data * data)
{
  acl_time_data *next = NULL;
  for (; data; data = next)
    {
      next = data->next;
      memFree (data, MEM_ACL_TIME_DATA);
    }
}

void
aclDestroyRegexList (relist * data)
{
  relist *next = NULL;
  for (; data; data = next)
    {
      next = data->next;
      regfree (&data->regex);
      safe_free (data->pattern);
      memFree (data, MEM_RELIST);
    }
}

static void
aclFreeIpData (void *p)
{
  memFree (p, MEM_ACL_IP_DATA);
}

static void
aclFreeUserData (void *data)
{
  acl_user_data *d = data;
  if (d->names)
    splay_destroy (d->names, xfree);
  memFree (d, MEM_ACL_USER_DATA);
}


void
aclDestroyAcls (acl ** head)
{
  acl *a = NULL;
  acl *next = NULL;
  for (a = *head; a; a = next)
    {
      next = a->next;
      debug (28, 3) ("aclDestroyAcls: '%s'\n", a->cfgline);
      switch (a->type)
	{
	case ACL_SRC_IP:
	case ACL_DST_IP:
	case ACL_MY_IP:
	  splay_destroy (a->data, aclFreeIpData);
	  break;
#if USE_ARP_ACL
	case ACL_SRC_ARP:
#endif
	case ACL_DST_DOMAIN:
	case ACL_SRC_DOMAIN:
	  splay_destroy (a->data, xfree);
	  break;
#if SQUID_SNMP
	case ACL_SNMP_COMMUNITY:
	  wordlistDestroy ((wordlist **) & a->data);
	  break;
#endif
#if USE_IDENT
	case ACL_IDENT:
	  aclFreeUserData (a->data);
	  break;
#endif
	case ACL_PROXY_AUTH:
	  aclFreeUserData (a->data);
	  break;
	case ACL_TIME:
	  aclDestroyTimeList (a->data);
	  break;
#if USE_IDENT
	case ACL_IDENT_REGEX:
#endif
	case ACL_PROXY_AUTH_REGEX:
	case ACL_URL_REGEX:
	case ACL_URLPATH_REGEX:
	case ACL_BROWSER:
	case ACL_SRC_DOM_REGEX:
	case ACL_DST_DOM_REGEX:
	case ACL_REP_MIME_TYPE:
	case ACL_REQ_MIME_TYPE:
	  aclDestroyRegexList (a->data);
	  break;
	case ACL_PROTO:
	case ACL_METHOD:
	case ACL_SRC_ASN:
	case ACL_DST_ASN:
#if SRC_RTT_NOT_YET_FINISHED
	case ACL_NETDB_SRC_RTT:
#endif
	case ACL_MAXCONN:
	  intlistDestroy ((intlist **) & a->data);
	  break;
	case ACL_MAX_USER_IP:
	  aclDestroyUserMaxIP (&a->data);
	  break;
	case ACL_URL_PORT:
	case ACL_MY_PORT:
	  aclDestroyIntRange (a->data);
	  break;
	case ACL_NONE:
	case ACL_ENUM_MAX:
	  debug (28, 1) ("aclDestroyAcls: no case for ACL type %d\n", a->type);
	  break;
	}
      safe_free (a->cfgline);
      memFree (a, MEM_ACL);
    }
  *head = NULL;
}

void
aclDestroyAclList (acl_list ** head)
{
  acl_list *l;
  for (l = *head; l; l = *head)
    {
      *head = l->next;
      memFree (l, MEM_ACL_LIST);
    }
}

void
aclDestroyAccessList (acl_access ** list)
{
  acl_access *l = NULL;
  acl_access *next = NULL;
  for (l = *list; l; l = next)
    {
      debug (28, 3) ("aclDestroyAccessList: '%s'\n", l->cfgline);
      next = l->next;
      aclDestroyAclList (&l->acl_list);
      safe_free (l->cfgline);
      cbdataFree (l);
    }
  *list = NULL;
}

/* maex@space.net (06.09.1996)
 *    destroy an _acl_deny_info_list */

void
aclDestroyDenyInfoList (acl_deny_info_list ** list)
{
  acl_deny_info_list *a = NULL;
  acl_deny_info_list *a_next = NULL;
  acl_name_list *l = NULL;
  acl_name_list *l_next = NULL;

  for (a = *list; a; a = a_next)
    {
      for (l = a->acl_list; l; l = l_next)
	{
	  l_next = l->next;
	  safe_free (l);
	}
      a_next = a->next;
      xfree (a->err_page_name);
      memFree (a, MEM_ACL_DENY_INFO_LIST);
    }
  *list = NULL;
}

static void
aclDestroyIntRange (intrange * list)
{
  intrange *w = NULL;
  intrange *n = NULL;
  for (w = list; w; w = n)
    {
      n = w->next;
      safe_free (w);
    }
}

/* general compare functions, these are used for tree search algorithms
 * so they return <0, 0 or >0 */

/* compare two domains */

static int
aclDomainCompare (const void *a, const void *b)
{
  const char *d1;
  const char *d2;
  int ret;
  d1 = b;
  d2 = a;
  ret = aclHostDomainCompare (d1, d2);
  if (ret != 0)
    {
      d1 = a;
      d2 = b;
      ret = aclHostDomainCompare (d1, d2);
    }
  if (ret == 0)
    {
      debug (28, 0) ("WARNING: '%s' is a subdomain of '%s'\n", d1, d2);
      debug (28, 0) ("WARNING: because of this '%s' is ignored to keep splay tree searching predictable\n", a);
      debug (28, 0) ("WARNING: You should probably remove '%s' from the ACL named '%s'\n", d1, AclMatchedName);
    }
  return ret;
}

/* compare a host and a domain */

static int
aclHostDomainCompare (const void *a, const void *b)
{
  const char *h = a;
  const char *d = b;
  return matchDomainName (h, d);
}

/* compare two network specs

 * NOTE: this is very similar to aclIpNetworkCompare and it's not yet
 * clear whether this OK. The problem could be with when a network
 * is a subset of the other networks:
 * 
 * 128.1.2.0/255.255.255.128 == 128.1.2.0/255.255.255.0 ?
 * 
 * Currently only the first address of the first network is used.
 */

/* compare an address and a network spec */

static int
aclIpNetworkCompare (const void *a, const void *b)
{
  struct in_addr A = *(const struct in_addr *) a;
  const acl_ip_data *q = b;
  const struct in_addr B = q->addr1;
  const struct in_addr C = q->addr2;
  int rc = 0;
  A.s_addr &= q->mask.s_addr;	/* apply netmask */
  if (C.s_addr == 0)
    {				/* single address check */
      if (ntohl (A.s_addr) > ntohl (B.s_addr))
	rc = 1;
      else if (ntohl (A.s_addr) < ntohl (B.s_addr))
	rc = -1;
      else
	rc = 0;
    }
  else
    {				/* range address check */
      if (ntohl (A.s_addr) > ntohl (C.s_addr))
	rc = 1;
      else if (ntohl (A.s_addr) < ntohl (B.s_addr))
	rc = -1;
      else
	rc = 0;
    }
  return rc;
}

static void
aclDumpUserListWalkee (void *node_data, void *outlist)
{
  /* outlist is really a wordlist ** */
  wordlistAdd (outlist, node_data);
}

static wordlist *
aclDumpUserList (acl_user_data * data)
{
  wordlist *wl = NULL;
  if (data->flags.case_insensitive)
    wordlistAdd (&wl, "-i");
  /* damn this is VERY inefficient for long ACL lists... filling
   * a wordlist this way costs Sum(1,N) iterations. For instance
   * a 1000-elements list will be filled in 499500 iterations.
   */
  if (data->flags.required)
    wordlistAdd (&wl, "REQUIRED");
  else if (data->names)
    splay_walk (data->names, aclDumpUserListWalkee, &wl);
  return wl;
}

static void
aclDumpIpListWalkee (void *node, void *state)
{
  acl_ip_data *ip = node;
  MemBuf mb;
  wordlist **W = state;
  memBufDefInit (&mb);
  memBufPrintf (&mb, "%s", inet_ntoa (ip->addr1));
  if (ip->addr2.s_addr != any_addr.s_addr)
    memBufPrintf (&mb, "-%s", inet_ntoa (ip->addr2));
  if (ip->mask.s_addr != no_addr.s_addr)
    memBufPrintf (&mb, "/%s", inet_ntoa (ip->mask));
  wordlistAdd (W, mb.buf);
  memBufClean (&mb);
}

static wordlist *
aclDumpIpList (void *data)
{
  wordlist *w = NULL;
  splay_walk (data, aclDumpIpListWalkee, &w);
  return w;
}

static void
aclDumpDomainListWalkee (void *node, void *state)
{
  char *domain = node;
  wordlistAdd (state, domain);
}

static wordlist *
aclDumpDomainList (void *data)
{
  wordlist *w = NULL;
  splay_walk (data, aclDumpDomainListWalkee, &w);
  return w;
}

static wordlist *
aclDumpTimeSpecList (acl_time_data * t)
{
  wordlist *W = NULL;
  char buf[128];
  while (t != NULL)
    {
      snprintf (buf, sizeof (buf), "%c%c%c%c%c%c%c %02d:%02d-%02d:%02d",
		t->weekbits & ACL_SUNDAY ? 'S' : '-',
		t->weekbits & ACL_MONDAY ? 'M' : '-',
		t->weekbits & ACL_TUESDAY ? 'T' : '-',
		t->weekbits & ACL_WEDNESDAY ? 'W' : '-',
		t->weekbits & ACL_THURSDAY ? 'H' : '-',
		t->weekbits & ACL_FRIDAY ? 'F' : '-',
		t->weekbits & ACL_SATURDAY ? 'A' : '-',
		t->start / 60, t->start % 60, t->stop / 60, t->stop % 60);
      wordlistAdd (&W, buf);
      t = t->next;
    }
  return W;
}

static wordlist *
aclDumpRegexList (relist * data)
{
  wordlist *W = NULL;
  while (data != NULL)
    {
      wordlistAdd (&W, data->pattern);
      data = data->next;
    }
  return W;
}

static wordlist *
aclDumpIntlistList (intlist * data)
{
  wordlist *W = NULL;
  char buf[32];
  while (data != NULL)
    {
      snprintf (buf, sizeof (buf), "%d", data->i);
      wordlistAdd (&W, buf);
      data = data->next;
    }
  return W;
}

static wordlist *
aclDumpIntRangeList (intrange * data)
{
  wordlist *W = NULL;
  char buf[32];
  while (data != NULL)
    {
      if (data->i == data->j)
	snprintf (buf, sizeof (buf), "%d", data->i);
      else
	snprintf (buf, sizeof (buf), "%d-%d", data->i, data->j);
      wordlistAdd (&W, buf);
      data = data->next;
    }
  return W;
}

static wordlist *
aclDumpProtoList (intlist * data)
{
  wordlist *W = NULL;
  while (data != NULL)
    {
      wordlistAdd (&W, ProtocolStr[data->i]);
      data = data->next;
    }
  return W;
}

static wordlist *
aclDumpMethodList (intlist * data)
{
  wordlist *W = NULL;
  while (data != NULL)
    {
      wordlistAdd (&W, RequestMethodStr[data->i]);
      data = data->next;
    }
  return W;
}

wordlist *
aclDumpGeneric (const acl * a)
{
  debug (28, 3) ("aclDumpGeneric: %s type %d\n", a->name, a->type);
  switch (a->type)
    {
    case ACL_SRC_IP:
    case ACL_DST_IP:
    case ACL_MY_IP:
      return aclDumpIpList (a->data);
    case ACL_SRC_DOMAIN:
    case ACL_DST_DOMAIN:
      return aclDumpDomainList (a->data);
#if SQUID_SNMP
    case ACL_SNMP_COMMUNITY:
      return wordlistDup (a->data);
#endif
#if USE_IDENT
    case ACL_IDENT:
      return aclDumpUserList (a->data);
    case ACL_IDENT_REGEX:
      return aclDumpRegexList (a->data);
#endif
    case ACL_PROXY_AUTH:
      return aclDumpUserList (a->data);
    case ACL_TIME:
      return aclDumpTimeSpecList (a->data);
    case ACL_PROXY_AUTH_REGEX:
    case ACL_URL_REGEX:
    case ACL_URLPATH_REGEX:
    case ACL_BROWSER:
    case ACL_SRC_DOM_REGEX:
    case ACL_DST_DOM_REGEX:
    case ACL_REQ_MIME_TYPE:
    case ACL_REP_MIME_TYPE:
      return aclDumpRegexList (a->data);
    case ACL_SRC_ASN:
    case ACL_MAXCONN:
    case ACL_DST_ASN:
      return aclDumpIntlistList (a->data);
    case ACL_MAX_USER_IP:
      return aclDumpUserMaxIP (a->data);
    case ACL_URL_PORT:
    case ACL_MY_PORT:
      return aclDumpIntRangeList (a->data);
    case ACL_PROTO:
      return aclDumpProtoList (a->data);
    case ACL_METHOD:
      return aclDumpMethodList (a->data);
#if USE_ARP_ACL
    case ACL_SRC_ARP:
      return aclDumpArpList (a->data);
#endif
    case ACL_NONE:
    case ACL_ENUM_MAX:
      break;
    }
  debug (28, 1) ("aclDumpGeneric: no case for ACL type %d\n", a->type);
  return NULL;
}

/*
 * This function traverses all ACL elements referenced
 * by an access list (presumably 'http_access').   If 
 * it finds a PURGE method ACL, then it returns TRUE,
 * otherwise FALSE.
 */
int
aclPurgeMethodInUse (acl_access * a)
{
  acl_list *b;
  for (; a; a = a->next)
    {
      for (b = a->acl_list; b; b = b->next)
	{
	  if (ACL_METHOD != b->acl->type)
	    continue;
	  if (aclMatchInteger (b->acl->data, METHOD_PURGE))
	    return 1;
	}
    }
  return 0;
}


#if USE_ARP_ACL
/* ==== BEGIN ARP ACL SUPPORT ============================================= */

/*
 * From:    dale@server.ctam.bitmcnit.bryansk.su (Dale)
 * To:      wessels@nlanr.net
 * Subject: Another Squid patch... :)
 * Date:    Thu, 04 Dec 1997 19:55:01 +0300
 * ============================================================================
 * 
 * Working on setting up a proper firewall for a network containing some
 * Win'95 computers at our Univ, I've discovered that some smart students
 * avoid the restrictions easily just changing their IP addresses in Win'95
 * Contol Panel... It has been getting boring, so I took Squid-1.1.18
 * sources and added a new acl type for hard-wired access control:
 * 
 * acl <name> arp <Ethernet address> ...
 * 
 * For example,
 * 
 * acl students arp 00:00:21:55:ed:22 00:00:21:ff:55:38
 *
 * NOTE: Linux code by David Luyer <luyer@ucs.uwa.edu.au>.
 *       Original (BSD-specific) code no longer works.
 *       Solaris code by R. Gancarz <radekg@solaris.elektrownia-lagisza.com.pl>
 */

#ifdef _SQUID_SOLARIS_
#include <sys/sockio.h>
#else
#include <sys/sysctl.h>
#endif
#ifdef _SQUID_LINUX_
#include <net/if_arp.h>
#include <sys/ioctl.h>
#else
#include <net/if_dl.h>
#endif
#include <net/route.h>
#include <net/if.h>
#if HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif

/*
 * Decode an ascii representation (asc) of an ethernet adress, and place
 * it in eth[6].
 */
static int
decode_eth (const char *asc, char *eth)
{
  int a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0, a6 = 0;
  if (sscanf (asc, "%x:%x:%x:%x:%x:%x", &a1, &a2, &a3, &a4, &a5, &a6) != 6)
    {
      debug (28, 0) ("decode_eth: Invalid ethernet address '%s'\n", asc);
      return 0;			/* This is not valid address */
    }
  eth[0] = (u_char) a1;
  eth[1] = (u_char) a2;
  eth[2] = (u_char) a3;
  eth[3] = (u_char) a4;
  eth[4] = (u_char) a5;
  eth[5] = (u_char) a6;
  return 1;
}

static acl_arp_data *
aclParseArpData (const char *t)
{
  LOCAL_ARRAY (char, eth, 256);
  acl_arp_data *q = xcalloc (1, sizeof (acl_arp_data));
  debug (28, 5) ("aclParseArpData: %s\n", t);
  if (sscanf (t, "%[0-9a-fA-F:]", eth) != 1)
    {
      debug (28, 0) ("aclParseArpData: Bad ethernet address: '%s'\n", t);
      safe_free (q);
      return NULL;
    }
  if (!decode_eth (eth, q->eth))
    {
      debug (28, 0) ("%s line %d: %s\n",
		     cfg_filename, config_lineno, config_input_line);
      debug (28, 0) ("aclParseArpData: Ignoring invalid ARP acl entry: can't parse '%s'\n", eth);
      safe_free (q);
      return NULL;
    }
  return q;
}


/*******************/
/* aclParseArpList */
/*******************/
static void
aclParseArpList (void *curlist)
{
  char *t = NULL;
  splayNode **Top = curlist;
  acl_arp_data *q = NULL;
  while ((t = strtokFile ()))
    {
      if ((q = aclParseArpData (t)) == NULL)
	continue;
      *Top = splay_insert (q, *Top, aclArpCompare);
    }
}

/***************/
/* aclMatchArp */
/***************/
static int
aclMatchArp (void *dataptr, struct in_addr c)
{
#if defined(_SQUID_LINUX_)
  struct arpreq arpReq;
  struct sockaddr_in ipAddr;
  unsigned char ifbuffer[sizeof (struct ifreq) * 64];
  struct ifconf ifc;
  struct ifreq *ifr;
  int offset;
  splayNode **Top = dataptr;
  /*
   * The linux kernel 2.2 maintains per interface ARP caches and
   * thus requires an interface name when doing ARP queries.
   * 
   * The older 2.0 kernels appear to use a unified ARP cache,
   * and require an empty interface name
   * 
   * To support both, we attempt the lookup with a blank interface
   * name first. If that does not succeed, the try each interface
   * in turn
   */
  /*
   * Set up structures for ARP lookup with blank interface name
   */
  ipAddr.sin_family = AF_INET;
  ipAddr.sin_port = 0;
  ipAddr.sin_addr = c;
  memset (&arpReq, '\0', sizeof (arpReq));
  xmemcpy (&arpReq.arp_pa, &ipAddr, sizeof (struct sockaddr_in));
  /* Query ARP table */
  if (ioctl (HttpSockets[0], SIOCGARP, &arpReq) != -1)
    {
      /* Skip non-ethernet interfaces */
      if (arpReq.arp_ha.sa_family != ARPHRD_ETHER)
	{
	  return 0;
	}
      debug (28, 4) ("Got address %02x:%02x:%02x:%02x:%02x:%02x\n",
	   arpReq.arp_ha.sa_data[0] & 0xff, arpReq.arp_ha.sa_data[1] & 0xff,
	   arpReq.arp_ha.sa_data[2] & 0xff, arpReq.arp_ha.sa_data[3] & 0xff,
	  arpReq.arp_ha.sa_data[4] & 0xff, arpReq.arp_ha.sa_data[5] & 0xff);
      /* Do lookup */
      *Top = splay_splay (&arpReq.arp_ha.sa_data, *Top, aclArpCompare);
      debug (28, 3) ("aclMatchArp: '%s' %s\n",
		     inet_ntoa (c), splayLastResult ? "NOT found" : "found");
      return (0 == splayLastResult);
    }
  /* lookup list of interface names */
  ifc.ifc_len = sizeof (ifbuffer);
  ifc.ifc_buf = ifbuffer;
  if (ioctl (HttpSockets[0], SIOCGIFCONF, &ifc) < 0)
    {
      debug (28, 1) ("Attempt to retrieve interface list failed: %s\n",
		     xstrerror ());
      return 0;
    }
  if (ifc.ifc_len > sizeof (ifbuffer))
    {
      debug (28, 1) ("Interface list too long - %d\n", ifc.ifc_len);
      return 0;
    }
  /* Attempt ARP lookup on each interface */
  offset = 0;
  while (offset < ifc.ifc_len)
    {
      ifr = (struct ifreq *) (ifbuffer + offset);
      offset += sizeof (*ifr);
      /* Skip loopback and aliased interfaces */
      if (0 == strncmp (ifr->ifr_name, "lo", 2))
	continue;
      if (NULL != strchr (ifr->ifr_name, ':'))
	continue;
      debug (28, 4) ("Looking up ARP address for %s on %s\n", inet_ntoa (c),
		     ifr->ifr_name);
      /* Set up structures for ARP lookup */
      ipAddr.sin_family = AF_INET;
      ipAddr.sin_port = 0;
      ipAddr.sin_addr = c;
      memset (&arpReq, '\0', sizeof (arpReq));
      xmemcpy (&arpReq.arp_pa, &ipAddr, sizeof (struct sockaddr_in));
      strncpy (arpReq.arp_dev, ifr->ifr_name, sizeof (arpReq.arp_dev) - 1);
      arpReq.arp_dev[sizeof (arpReq.arp_dev) - 1] = '\0';
      /* Query ARP table */
      if (-1 == ioctl (HttpSockets[0], SIOCGARP, &arpReq))
	{
	  /*
	   * Query failed.  Do not log failed lookups or "device
	   * not supported"
	   */
	  if (ENXIO == errno)
	    (void) 0;
	  else if (ENODEV == errno)
	    (void) 0;
	  else
	    debug (28, 1) ("ARP query failed: %s: %s\n",
			   ifr->ifr_name, xstrerror ());
	  continue;
	}
      /* Skip non-ethernet interfaces */
      if (arpReq.arp_ha.sa_family != ARPHRD_ETHER)
	continue;
      debug (28, 4) ("Got address %02x:%02x:%02x:%02x:%02x:%02x on %s\n",
		     arpReq.arp_ha.sa_data[0] & 0xff,
		     arpReq.arp_ha.sa_data[1] & 0xff,
		     arpReq.arp_ha.sa_data[2] & 0xff,
		     arpReq.arp_ha.sa_data[3] & 0xff,
		     arpReq.arp_ha.sa_data[4] & 0xff,
		     arpReq.arp_ha.sa_data[5] & 0xff, ifr->ifr_name);
      /* Do lookup */
      *Top = splay_splay (&arpReq.arp_ha.sa_data, *Top, aclArpCompare);
      /* Return if match, otherwise continue to other interfaces */
      if (0 == splayLastResult)
	{
	  debug (28, 3) ("aclMatchArp: %s found on %s\n",
			 inet_ntoa (c), ifr->ifr_name);
	  return 1;
	}
      /*
       * Should we stop looking here? Can the same IP address
       * exist on multiple interfaces?
       */
    }
#elif defined(_SQUID_SOLARIS_)
  struct arpreq arpReq;
  struct sockaddr_in ipAddr;
  unsigned char ifbuffer[sizeof (struct ifreq) * 64];
  struct ifconf ifc;
  struct ifreq *ifr;
  int offset;
  splayNode **Top = dataptr;
  /*
   * Set up structures for ARP lookup with blank interface name
   */
  ipAddr.sin_family = AF_INET;
  ipAddr.sin_port = 0;
  ipAddr.sin_addr = c;
  memset (&arpReq, '\0', sizeof (arpReq));
  xmemcpy (&arpReq.arp_pa, &ipAddr, sizeof (struct sockaddr_in));
  /* Query ARP table */
  if (ioctl (HttpSockets[0], SIOCGARP, &arpReq) != -1)
    {
      /*
       *  Solaris (at least 2.6/x86) does not use arp_ha.sa_family -
       * it returns 00:00:00:00:00:00 for non-ethernet media 
       */
      if (arpReq.arp_ha.sa_data[0] == 0 &&
	  arpReq.arp_ha.sa_data[1] == 0 &&
	  arpReq.arp_ha.sa_data[2] == 0 &&
	  arpReq.arp_ha.sa_data[3] == 0 &&
	  arpReq.arp_ha.sa_data[4] == 0 && arpReq.arp_ha.sa_data[5] == 0)
	return 0;
      debug (28, 4) ("Got address %02x:%02x:%02x:%02x:%02x:%02x\n",
	   arpReq.arp_ha.sa_data[0] & 0xff, arpReq.arp_ha.sa_data[1] & 0xff,
	   arpReq.arp_ha.sa_data[2] & 0xff, arpReq.arp_ha.sa_data[3] & 0xff,
	  arpReq.arp_ha.sa_data[4] & 0xff, arpReq.arp_ha.sa_data[5] & 0xff);
      /* Do lookup */
      *Top = splay_splay (&arpReq.arp_ha.sa_data, *Top, aclArpCompare);
      debug (28, 3) ("aclMatchArp: '%s' %s\n",
		     inet_ntoa (c), splayLastResult ? "NOT found" : "found");
      return (0 == splayLastResult);
    }
#else
  WRITE ME;
#endif
  /*
   * Address was not found on any interface
   */
  debug (28, 3) ("aclMatchArp: %s NOT found\n", inet_ntoa (c));
  return 0;
}

static int
aclArpCompare (const void *a, const void *b)
{
#if defined(_SQUID_LINUX_)
  const unsigned short *d1 = a;
  const unsigned short *d2 = b;
  if (d1[0] != d2[0])
    return (d1[0] > d2[0]) ? 1 : -1;
  if (d1[1] != d2[1])
    return (d1[1] > d2[1]) ? 1 : -1;
  if (d1[2] != d2[2])
    return (d1[2] > d2[2]) ? 1 : -1;
#elif defined(_SQUID_SOLARIS_)
  const unsigned char *d1 = a;
  const unsigned char *d2 = b;
  if (d1[0] != d2[0])
    return (d1[0] > d2[0]) ? 1 : -1;
  if (d1[1] != d2[1])
    return (d1[1] > d2[1]) ? 1 : -1;
  if (d1[2] != d2[2])
    return (d1[2] > d2[2]) ? 1 : -1;
  if (d1[3] != d2[3])
    return (d1[3] > d2[3]) ? 1 : -1;
  if (d1[4] != d2[4])
    return (d1[4] > d2[4]) ? 1 : -1;
  if (d1[5] != d2[5])
    return (d1[5] > d2[5]) ? 1 : -1;
#else
  WRITE ME;
#endif
  return 0;
}

#if UNUSED_CODE
/**********************************************************************
* This is from the pre-splay-tree code for BSD
* I suspect the Linux approach will work on most O/S and be much
* better - <luyer@ucs.uwa.edu.au>
***********************************************************************
static int
checkARP(u_long ip, char *eth)
{
    int mib[6] =
    {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO};
    size_t needed;
    char *buf, *next, *lim;
    struct rt_msghdr *rtm;
    struct sockaddr_inarp *sin;
    struct sockaddr_dl *sdl;
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
	debug(28, 0) ("Can't estimate ARP table size!\n");
	return 0;
    }
    if ((buf = xmalloc(needed)) == NULL) {
	debug(28, 0) ("Can't allocate temporary ARP table!\n");
	return 0;
    }
    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
	debug(28, 0) ("Can't retrieve ARP table!\n");
	xfree(buf);
	return 0;
    }
    lim = buf + needed;
    for (next = buf; next < lim; next += rtm->rtm_msglen) {
	rtm = (struct rt_msghdr *) next;
	sin = (struct sockaddr_inarp *) (rtm + 1);
	sdl = (struct sockaddr_dl *) (sin + 1);
	if (sin->sin_addr.s_addr == ip) {
	    if (sdl->sdl_alen)
		if (!memcmp(LLADDR(sdl), eth, 6)) {
		    xfree(buf);
		    return 1;
		}
	    break;
	}
    }
    xfree(buf);
    return 0;
}
**********************************************************************/
#endif

static void
aclDumpArpListWalkee (void *node, void *state)
{
  acl_arp_data *arp = node;
  wordlist **W = state;
  static char buf[24];
  while (*W != NULL)
    W = &(*W)->next;
  snprintf (buf, sizeof (buf), "%02x:%02x:%02x:%02x:%02x:%02x",
	    arp->eth[0], arp->eth[1], arp->eth[2], arp->eth[3],
	    arp->eth[4], arp->eth[5]);
  wordlistAdd (state, buf);
}

static wordlist *
aclDumpArpList (void *data)
{
  wordlist *w = NULL;
  splay_walk (data, aclDumpArpListWalkee, &w);
  return w;
}

/* ==== END ARP ACL SUPPORT =============================================== */
#endif /* USE_ARP_ACL */
