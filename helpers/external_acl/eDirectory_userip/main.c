/* squid_edir_iplookup - Copyright (C) 2009, 2010 Chad E. Naugle
 *
 ********************************************************************************
 *
 *  This file is part of squid_edir_iplookup.
 *
 *  squid_edir_iplookup is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
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
 * main.c --
 *
 * Main program functions.
 *
 */

#include "main.h"
#include "edui_util.h"
#include "iplookup.h"

char *search_attrib[] = { "cn", "uid", "networkAddress", "groupMembership", NULL };
conf_t conf;
ldap_t ldap;
time_t now;
time_t elap;

/* Displays version information */
void DisplayVersion()
{
    printfx("Squid eDirectory IP Lookup Helper v1.5.  Copyright (C) 2009, 2010 Chad E. Naugle\n");
}

/* Displays program usage information */
void DisplayUsage()
{
    DisplayVersion();
    printfx("\n");
    printfx("Usage: %s\n", conf.program);
    printfx("		-H <host> -p <port> [-Z] [-P] [-v 3] -b <basedn> -s <scope>\n");
    printfx("		-D <binddn> -W <bindpass> -F <search-filter> [-G] \n\n");
    printfx("	-d	    : Debug Mode.\n");
    printfx("	-4	    : Address is IPv4 (127.0.0.1 format).\n");
    printfx("	-6	    : Address is IPv6 (::1 format).\n");
    printfx("	-46	    : Address is IPv4-in-IPv6 (::ffff:127.0.0.1 format).\n");
    printfx("	-H <host>   : Specify hostname/ip of server.\n");
    printfx("	-p <port>   : Specify port number. (Range 1-65535)\n");
    printfx("	-Z	    : Enable TLS security.\n");
    printfx("	-P	    : Use persistent connections.\n");
    printfx("	-t <sec>    : Timeout factor for persistent connections.  (Default is 60 sec, set to 0 for never timeout)\n");
    printfx("	-v <1,2,3>  : Set LDAP version to 1, 2, or 3.\n");
    printfx("	-b <base>   : Specify Base DN. (ie. \"o=ORG\")\n");
    printfx("	-s <scope>  : Specify LDAP Search Scope (base, one, sub; defaults to 'base').\n");
    printfx("	-D <dn>     : Specify Binding DN. (ie. cn=squid,o=ORG)\n");
    printfx("	-W <pass>   : Specify Binding password.\n");
    printfx("	-u <attrib> : Set userid attribute (Defaults to \"cn\").\n");
    printfx("	-F <filter> : Specify LDAP search filter. (ie. \"(objectClass=User)\")\n");
    printfx("	-G 	    : Specify if LDAP search group is required. (ie. \"groupMembership=\")\n");
    printfx("	-V	    : Display version & exit.\n");
    printfx("	-h	    : This screen & exit.\n");
    printfx("\n");
}

/* Initalizes program's configuration paremeters */
void InitConf()
{
    memset(conf.program, '\0', sizeof(conf.program));
    memset(conf.basedn, '\0', sizeof(conf.basedn));
    memset(conf.host, '\0', sizeof(conf.host));
    memset(conf.attrib, '\0', sizeof(conf.attrib));
    memset(conf.dn, '\0', sizeof(conf.dn));
    memset(conf.passwd, '\0', sizeof(conf.passwd));
    memset(conf.search_filter, '\0', sizeof(conf.search_filter));
    conf.scope = -1;
    conf.ver = -1;
    conf.port = -1;
    conf.persist_timeout = -1;
    conf.mode = 0;
    conf.mode |= MODE_INIT;

    /* Set defaults from edui_config.h */
#ifdef DEFAULT_BASE_DN
    strcpy(conf.basedn, DEFAULT_BASE_DN);
#endif
#ifdef DEFAULT_HOST
    strcpy(conf.host, DEFAULT_HOST);
#endif
#ifdef DEFAULT_BIND_DN
    strcpy(conf.dn, DEFAULT_BIND_DN);
#endif
#ifdef DEFAULT_BIND_PASS
    strcpy(conf.passwd, DEFAULT_BIND_PASS);
#endif
#ifdef DEFAULT_USER_ATTRIB
    strcpy(conf.attrib, DEFAULT_USER_ATTRIB);
#endif
#ifdef DEFAULT_SEARCH_FILTER
    strcpy(conf.search_filter, DEFAULT_SEARCH_FILTER);
#endif
#ifdef DEFAULT_SEARCH_SCOPE
    if (!strcmp(DEFAULT_SEARCH_SCOPE, "base"))
        conf.scope = 0;
    else if (!strcmp(DEFAULT_SEARCH_SCOPE, "one"))
        conf.scope = 1;
    else if (!strcmp(DEFAULT_SEARCH_SCOPE, "sub"))
        conf.scope = 2;
    else
        conf.scope = 0;
#endif
#ifdef DEFAULT_LDAP_VERSION
    conf.ver = DEFAULT_LDAP_VERSION;
#endif
#ifdef DEFAULT_PORT
    conf.port = DEFAULT_PORT;
#endif
#ifdef DEFAULT_USE_IPV4
    conf.mode |= MODE_IPV4;
#endif
#ifdef DEFAULT_USE_IPV6
    conf.mode |= MODE_IPV6;
#endif
#ifdef DEFAULT_USE_TLS
    conf.mode |= MODE_TLS;
#endif
#ifdef DEFAULT_USE_PERSIST
    conf.mode |= MODE_PERSIST;
#endif
#ifdef DEFAULT_PERSIST_TIMEOUT
    conf.persist_timeout = DEFAULT_PERSIST_TIMEOUT;
#endif
#ifdef DEFAULT_GROUP_REQUIRED
    conf.mode |= MODE_GROUP;
#endif
#ifdef DEFAULT_DEBUG
    conf.mode |= MODE_DEBUG;
#endif
}

/* Displays running configuration */
void DisplayConf()
{
    if (!(conf.mode & MODE_DEBUG))
        return;
    DisplayVersion();
    printfx("\n");
    printfx("Configuration:\n");
    if (conf.mode & MODE_DEBUG)
        printfx("	Debug mode: ON\n");
    else
        printfx("	Debug mode: OFF\n");
    if ((conf.mode & MODE_IPV4) && (conf.mode & MODE_IPV6))
        printfx("	Address format: IPv4-in-IPv6 (::ffff:127.0.0.1)\n");
    else if (conf.mode & MODE_IPV6)
        printfx("	Address format: IPv6 (::1)\n");
    else
        printfx("	Address format: IPv4 (127.0.0.1)\n");
    if (conf.host[0] != '\0')
        printfx("	Hostname: %s\n", conf.host);
    else
        printfx("	Hostname: 127.0.0.1\n");
    if (conf.port > 0)
        printfx("	Port: %d\n", conf.port);
    else
        printfx("	Port: %d\n", LDAP_PORT);
    if (conf.mode & MODE_TLS)
        printfx("	TLS mode: ON\n");
    else
        printfx("	TLS mode: OFF\n");
    if (conf.mode & MODE_PERSIST) {
        printfx("	Persistent mode: ON\n");
        if (conf.persist_timeout > 0)
            printfx("	Persistent mode idle timeout: %d\n", conf.persist_timeout);
        else
            printfx("	Persistent mode idle timeout: OFF\n");
    } else
        printfx("	Persistent mode: OFF\n");
    printfx("	LDAP Version: %d\n", conf.ver);
    if (conf.basedn[0] != '\0')
        printfx("	Base DN: %s\n", conf.basedn);
    else
        printfx("	Base DN: None\n");
    if (conf.dn[0] != '\0')
        printfx("	Binding DN: %s\n", conf.dn);
    else
        printfx("	Binding DN: Anonymous\n");
    if (conf.passwd[0] != '\0')
        printfx("	Binding Password: %s\n", conf.passwd);
    else
        printfx("	Binding Password: None\n");
    switch (conf.scope) {
    case 0:
        printfx("	Search Scope: base\n");
        break;
    case 1:
        printfx("	Search Scope: one level\n");
        break;
    case 2:
        printfx("	Search Scope: subtree\n");
        break;
    default:
        printfx("	Search Scope: base\n");
        break;
    }
    if (conf.search_filter[0] != '\0')
        printfx("	Search Filter: %s\n", conf.search_filter);
    else
        printfx("	Search Filter: (&(objectClass=User)(networkAddress=*))\n");
    if (conf.mode & MODE_GROUP)
        printfx("	Search Group Required: Yes\n");
    else
        printfx("	Search Group Required: No\n");
    printfx("\n");
}

/* Signal Trap routine */
static void SigTrap(int s)
{
    if (!(conf.mode & MODE_KILL))
        conf.mode |= MODE_KILL;

    /* Clean Up */
    if (ldap.status & LDAP_OPEN_S)
        CloseLDAP(&ldap);

    debug("SigTrap", "Terminating, Signal: %d\n", s);
    exit(0);
}

/* main() - function */
int main(int argc, char **argv)
{
    char bufa[MAXLEN], bufb[MAXLEN], *p = NULL;
    char bufc[MAXLEN];
    char sfmod[MAXLEN];
    int x;
    size_t i, j, s, k;
    time_t t;
    struct sigaction sv;

    /* Init */
    k = (size_t) argc;
    memset(bufa, '\0', sizeof(bufa));
    memset(bufb, '\0', sizeof(bufb));
    memset(bufc, '\0', sizeof(bufc));
    memset(sfmod, '\0', sizeof(sfmod));
    InitConf(&conf);
    strncpy(conf.program, argv[0], sizeof(conf.program));
    now = -1;
    t = -1;
    debug("main", "InitConf() done.\n");

    /* Scan args */
    if (k > 1) {
        for (i = 1; i < k; i++) {
            /* Classic / novelty usage schemes */
            if (!strcmp(argv[i], "--help")) {
                DisplayUsage();
                return 1;
            } else if (!strcmp(argv[i], "--usage")) {
                DisplayUsage();
                return 1;
            } else if (!strcmp(argv[i], "--version")) {
                DisplayVersion();
                return 1;
            } else if (argv[i][0] == '-') {
                s = strlen(argv[i]);
                for (j = 1; j < s; j++) {
                    switch (argv[i][j]) {
                    case 'h':
                        DisplayUsage();
                        return 1;
                    case 'V':
                        DisplayVersion();
                        return 1;
                    case 'd':
                        if (!(conf.mode & MODE_DEBUG))
                            conf.mode |= MODE_DEBUG;		/* Don't set mode more than once */
                        break;
                    case '4':
                        if (!(conf.mode & MODE_IPV4))
                            conf.mode |= MODE_IPV4;			/* Don't set mode more than once */
                        break;
                    case '6':
                        if (!(conf.mode & MODE_IPV6))
                            conf.mode |= MODE_IPV6;			/* Don't set mode more than once */
                        break;
                    case 'Z':
                        if (!(conf.mode & MODE_TLS))
                            conf.mode |= MODE_TLS;			/* Don't set mode more than once */
                        break;
                    case 'P':
                        if (!(conf.mode & MODE_PERSIST))
                            conf.mode |= MODE_PERSIST;			/* Don't set mode more than once */
                        break;
                    case 'v':
                        i++;
                        if (argv[i] != NULL) {
                            conf.ver = atoi(argv[i]);
                            if (conf.ver < 1)
                                conf.ver = 1;
                            else if (conf.ver > 3)
                                conf.ver = 3;
                        } else {
                            printfx("No parameters given for 'v'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 't':
                        i++;
                        if (argv[i] != NULL) {
                            conf.persist_timeout = atoi(argv[i]);
                            if (conf.persist_timeout < 0)
                                conf.persist_timeout = 0;
                        } else {
                            printfx("No parameters given for 't'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'b':
                        i++;					/* Set Base DN */
                        if (argv[i] != NULL)
                            strncpy(conf.basedn, argv[i], sizeof(conf.basedn));
                        else {
                            printfx("No parameters given for 'b'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'H':
                        i++;					/* Set Hostname */
                        if (argv[i] != NULL)
                            strncpy(conf.host, argv[i], sizeof(conf.host));
                        else {
                            printfx("No parameters given for 'H'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'p':
                        i++;					/* Set port */
                        if (argv[i] != NULL)
                            conf.port = atoi(argv[i]);
                        else {
                            printfx("No parameters given for 'p'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'D':
                        i++;					/* Set Bind DN */
                        if (argv[i] != NULL)
                            strncpy(conf.dn, argv[i], sizeof(conf.dn));
                        else {
                            printfx("No parameters given for 'D'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'W':
                        i++;					/* Set Bind PWD */
                        if (argv[i] != NULL)
                            strncpy(conf.passwd, argv[i], sizeof(conf.passwd));
                        else {
                            printfx("No parameters given for 'W'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'F':
                        i++;					/* Set Search Filter */
                        if (argv[i] != NULL)
                            strncpy(conf.search_filter, argv[i], sizeof(conf.search_filter));
                        else {
                            printfx("No parameters given for 'F'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'G':
                        if (!(conf.mode & MODE_GROUP))
                            conf.mode |= MODE_GROUP;		/* Don't set mode more than once */
                        break;
                    case 's':
                        i++;					/* Set Scope Level */
                        if (argv[i] != NULL) {
                            if (!strncmp(argv[i], "base", 4))
                                conf.scope = 0;
                            else if (!strncmp(argv[i], "one", 4))
                                conf.scope = 1;
                            else if (!strncmp(argv[i], "sub", 4))
                                conf.scope = 2;
                            else
                                conf.scope = 0;			/* Default is 'base' */
                        } else {
                            printfx("No parameters given for 's'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case '-':					/* We got a second '-' ... ignore */
                        break;
                    default:
                        printfx("Invalid parameter - '%c'.\n", argv[i][j]);
                        break;
                    }
                }
            } else {
                /* Incorrect parameter, display usage */
                DisplayUsage();
                return 1;
            }
        }
    }

    /* Set predefined required paremeters if none are given, localhost:LDAP_PORT, etc */
    if (conf.host[0] == '\0')				/* Default to 127.0.0.1 */
        strcpy(conf.host, "127.0.0.1");
    if (conf.port < 0)
        conf.port = LDAP_PORT;				/* Default: LDAP_PORT */
    if (!(conf.mode & MODE_IPV4) && !(conf.mode & MODE_IPV6))
        conf.mode |= MODE_IPV4;				/* Default to IPv4 */
    if (conf.ver < 0)
        conf.ver = 2;
    if ((conf.mode & MODE_TLS) && (conf.ver < 3))
        conf.ver = 3;					/* TLS requires version 3 */
    if (conf.persist_timeout < 0)
        conf.persist_timeout = 600;				/* Default: 600 seconds (10 minutes) */
    if (conf.scope < 0)
        conf.scope = 0;					/* Default: base */
    if (conf.search_filter[0] == '\0')
        strcpy(conf.search_filter, "(&(objectclass=User)(networkAddress=*))");
    debug("main", "Configuration done.\n");

    DisplayConf();
    /* Done with arguments */

    /* Trap the following signals */
    sigemptyset(&sv.sa_mask);
    sv.sa_handler = SigTrap;
    sigaction(SIGTERM, &sv, NULL);
    sv.sa_handler = SigTrap;
    sigaction(SIGHUP, &sv, NULL);
    sv.sa_handler = SigTrap;
    sigaction(SIGABRT, &sv, NULL);
    sv.sa_handler = SigTrap;
    sigaction(SIGINT, &sv, NULL);
    sv.sa_handler = SigTrap;
    sigaction(SIGSEGV, &sv, NULL);
    debug("main", "Signals trapped.\n");

    /* Set elap timer */
    time(&now);
    t = now;

    /* Main loop -- Waits for stdin input before action */
    while (fgets(bufa, sizeof(bufa), stdin) != NULL) {
        if (conf.mode & MODE_KILL)
            break;
        time(&now);
        if (t < now) {
            /* Elapse seconds */
            elap = now - t;
//      debug("main", "while() -> %d seconds elapsed.\n", elap);
            t = now;
        } else
            elap = 0;
        k = strlen(bufa);
        /*
            debug("main", "while() -> bufa[%zd]: %s", k, bufa);
            debug("main", "while() -> bufa[%zd]: ");
            for (i = 0; i < k; i++)
              debugx("%.2X", bufa[i]);
            debugx("\n");
        */
        /* Check for CRLF */
        p = strchr(bufa, '\n');
        if (p != NULL)
            *p = '\0';
        p = strchr(bufa, '\r');
        if (p != NULL)
            *p = '\0';
        p = strchr(bufa, ' ');

        /* No space given, but group string is required --> ERR */
        if ((conf.mode & MODE_GROUP) && (p == NULL)) {
            debug("main", "while() -> Search group is required.\n");
            printfx("ERR\n");
            continue;
        }
        x = 0;

        /* Open LDAP connection */
        if (!(ldap.status & LDAP_INIT_S)) {
            InitLDAP(&ldap);
            debug("main", "InitLDAP() -> %s\n", ErrLDAP(LDAP_ERR_SUCCESS));
            if (conf.mode & MODE_PERSIST)					/* Setup persistant mode */
                ldap.status |= LDAP_PERSIST_S;
        }
        if ((ldap.status & LDAP_IDLE_S) && (elap > 0)) {
            ldap.idle_time = ldap.idle_time + elap;
        }
        if ((ldap.status & LDAP_PERSIST_S) && (ldap.status & LDAP_IDLE_S) && (ldap.idle_time > conf.persist_timeout)) {
            debug("main", "while() -> Connection timed out after %u seconds\n", ldap.idle_time);
            x = CloseLDAP(&ldap);
            debug("main", "CloseLDAP(-) -> %s\n", ErrLDAP(x));
        }
        ldap.err = -1;
        if (!(ldap.status & LDAP_OPEN_S)) {
            x = OpenLDAP(&ldap, conf.host, conf.port);
            if (x != LDAP_ERR_SUCCESS) {
                /* Failed to connect */
                debug("main", "OpenLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(ldap.err));
            } else {
                debug("main", "OpenLDAP(-, %s, %d) -> %s\n", conf.host, conf.port, ErrLDAP(x));
                x = SetVerLDAP(&ldap, conf.ver);
                if (x != LDAP_ERR_SUCCESS) {
                    /* Failed to set version */
                    debug("main", "SetVerLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(ldap.err));
                } else
                    debug("main", "SetVerLDAP(-, %d) -> %s\n", conf.ver, ErrLDAP(x));
            }
        }
        ldap.err = -1;
        if (!(ldap.status & LDAP_BIND_S) && (conf.mode & MODE_TLS)) {
            /* TLS binding */
            x = BindLDAP(&ldap, conf.dn, conf.passwd, LDAP_AUTH_TLS);
            if (x != LDAP_ERR_SUCCESS) {
                /* Unable to bind */
                debug("main", "BindLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(ldap.err));
            } else
                debug("main", "BindLDAP(-, %s, %s, %ul) -> %s\n", conf.dn, conf.passwd, LDAP_AUTH_TLS, ErrLDAP(x));
        } else if (!(ldap.status & LDAP_BIND_S)) {
            if (conf.dn[0] != '\0') {
                /* Simple binding - using dn / passwd for authorization */
                x = BindLDAP(&ldap, conf.dn, conf.passwd, LDAP_AUTH_SIMPLE);
                if (x != LDAP_ERR_SUCCESS) {
                    /* Unable to bind */
                    debug("main", "BindLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(ldap.err));
                } else
                    debug("main", "BindLDAP(-, %s, %s, %ul) -> %s\n", conf.dn, conf.passwd, LDAP_AUTH_SIMPLE, ErrLDAP(x));
            } else {
                /* Anonymous binding */
                x = BindLDAP(&ldap, conf.dn, conf.passwd, LDAP_AUTH_NONE);
                if (x != LDAP_ERR_SUCCESS) {
                    /* Unable to bind */
                    debug("main", "BindLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(ldap.err));
                } else
                    debug("main", "BindLDAP(-, -, -, %ul) -> %s\n", LDAP_AUTH_NONE, ErrLDAP(x));
            }
        }
        ldap.err = -1;
        if (ldap.status & LDAP_PERSIST_S) {
            x = ResetLDAP(&ldap);
            if (x != LDAP_ERR_SUCCESS) {
                /* Unable to reset */
                debug("main", "ResetLDAP() -> %s\n", ErrLDAP(x));
            } else
                debug("main", "ResetLDAP() -> %s\n", ErrLDAP(x));
        }
        if (x != LDAP_ERR_SUCCESS) {
            /* Everything failed --> ERR */
            debug("main", "while() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(ldap.err));
            CloseLDAP(&ldap);
            printfx("ERR\n");
            continue;
        }
        ldap.err = -1;
        /* If we got a group string, split it */
        if (p != NULL) {
            /* Split string */
            debug("main", "SplitString(%s, %zd, ' ', %s, %zd)\n", bufa, strlen(bufa), bufb, sizeof(bufb));
            i = SplitString(bufa, strlen(bufa), ' ', bufb, sizeof(bufb));
            if (i > 0) {
                debug("main", "SplitString(%s, %s) done.  Result: %zd\n", bufa, bufb, i);
                /* Got a group to match against */
                x = ConvertIP(&ldap, bufb);
                if (x < 0) {
                    debug("main", "ConvertIP() -> %s\n", ErrLDAP(x));
                    printfx("ERR\n");
                } else {
                    ldap.err = -1;
                    debug("main", "ConvertIP(-, %s) -> Result[%zd]: %s\n", bufb, x, ldap.search_ip);
                    x = SearchFilterLDAP(&ldap, bufa);
                    if (x < 0) {
                        debug("main", "SearchFilterLDAP() -> %s\n", ErrLDAP(x));
                        printfx("ERR\n");
                    } else {
                        /* Do Search */
                        ldap.err = -1;
                        debug("main", "SearchFilterLDAP(-, %s) -> Length: %u\n", bufa, x);
                        x = SearchLDAP(&ldap, ldap.scope, ldap.search_filter, search_attrib);
                        if (x != LDAP_ERR_SUCCESS) {
                            debug("main", "SearchLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(ldap.err));
                            printfx("ERR\n");
                        } else {
                            ldap.err = -1;
                            debug("main", "SearchLDAP(-, %d, %s, -) -> %s\n", conf.scope, ldap.search_filter, ErrLDAP(x));
                            x = SearchIPLDAP(&ldap, bufc);
                            if (x != LDAP_ERR_SUCCESS) {
                                debug("main", "SearchIPLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(ldap.err));
                                printfx("ERR\n");
                            } else {
                                debug("main", "SearchIPLDAP(-, %s) -> %s\n", bufc, ErrLDAP(x));
                                printfx("OK user=%s\n", bufc);			/* Got userid --> OK user=<userid> */
                            }
                        }
                        /* Clear for next query */
                        memset(bufc, '\0', strlen(bufc));
                    }
                }
            } else {
                debug("main", "SplitString() -> Error: %d\n", i);
                printfx("ERR\n");
            }
        } else {
            /* No group to match against, only an IP */
            x = ConvertIP(&ldap, bufa);
            if (x < 0) {
                debug("main", "ConvertIP() -> %s\n", ErrLDAP(x));
                printfx("ERR\n");
            } else {
                debug("main", "ConvertIP(-, %s) -> Result[%zd]: %s\n", bufa, x, ldap.search_ip);
                /* Do search */
                x = SearchFilterLDAP(&ldap, NULL);
                if (x < 0) {
                    debug("main", "SearchFilterLDAP() -> %s\n", ErrLDAP(x));
                    printfx("ERR\n");
                } else {
                    ldap.err = -1;
                    debug("main", "SearchFilterLDAP(-, NULL) -> Length: %u\n", x);
                    x = SearchLDAP(&ldap, ldap.scope, ldap.search_filter, search_attrib);
                    if (x != LDAP_ERR_SUCCESS) {
                        debug("main", "SearchLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(x));
                        printfx("ERR\n");
                    } else {
                        ldap.err = -1;
                        debug("main", "SearchLDAP(-, %d, %s, -) -> %s\n", conf.scope, ldap.search_filter, ErrLDAP(x));
                        x = SearchIPLDAP(&ldap, bufc);
                        if (x != LDAP_ERR_SUCCESS) {
                            debug("main", "SearchIPLDAP() -> %s (LDAP: %s)\n", ErrLDAP(x), ldap_err2string(ldap.err));
                            printfx("ERR\n");
                        } else {
                            debug("main", "SearchIPLDAP(-, %s) -> %s\n", bufc, ErrLDAP(x));
                            printfx("OK user=%s\n", bufc);				/* Got a userid --> OK user=<userid> */
                        }
                    }
                }
                /* Clear for next query */
                memset(bufc, '\0', strlen(bufc));
            }
        }

        /* Clear buffer and close for next data, if not persistent */
        ldap.err = -1;
        memset(bufa, '\0', strlen(bufa));
        if (!(ldap.status & LDAP_PERSIST_S)) {
            x = CloseLDAP(&ldap);
            debug("main", "CloseLDAP(-) -> %s\n", ErrLDAP(x));
        }
    }

    debug("main", "Terminating.\n");
    exit(1);
}
