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
 * main.c --
 *
 * Main program functions.
 *
 */

#include "main.h"
#include "util.h"
#include "iplookup.h"

char *search_attrib[] = { "cn", "uid", "networkAddress", "groupMembership", NULL };
conf_t conf;
ldap_t ldap;

/* Displays version information */
void DisplayVersion()
{
    printfx("Squid eDirectory IP Lookup Helper v1.2.  Copyright (C) 2009, 2010 Chad E. Naugle\n");
}

/* Displays program usage information */
void DisplayUsage()
{
    DisplayVersion();
    printfx("\n");
    printfx("Usage: %s\n", conf.program);
    printfx("		-H <host> -p <port> [-Z] [-2/3] -b <basedn> -s <scope>\n");
    printfx("		-D <binddn> -W <bindpass> -F <search-filter> -G \n\n");
    printfx("	-d	    : Debug Mode.\n");
    printfx("	-4	    : Address is IPv4 (127.0.0.1 format).\n");
    printfx("	-6	    : Address is IPv6 (::1 format).\n");
    printfx("	-46	    : Address is IPv4-in-IPv6 (::ffff:127.0.0.1 format).\n");
    printfx("	-H <host>   : Specify hostname/ip of server.\n");
    printfx("	-p <port>   : Specify port number. (Range 1-65535)\n");
    printfx("	-Z	    : Enable TLS security.\n");
    printfx("	-1	    : Set LDAP version 1.\n");
    printfx("	-2	    : Set LDAP version 2.\n");
    printfx("	-3	    : Set LDAP version 3.\n");
    printfx("	-b <base>   : Specify Base DN. (ie. o=ORG)\n");
    printfx("	-s <scope>  : Specify LDAP Search Scope (base, one, sub; defaults to 'base').\n");
    printfx("	-D <dn>     : Specify Binding DN. (ie. cn=squid,o=ORG)\n");
    printfx("	-W <pass>   : Specify Binding password.\n");
    printfx("	-F <filter> : Specify LDAP search filter. (ie. \"(objectClass=User)\")\n");
    printfx("	-G 	    : Specify if LDAP search group is required.\n");
    printfx("	-v	    : Display version & exit.\n");
    printfx("	-h	    : This screen & exit.\n");
    printfx("\n");
}

/* Initalizes program's configuration paremeters */
void InitConf()
{
    memset(conf.program, '\0', sizeof(conf.program));
    memset(conf.basedn, '\0', sizeof(conf.basedn));
    memset(conf.host, '\0', sizeof(conf.host));
    memset(conf.dn, '\0', sizeof(conf.dn));
    memset(conf.passwd, '\0', sizeof(conf.passwd));
    memset(conf.search_filter, '\0', sizeof(conf.search_filter));
    conf.scope = -1;
    conf.ver = -1;
    conf.port = -1;
    conf.mode = 0;
    conf.mode |= MODE_INIT;

    /* Set defaults from config.h */
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
#ifdef DEFAULT_SEARCH_FILTER
    strcpy(conf.search_filter, DEFAULT_SEARCH_FILTER);
#endif
#ifdef DEFAULT_SEARCH_SCOPE
    conf.scope = DEFAULT_SEARCH_SCOPE;
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
#ifdef DEFAULT_DEBUG
    conf.mode |= MODE_DEBUG;
#endif
#ifdef DEFAULT_GROUP_REQUIRED
    conf.mode |= MODE_GROUP;
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
    struct sigaction sv;

    /* Init */
    k = (size_t) argc;
    memset(bufa, '\0', sizeof(bufa));
    memset(bufb, '\0', sizeof(bufb));
    memset(bufc, '\0', sizeof(bufc));
    memset(sfmod, '\0', sizeof(sfmod));
    InitConf(&conf);
    strncpy(conf.program, argv[0], sizeof(conf.program));
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
                    case 'v':
                        DisplayVersion();
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
                    case '1':
                        conf.ver = 1;
                        break;
                    case '2':
                        conf.ver = 2;
                        break;
                    case '3':
                        conf.ver = 3;
                        break;
                    case 'b':
                        i++;					/* Set Base DN */
                        if (argv[i] != NULL)
                            strncpy(conf.basedn, argv[i], sizeof(conf.basedn));
                        else {
                            printfx("No parameters given to 'b'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'H':
                        i++;					/* Set Hostname */
                        if (argv[i] != NULL)
                            strncpy(conf.host, argv[i], sizeof(conf.host));
                        else {
                            printfx("No parameters given to 'H'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'p':
                        i++;					/* Set port */
                        if (argv[i] != NULL)
                            conf.port = atoi(argv[i]);
                        else {
                            printfx("No parameters given to 'p'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'D':
                        i++;					/* Set Bind DN */
                        if (argv[i] != NULL)
                            strncpy(conf.dn, argv[i], sizeof(conf.dn));
                        else {
                            printfx("No parameters given to 'D'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'W':
                        i++;					/* Set Bind PWD */
                        if (argv[i] != NULL)
                            strncpy(conf.passwd, argv[i], sizeof(conf.passwd));
                        else {
                            printfx("No parameters given to 'W'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'F':
                        i++;					/* Set Search Filter */
                        if (argv[i] != NULL)
                            strncpy(conf.search_filter, argv[i], sizeof(conf.search_filter));
                        else {
                            printfx("No parameters given to 'F'.\n");
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
                            strncpy(bufa, argv[i], sizeof(bufa));
                            if (!strcmp(bufa, "base"))
                                conf.scope = 0;
                            else if (!strcmp(bufa, "one"))
                                conf.scope = 1;
                            else if (!strcmp(bufa, "sub"))
                                conf.scope = 2;
                            else
                                conf.scope = 0;
                        } else {
                            printfx("No parameters given to 's'.\n");
                            DisplayUsage();
                            return 1;
                        }
                        break;
                    case 'h':
                        DisplayUsage();
                        return 1;
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

    /* Main loop -- Waits for stdin input before action */
    while (fgets(bufa, sizeof(bufa), stdin) != NULL) {
        if (conf.mode & MODE_KILL)
            break;
        k = strlen(bufa);
        debug("main", "while() bufa[%zd]: %s", k, bufa);
        debug("main", "while() bufa[%zd]: ");
        for (i = 0; i < k; i++)
            debugx("%.2X", bufa[i]);
        debugx("\n");
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
            printfx("ERR\n");
            continue;
        }

        /* Open LDAP connection */
        InitLDAP(&ldap);
        debug("main", "InitLDAP() done.\n");
        x = OpenLDAP(&ldap, conf.host, conf.port);
        if (x != LDAP_SUCCESS) {
            /* Failed to connect */
            debug("main", "Failed to connect.  Error: %d (%s)\n", x, ldap_err2string(x));
        } else {
            debug("main", "OpenLDAP(-, %s, %d) done. Result: %d\n", conf.host, conf.port, x);
            x = SetVerLDAP(&ldap, conf.ver);
            if (x != LDAP_SUCCESS) {
                /* Failed to set version */
                debug("main", "Failed to set version.  Error: %d (%s)\n", x, ldap_err2string(x));
            } else {
                debug("main", "SetVerLDAP(-, %d) done. Result: %d\n", conf.ver, x);
                if (conf.mode & MODE_TLS) {
                    /* TLS binding */
                    x = BindLDAP(&ldap, conf.dn, conf.passwd, LDAP_AUTH_TLS);
                    if (x != LDAP_SUCCESS) {
                        /* Unable to bind */
                        debug("main", "Failed to bind.  Error: %d (%s)\n", x, ldap_err2string(x));
                    } else
                        debug("main", "BindLDAP(-, %s, %s, %ul) done. Result: %d\n", conf.dn, conf.passwd, LDAP_AUTH_TLS, x);
                } else if (conf.dn[0] != '\0') {
                    /* Simple binding - using dn / passwd for authorization */
                    x = BindLDAP(&ldap, conf.dn, conf.passwd, LDAP_AUTH_SIMPLE);
                    if (x != LDAP_SUCCESS) {
                        /* Unable to bind */
                        debug("main", "Failed to bind.  Error: %d (%s)\n", x, ldap_err2string(x));
                    } else
                        debug("main", "BindLDAP(-, %s, %s, %ul) done. Result: %d\n", conf.dn, conf.passwd, LDAP_AUTH_SIMPLE, x);
                } else {
                    /* Anonymous binding */
                    x = BindLDAP(&ldap, conf.dn, conf.passwd, LDAP_AUTH_NONE);
                    if (x != LDAP_SUCCESS) {
                        /* Unable to bind */
                        debug("main", "Failed to bind.  Error: %d (%s)\n", x, ldap_err2string(x));
                    } else
                        debug("main", "BindLDAP(-, -, -, %ul) done. Result: %d\n", LDAP_AUTH_NONE, x);
                }
            }
        }
        /* Everything failed --> ERR */
        if (x != LDAP_SUCCESS) {
            printfx("ERR\n");
            memset(bufa, '\0', strlen(bufa));
            CloseLDAP(&ldap);
            continue;
        } else {
            /* We got a group string -- split it */
            if (p != NULL) {
                /* Split string */
                debug("main", "SplitString(%s, %zd, ' ', %s, %zd)\n", bufa, strlen(bufa), bufb, sizeof(bufb));
                i = SplitString(bufa, strlen(bufa), ' ', bufb, sizeof(bufb));
                if (i > 0) {
                    debug("main", "SplitString(%s, %s) done.  Result: %zd\n", bufa, bufb, i);
                    /* Got a group to match against */
                    x = ConvertIP(&ldap, bufb);
                    if (x < 0) {
                        debug("main", "Failed to ConvertIP().  Error: %d\n", x);
                        printfx("ERR (ConvertIP %d)\n", x);
                    } else {
                        debug("main", "ConvertIP(-, %s) done.  Result[%zd]: %s\n", bufb, x, ldap.search_ip);
                        x = SearchFilterLDAP(&ldap, bufa);
                        if (x < 0) {
                            debug("main", "Failed to SearchFilterLDAP().  Error: %d\n", x);
                            printfx("ERR\n");
                        } else {
                            /* Do Search */
                            debug("main", "IP: %s, Search Filter: %s\n", ldap.search_ip, ldap.search_filter);
                            x = SearchLDAP(&ldap, ldap.scope, ldap.search_filter, search_attrib);
                            if (x != LDAP_SUCCESS) {
                                debug("main", "Failed to SearchLDAP().  Error: %d (%s)\n", x, ldap_err2string(x));
                                printfx("ERR\n");
                            } else {
                                debug("main", "SearchLDAP(-, %d, %s, -) done. Result: %d\n", conf.scope, ldap.search_filter, x);
                                x = SearchIPLDAP(&ldap, bufc);
                                if (x != LDAP_SUCCESS) {
                                    debug("main", "Failed to SearchIPLDAP().  Error: %d\n", x);
                                    printfx("ERR\n");
                                } else {
                                    debug("main", "SearchIPLDAP(-, %s) done. Result: %d\n", bufc, x);
                                    printfx("OK user=%s\n", bufc);			/* Got userid --> OK user=<userid> */
                                }
                            }

                            /* Clear for next query */
                            memset(bufc, '\0', strlen(bufc));
                        }
                    }
                } else {
                    debug("main", "Failed to SplitString().  Error: %d\n", i);
                    printfx("ERR\n");
                }
            } else {
                /* No group to match against, only an IP */
                x = ConvertIP(&ldap, bufa);
                if (x < 0) {
                    debug("main", "Failed to ConvertIP().  Error: %d\n", x);
                    printfx("ERR (ConvertIP %d)\n", x);
                } else {
                    debug("main", "ConvertIP(-, %s) done.  Result[%zd]: %s\n", bufa, x, ldap.search_ip);
                    /* Do search */
                    x = SearchFilterLDAP(&ldap, NULL);
                    if (x < 0) {
                        debug("main", "Failed to SearchFilterLDAP().  Error: %d\n", x);
                        printfx("ERR\n");
                    } else {
                        debug("main", "IP: %s, Search Filter: %s\n", ldap.search_ip, ldap.search_filter);
                        x = SearchLDAP(&ldap, ldap.scope, ldap.search_filter, search_attrib);
                        if (x != LDAP_SUCCESS) {
                            debug("main", "Failed to SearchLDAP().  Error: %d (%s)\n", x, ldap_err2string(x));
                            printfx("ERR\n");
                        } else {
                            debug("main", "SearchLDAP(-, %d, %s, -) done. Result: %d\n", conf.scope, ldap.search_filter, x);
                            x = SearchIPLDAP(&ldap, bufc);
                            if (x != LDAP_SUCCESS) {
                                debug("main", "Failed to SearchIPLDAP().  Error: %d\n", x);
                                printfx("ERR\n");
                            } else {
                                debug("main", "SearchIPLDAP(-, %s) done. Result: %d\n", bufc, x);
                                printfx("OK user=%s\n", bufc);				/* Got a userid --> OK user=<userid> */
                            }
                        }
                    }
                    /* Clear for next query */
                    memset(bufc, '\0', strlen(bufc));
                }
            }
        }

        /* Clear buffer and close for next data */
        memset(bufa, '\0', strlen(bufa));
        CloseLDAP(&ldap);
    }

    debug("main", "Terminating.\n");
    exit(1);
}
