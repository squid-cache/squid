/* $Id: cachemgr.cc,v 1.5 1996/04/01 23:22:03 wessels Exp $ */

#include "squid.h"

static int client_comm_connect();

#define MAX_ENTRIES 10000
#define INFO        0
#define CACHED      1
#define SERVER      2
#define LOG         3
#define STATS_G     4
#define STATS_O     5
#define STATS_U     6
#define PARAM       7
#define RESPT       8
#define SHUTDOWN    9
#define REFRESH     10
#ifdef REMOVE_OBJECT
#define REMOVE      11
#endif
#define FALSE       0
#define TRUE        1

typedef struct {
    char *name;
    char *val;
} entry;

int hasTables = FALSE;

char *script_name = "/Harvest/cgi-bin/cachemgr.cgi";
char *progname = NULL;

#define LF 10
#define CR 13

void print_trailer()
{
    time_t now = time(NULL);
    static char tbuf[128];
    struct tm *gmt;

    gmt = gmtime(&now);
    strftime(tbuf, 128, "%A, %d-%b-%y %H:%M:%S GMT", gmt);

    printf("<HR>\n");
    printf("<ADDRESS>\n");
    printf("Generated %s, by %s/%s@%s\n",
	tbuf, progname, SQUID_VERSION, getfullhostname());
    printf("</ADDRESS>\n");
}

void noargs_html()
{
    printf("\r\n\r\n");
    printf("<TITLE>Harvest Cache Manager Interface</TITLE>\n");
    printf("<H1>Cache Manager Interface</H1>\n");
    printf("<P>\n");
    printf("This is a WWW interface to the instrumentation interface ");
    printf("for the\n");
    printf("<A HREF=\"http://harvest.cs.colorado.edu/\">\n");
    printf("\tHarvest object cache</A>.\n");
    printf("<HR>\n");
    printf("<P>\n");
    printf("<FORM METHOD=\"POST\" ACTION=\"%s\">\n", script_name);
    printf("<PRE>\n");
    printf("<BR><STRONG>Cache Host:</STRONG><INPUT NAME=\"host\" ");
    printf("SIZE=30 VALUE=\"%s\">\n", CACHEMGR_HOSTNAME);
    printf("<BR><STRONG>Cache Port:</STRONG><INPUT NAME=\"port\" ");
    printf("SIZE=30 VALUE=\"%d\">\n", CACHE_HTTP_PORT);
    printf("<BR><STRONG>Password  :</STRONG><INPUT TYPE=\"password\" ");
    printf("NAME=\"password\" SIZE=30 VALUE=\"\">\n");
    printf("<BR><STRONG>URL       :</STRONG><INPUT NAME=\"url\" ");
    printf("SIZE=30 VALUE=\"\">\n");
    printf("<BR><STRONG>Operation :</STRONG>");
    printf("<SELECT NAME=\"operation\">\n");
    printf("<OPTION SELECTED VALUE=\"info\">Cache Information\n");
    printf("<OPTION VALUE=\"cached.conf\">Cache Configuration File\n");
    printf("<OPTION VALUE=\"parameter\">Cache Parameters\n");
#ifdef MENU_RESPONSETIME
    printf("<OPTION VALUE=\"responsetime\">Cache Response Time Histogram\n");
#endif
#ifdef MENU_SHOW_LOG
    printf("<OPTION VALUE=\"log\">Cache Log\n");
#endif
    printf("<OPTION VALUE=\"stats/utilization\">Utilization\n");
    printf("<OPTION VALUE=\"stats/objects\">Objects\n");
    printf("<OPTION VALUE=\"stats/vm_objects\">VM_Objects\n");
    printf("<OPTION VALUE=\"server_list\">Cache Server List\n");
    printf("<OPTION VALUE=\"stats/general\">IP Cache Contents\n");
    printf("<OPTION VALUE=\"shutdown\">Shutdown Cache (password required)\n");
    printf("<OPTION VALUE=\"refresh\">Refresh Object (URL required)\n");
#ifdef REMOVE_OBJECT
    printf("<OPTION VALUE=\"remove\">Remove Object (URL required)\n");
#endif
    printf("</SELECT>\n");
    printf("</PRE>\n");
    printf("<HR>\n");
    printf("<BR><INPUT TYPE=\"submit\"> <INPUT TYPE=\"reset\">\n");
    printf("</FORM>\n");
    print_trailer();
}

/* A utility function from the NCSA httpd cgi-src utils.c */
char *makeword(char *line, char stop)
{
    int x = 0, y;
    char *word = (char *) malloc(sizeof(char) * (strlen(line) + 1));

    for (x = 0; ((line[x]) && (line[x] != stop)); x++)
	word[x] = line[x];

    word[x] = '\0';
    if (line[x])
	++x;
    y = 0;

    while ((line[y++] = line[x++]));
    return word;
}

/* A utility function from the NCSA httpd cgi-src utils.c */
char *fmakeword(FILE * f, char stop, int *cl)
{
    int wsize;
    char *word;
    int ll;

    wsize = 102400;
    ll = 0;
    word = (char *) malloc(sizeof(char) * (wsize + 1));

    while (1) {
	word[ll] = (char) fgetc(f);
	if (ll == wsize) {
	    word[ll + 1] = '\0';
	    wsize += 102400;
	    word = (char *) realloc(word, sizeof(char) * (wsize + 1));
	}
	--(*cl);
	if ((word[ll] == stop) || (feof(f)) || (!(*cl))) {
	    if (word[ll] != stop)
		ll++;
	    word[ll] = '\0';
	    return word;
	}
	++ll;
    }
    /* NOTREACHED */
}

/* A utility function from the NCSA httpd cgi-src utils.c */
char x2c(char *what)
{
    register char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10 : (what[1] - '0'));
    return (digit);
}

/* A utility function from the NCSA httpd cgi-src utils.c */
void unescape_url(char *url)
{
    register int x, y;

    for (x = 0, y = 0; url[y]; ++x, ++y) {
	if ((url[x] = url[y]) == '%') {
	    url[x] = x2c(&url[y + 1]);
	    y += 2;
	}
    }
    url[x] = '\0';
}

/* A utility function from the NCSA httpd cgi-src utils.c */
void plustospace(char *str)
{
    register int x;

    for (x = 0; str[x]; x++)
	if (str[x] == '+')
	    str[x] = ' ';
}


void parse_object(char *string)
{
    char *tmp_line = NULL;
    char *url = NULL;
    char *token = NULL;
    char *store_time = NULL;
    char *last_ref = NULL;
    char *ttl = NULL;
    char *sto = NULL;
    char *status = NULL;
    char *obj_status = NULL;
    char *w_space = " \t\n";
    int obj_size;
    int ref_cnt;

    /* Use tmp_line as a temporary pointer to the input line */
    tmp_line = string;

    /* Parse out the url */
    url = strtok(tmp_line, w_space);

    if (!url)
	return;

#if !ALL_OBJECTS
    if (!strncmp(url, "cache_object", 12))
	return;
    if (!strncmp(url, "POST", 4))
	return;
#endif

    tmp_line = NULL;

    token = strtok(tmp_line, w_space);
    sscanf(token, "%d", &obj_size);

    token = strtok(tmp_line, w_space);
    store_time = strdup(token);

    token = strtok(tmp_line, w_space);
    obj_status = strdup(token);

    token = strtok(tmp_line, w_space);
    last_ref = strdup(token);

    token = strtok(tmp_line, w_space);
    ttl = strdup(token);

    token = strtok(tmp_line, w_space);
    /* Active */

    token = strtok(tmp_line, w_space);
    sscanf(token, "%d", &ref_cnt);

    token = strtok(tmp_line, w_space);
    sto = strdup(token);

    token = strtok(tmp_line, w_space);
    status = strdup(token);

    printf("<LI>Cache: <A HREF=\"%s\">%s</A><BR>",
	url, url);
    printf("Size: %d bytes, TTL: %s ,<BR>",
	obj_size, ttl);
    printf("Stored: %s, %s ago, %s %s,<BR>",
	sto, store_time, obj_status, status);
    printf("Refs: %d, Referenced %s hh:mm:ss ago</LI>\n",
	ref_cnt, last_ref);

    free(ttl);
    free(store_time);
    free(last_ref);
    free(sto);
    free(status);
}

int main(int argc, char *argv[])
{
    static char hostname[256];
    static char operation[256];
    static char password[256];
    static char url[4096];
    static char msg[1024];
    static char buf[4096];
    static char reserve[4096];
    static char s1[255];
    static char s2[255];
    char *time_string = NULL;
    char *agent = NULL;
    char *s = NULL;
    int got_data = 0;
    int x;
    int cl;
    int conn;
    int len;
    int bytesWritten;
    int portnum = CACHE_HTTP_PORT;
    int op;
    int p_state;
    int n_loops;
    int cpy_ind;
    int indx;
    int in_list = 0;
    int in_table = 0;
    int d1, d2, d3, d4, d5, d6, d7;
    int single = TRUE;
    float f1;
    time_t time_val;
    entry entries[MAX_ENTRIES];

    if ((s = strrchr(argv[0], '/')))
	progname = strdup(s + 1);
    else
	progname = strdup(argv[0]);
    if ((s = getenv("SCRIPT_NAME")) != NULL) {
	script_name = strdup(s);
    }
    printf("Content-type: text/html\r\n\r\n");
    if ((agent = getenv("HTTP_USER_AGENT")) != NULL) {
	if (!strncasecmp(agent, "Mozilla", 7) ||
	    !strncasecmp(agent, "Netscape", 8)) {
	    hasTables = TRUE;
	}
    }
    hostname[0] = '\0';
    if ((s = getenv("CONTENT_LENGTH")) == NULL) {
	noargs_html();
	exit(0);
    }
    cl = atoi(s);
    password[0] = url[0] = '\0';
    for (x = 0; cl && (!feof(stdin)); x++) {
	got_data = 1;
	entries[x].val = fmakeword(stdin, '&', &cl);
	plustospace(entries[x].val);
	unescape_url(entries[x].val);
	entries[x].name = makeword(entries[x].val, '=');
	if (!strncmp(entries[x].name, "host", 4))
	    strncpy(hostname, entries[x].val, 256);
	else if (!strncmp(entries[x].name, "operation", 7))
	    strncpy(operation, entries[x].val, 256);
	else if (!strncmp(entries[x].name, "password", 8))
	    strncpy(password, entries[x].val, 256);
	else if (!strncmp(entries[x].name, "url", 3))
	    strncpy(url, entries[x].val, 4096);
	else if (!strncmp(entries[x].name, "port", 4))
	    portnum = atoi(entries[x].val);
	else {
	    printf("<P><B>Unknown CGI parameter: %s</B></P>\n",
		entries[x].name);
	    noargs_html();
	    exit(0);
	}
    }
    if (!got_data) {		/* prints HTML form if no args */
	noargs_html();
	exit(0);
    }
    if (hostname[0] == '\0') {
	printf("<H1>ERROR</H1>\n");
	printf("<P><B>You must provide a hostname!\n</B></P><HR>");
	noargs_html();
	exit(0);
    }
    close(0);

    if (!strncmp(operation, "info", 4) ||
	!strncmp(operation, "Cache Information", 17)) {
	op = INFO;
	sprintf(msg, "GET cache_object://%s/info\r\n", hostname);
    } else if (!strncmp(operation, "cached.conf", 10) ||
	!strncmp(operation, "Cache Configuration File", 24)) {
	op = CACHED;
	sprintf(msg, "GET cache_object://%s/cached.conf\r\n", hostname);
    } else if (!strncmp(operation, "server_list", 11) ||
	!strncmp(operation, "Cache Server List", 17)) {
	op = SERVER;
	sprintf(msg, "GET cache_object://%s/server_list\r\n", hostname);
#ifdef MENU_SHOW_LOG
    } else if (!strncmp(operation, "log", 3) ||
	!strncmp(operation, "Cache Log", 9)) {
	op = LOG;
	sprintf(msg, "GET cache_object://%s/log\r\n", hostname);
#endif
    } else if (!strncmp(operation, "parameter", 9) ||
	!strncmp(operation, "Cache Parameters", 16)) {
	op = PARAM;
	sprintf(msg, "GET cache_object://%s/parameter\r\n", hostname);
#ifdef MENU_RESPONSETIME
    } else if (!strncmp(operation, "responsetime", 11) ||
	!strncmp(operation, "Cache Response Time Histogram", 28)) {
	op = RESPT;
	sprintf(msg, "GET cache_object://%s/responsetime\r\n", hostname);
#endif
    } else if (!strncmp(operation, "stats/general", 13) ||
	!strncmp(operation, "General Statistics", 18)) {
	op = STATS_G;
	sprintf(msg, "GET cache_object://%s/stats/general\r\n", hostname);
    } else if (!strncmp(operation, "stats/vm_objects", 16)) {
	op = STATS_O;
	sprintf(msg, "GET cache_object://%s/stats/vm_objects\r\n", hostname);
    } else if (!strncmp(operation, "stats/objects", 13) ||
	!strncmp(operation, "Objects", 7)) {
	op = STATS_O;
	sprintf(msg, "GET cache_object://%s/stats/objects\r\n", hostname);
    } else if (!strncmp(operation, "stats/utilization", 17) ||
	!strncmp(operation, "Utilization", 11)) {
	op = STATS_U;
	sprintf(msg, "GET cache_object://%s/stats/utilization\r\n", hostname);
    } else if (!strncmp(operation, "shutdown", 8)) {
	op = SHUTDOWN;
	sprintf(msg, "GET cache_object://%s/shutdown@%s\r\n", hostname, password);
    } else if (!strncmp(operation, "refresh", 7)) {
	op = REFRESH;
	sprintf(msg, "GET %s HTTP/1.0\r\nPragma: no-cache\r\nAccept: */*\r\n\r\n", url);
#ifdef REMOVE_OBJECT
    } else if (!strncmp(operation, "remove", 6)) {
	op = REMOVE;
	/* Peter: not sure what to do here - depends what you do at your end! */
	sprintf(msg, "REMOVE %s HTTP/1.0\r\nPragma: no-cache\r\nAccept: */*\r\n\r\n", url);
#endif

    } else {
	printf("Unknown operation: %s\n", operation);
	exit(0);
    }


    time_val = time(NULL);
    time_string = ctime(&time_val);

    printf("<TITLE>Cache Manager: %s:%s:%d</TITLE>\n", operation, hostname, portnum);
    printf("<FORM METHOD=\"POST\" ACTION=\"%s\">\n", script_name);
    printf("<INPUT TYPE=\"submit\" VALUE=\"Refresh\">\n");
    printf("<SELECT NAME=\"operation\">\n");
    printf("<OPTION SELECTED VALUE=\"%s\">Current\n", operation);
    printf("<OPTION VALUE=\"info\">Cache Information\n");
    printf("<OPTION VALUE=\"cached.conf\">Cache Configuration File\n");
    printf("<OPTION VALUE=\"parameter\">Cache Parameters\n");
#ifdef MENU_RESPONSETIME
    printf("<OPTION VALUE=\"responsetime\">Cache Response Time Histogram\n");
#endif
#ifdef MENU_SHOW_LOG
    printf("<OPTION VALUE=\"log\">Cache Log\n");
#endif
    printf("<OPTION VALUE=\"stats/utilization\">Utilization\n");
    printf("<OPTION VALUE=\"stats/objects\">Objects\n");
    printf("<OPTION VALUE=\"stats/vm_objects\">VM_Objects\n");
    printf("<OPTION VALUE=\"server_list\">Cache Server List\n");
    printf("<OPTION VALUE=\"stats/general\">IP Cache Contents\n");
    printf("</SELECT>");
    printf("<INPUT TYPE=\"hidden\" NAME=\"host\" VALUE=\"%s\">\n", hostname);
    printf("<INPUT TYPE=\"hidden\" NAME=\"port\" VALUE=\"%d\">\n", portnum);
    printf("<INPUT TYPE=\"hidden\" NAME=\"password\" VALUE=\"NOT_PERMITTED\">\n");
    printf("</FORM>");
    printf("<H3><I><A HREF=\"%s\">Empty form</A></H3></I>\n", script_name);
    printf("<HR>\n");

    printf("<H3>%s:  %s:%d - dated %s</H3><P>", operation,
	hostname, portnum, time_string);
    printf("<PRE>\n");

    /* Connect to the server */
    if ((conn = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	perror("client: socket");
	exit(1);
    }
    if ((conn = client_comm_connect(conn, hostname, portnum)) < 0) {
	printf("Error: connecting to cache mgr: %s:%d\n", hostname, portnum);
	printf("%s</PRE>\n", xstrerror());
	exit(1);
    }
    bytesWritten = write(conn, msg, strlen(msg));

    if (bytesWritten < 0) {
	printf("Error: write failed\n");
	exit(1);
    } else if (bytesWritten != (strlen(msg))) {
	printf("Error: write short\n");
	exit(1);
    }
    /* Print header stuff for tables */
    switch (op) {
    case INFO:
    case CACHED:
    case SERVER:
    case LOG:
    case STATS_G:
    case STATS_O:
    case SHUTDOWN:
    case REFRESH:
	break;
    case PARAM:
	if (hasTables) {
	    printf("<table border=1><td><B>Parameter</B><td><B>Value</B><td><B>Description</B><tr>\n");
	    in_table = 1;
	} else {
	    printf("<B>\n %20s %10s %s</B><HR>\n", "Parameter", "Value", "Description");
	}
	break;
    case RESPT:
	if (hasTables) {
	    printf("<table border=1><td><B>Time (msec)</B><td><B>Frequency</B><tr>\n");
	    in_table = 1;
	} else {
	    printf("<B>\n %20s %10s </B><HR>\n", "Time (msec)", "Frequency");
	}
	break;
    case STATS_U:
	if (hasTables) {
	    printf("<table border=1><td><B>Protocol</B><td><B>Count</B><td><B>Max KB</B><td><B>Current KB</B><td><B>Min KB</B><td><B>Hit Ratio</B><td><B>Transfer Rate</B><td><B>References</B><td><B>Transfered KB</B><tr>\n");
	    in_table = 1;
	} else {
	    printf("<B>Protocol | Count | Maximum  | Current  | Minimum | Hit   | Transfer | Reference | Transfered |</B>\n");
	    printf("<B>         |       | KB       | KB       | KB      | Ratio | Rate     | Count     | KB         |</B>\n");
	    printf("<B>---------|-------|----------|----------|---------|-------|----------|-----------|------------|</B>\n");
	}
	break;
    default:
	printf("\n\n<P>\nNot currently implemented.\n");
	exit(1);
    }

    p_state = 0;
    cpy_ind = 0;
    n_loops = 0;		/* Keep track of the number of passes through while */
    while ((len = read(conn, buf, sizeof(buf))) > 0) {
	n_loops++;
	/* Simple state machine for parsing a {{ } { } ...} style list */
	for (indx = 0; indx < len; indx++) {
	    if (buf[indx] == '{')
		p_state++;
	    else if (buf[indx] == '}')
		if (p_state == 2) {	/* Have an element of the list */
		    single = FALSE;
		    p_state++;
		    reserve[cpy_ind] = '\0';
		    cpy_ind = 0;
		} else if (p_state == 1 && single)	/* Check for single element list */
		    p_state = 3;
		else		/* End of list */
		    p_state = 0;
	    else if ((indx == 0) && (n_loops == 1)) {
		if (op != REFRESH)
		    printf("ERROR:%s\n", buf);	/* Must be an error message, pass it on */
		else
		    printf("Refreshed URL: %s\n", url);
	    } else
		reserve[cpy_ind++] = buf[indx];


	    /* Have an element of the list, so parse reserve[] accordingly */
	    if (p_state == 3) {
		switch (op) {
		case INFO:
		case CACHED:
		case SERVER:
		case LOG:
		case STATS_G:
		case SHUTDOWN:
		    p_state = 1;
		    printf("%s", reserve);
		    break;
		case REFRESH:
		    /* throw object away */
		    break;
		case PARAM:
		    p_state = 1;
		    memset(s1, '\0', 255);
		    memset(s2, '\0', 255);
		    d1 = 0;
		    sscanf(reserve, "%s %d \"%[^\"]", s1, &d1, s2);
		    if (hasTables)
			printf("<tr><td><B>%s</B><td>%d<td>%s\n", s1, d1, s2 + 2);
		    else
			printf(" %20s %10d %s\n", s1, d1, s2 + 2);
		    break;
		case RESPT:
		    p_state = 1;
		    memset(s1, '\0', 255);
		    d1 = 0;
		    sscanf(reserve, "%s %d", s1, &d1);
		    if (hasTables)
			printf("<tr><td><B>%s</B><td>%d\n", s1, d1);
		    else
			printf(" %20s %10d\n", s1, d1);
		    break;
		case STATS_U:
		    p_state = 1;
		    sscanf(reserve, "%s %d %d %d %d %f %d %d %d",
			s1, &d1, &d2, &d3, &d4, &f1, &d5, &d6, &d7);
		    if (hasTables)
			printf("<tr><td><B>%s</B><td>%d<td>%d<td>%d<td>%d<td>%4.2f<td>%d<td>%d<td>%d",
			    s1, d1, d2, d3, d4, f1, d5, d6, d7);
		    else
			printf("%8s %7d %10d %10d %9d    %4.2f %10d  %10d   %10d<BR>\n",
			    s1, d1, d2, d3, d4, f1, d5, d6, d7);
		    break;
		case STATS_O:
		    if (!in_list) {
			in_list = 1;
			printf("<OL>\n");
		    }
		    parse_object(reserve);
		    p_state = 1;
		    break;
		default:
		    printf("%s\n", "Not currently implemented");
		    exit(1);
		}
	    }
	}
    }

    if (in_list)
	printf("</OL>\n");

    if (in_table)
	printf("</table>\n");

    printf("\n</PRE>\n");
    print_trailer();
    (void) close(conn);
    exit(0);
    /* NOTREACHED */
}

static int client_comm_connect(sock, dest_host, dest_port)
     int sock;			/* Type of communication to use. */
     char *dest_host;		/* Server's host name. */
     int dest_port;		/* Server's port. */
{
    struct hostent *hp;
    static struct sockaddr_in to_addr;

    /* Set up the destination socket address for message to send to. */
    to_addr.sin_family = AF_INET;

    if ((hp = gethostbyname(dest_host)) == 0) {
	return (-1);
    }
    memcpy(&to_addr.sin_addr, hp->h_addr, hp->h_length);
    to_addr.sin_port = htons(dest_port);
    return connect(sock, (struct sockaddr *) &to_addr, sizeof(struct sockaddr_in));
}
