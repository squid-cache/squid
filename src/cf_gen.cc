/*
 * $Id: cf_gen.cc,v 1.1 1997/06/26 22:29:30 wessels Exp $
 *
 * DEBUG: section 1     Startup and Main Loop
 * AUTHOR: Max Okumoto
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

/*****************************************************************************
 * Abstract:	This program parses the input file and generates code and
 *		files used to configure the variables in squid.
 *
 *		The output files are as follows:
 *		cf_parser.c - this file contains, default_all() which
 *			  initializes
 *			  variables with the default values, parse_line() that
 *			  parses line from squid.conf, dump_all that dumps the
 *			  current the values of the variables.
 *		squid.conf - default configuration file given to the server
 *			 administrator.
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>

#define MAX_LINE	1024	/* longest configuration line */
#define _PATH_PARSER		"cf_parser.c"
#define _PATH_SQUID_CONF	"squid.conf"

enum State {
    sSTART,
    s1,
    sDOC,
    sEXIT
};

typedef struct Line {
    char *data;
    struct Line *next;
} Line;

typedef struct Entry {
    char *name;
    char *type;
    char *loc;
    char *default_value;
    char *comment;
    Line *doc;
    struct Entry *next;
} Entry;


static const char WS[] = " \t";
static void gen_default(Entry *, FILE *);
static void gen_parse(Entry *, FILE *);
static void gen_dump(Entry *, FILE *);
static void gen_conf(Entry *, FILE *);

int
main(int argc, char *argv[])
{
    FILE *fp;
    char *input_filename = argv[1];
    char *output_filename = _PATH_PARSER;
    char *conf_filename = _PATH_SQUID_CONF;
    int linenum = 0;
    Entry *entries = NULL;
    Entry *curr = NULL;
    enum State state;

    /*-------------------------------------------------------------------*
     * Parse input file
     *-------------------------------------------------------------------*/

    /* Open input file */
    if ((fp = fopen(input_filename, "r")) == NULL) {
	perror(input_filename);
	exit(1);
    }
    state = sSTART;
    while (feof(fp) == 0 && state != sEXIT) {
	char buff[MAX_LINE];

	fgets(buff, MAX_LINE, fp);
	linenum++;
	*(strchr(buff, '\n')) = '\0';
	switch (state) {
	case sSTART:
	    if ((strlen(buff) == 0) || (!strncmp(buff, "#", 1))) {
		/* ignore empty and comment lines */

	    } else if (!strncmp(buff, "NAME:", 5)) {
		char *name;

		if ((name = strtok(buff + 5, WS)) == NULL) {
		    printf("Error in input file\n");
		    exit(1);
		}
		curr = malloc(sizeof(Entry));
		curr->name = strdup(name);
		curr->loc = NULL;
		curr->doc = NULL;
		state = s1;

	    } else if (!strcmp(buff, "EOF")) {
		state = sEXIT;

	    } else {
		printf("Error on line %d\n", linenum);
		exit(1);
	    }
	    break;

	case s1:
	    if ((strlen(buff) == 0) || (!strncmp(buff, "#", 1))) {
		/* ignore empty and comment lines */

	    } else if (!strncmp(buff, "COMMENT:", 8)) {
		char *ptr = buff+8;
		while(isspace(*ptr))
			ptr++;
		curr->comment = strdup(ptr);
	    } else if (!strncmp(buff, "DEFAULT:", 8)) {
		char *ptr;

		if ((ptr = strtok(buff + 8, WS)) == NULL) {
		    printf("Error on line %d\n", linenum);
		    exit(1);
		}
		curr->default_value = strdup(ptr);

	    } else if (!strncmp(buff, "LOC:", 4)) {
		char *ptr;

		if ((ptr = strtok(buff + 4, WS)) == NULL) {
		    printf("Error on line %d\n", linenum);
		    exit(1);
		}
		curr->loc = strdup(ptr);

	    } else if (!strncmp(buff, "TYPE:", 5)) {
		char *ptr;

		if ((ptr = strtok(buff + 5, WS)) == NULL) {
		    printf("Error on line %d\n", linenum);
		    exit(1);
		}
		curr->type = strdup(ptr);

	    } else if (!strcmp(buff, "DOC_START")) {
		state = sDOC;

	    } else if (!strcmp(buff, "DOC_NONE")) {
		/* add to list of entries */
		curr->next = entries;
		entries = curr;

		state = sSTART;

	    } else {
		printf("Error on line %d\n", linenum);
		exit(1);
	    }
	    break;

	case sDOC:
	    if (!strcmp(buff, "DOC_END")) {
		Line *head = NULL;
		Line *line = curr->doc;

		/* reverse order of doc lines */
		while (line != NULL) {
		    Line *tmp;
		    tmp = line->next;
		    line->next = head;
		    head = line;
		    line = tmp;
		}
		curr->doc = head;

		/* add to list of entries */
		curr->next = entries;
		entries = curr;

		state = sSTART;
	    } else {
		Line *line = malloc(sizeof(Line));

		line->data = strdup(buff);
		line->next = curr->doc;
		curr->doc = line;
	    }
	    break;

	case sEXIT:
	    assert(0);		/* should never get here */
	    break;
	}
    }
    if (state != sEXIT) {
	printf("Error unexpected EOF\n");
	exit(1);
    } else {
	/* reverse order of entries */
	Entry *head = NULL;

	while (entries != NULL) {
	    Entry *tmp;

	    tmp = entries->next;
	    entries->next = head;
	    head = entries;
	    entries = tmp;
	}
	entries = head;
    }
    fclose(fp);

    /*-------------------------------------------------------------------*
     * Generate default_all()
     * Generate parse_line()
     * Generate dump_all()
     * Generate example squid.conf file
     *-------------------------------------------------------------------*/

    /* Open output x.c file */
    if ((fp = fopen(output_filename, "w")) == NULL) {
	perror(output_filename);
	exit(1);
    }
    fprintf(fp,
	"/*\n"
	" * Generated automatically from %s by %s\n"
	" *\n"
	" * Abstract: This file contains routines used to configure the\n"
	" *           variables in the squid server.\n"
	" */\n"
	"\n",
	input_filename, argv[0]
	);
    gen_default(entries, fp);
    gen_parse(entries, fp);
    gen_dump(entries, fp);
    fclose(fp);

    /* Open output x.conf file */
    if ((fp = fopen(conf_filename, "w")) == NULL) {
	perror(conf_filename);
	exit(1);
    }
    gen_conf(entries, fp);
    fclose(fp);

    return (0);
}

static void
gen_default(Entry * head, FILE * fp)
{
    Entry *entry;
    fprintf(fp,
	"void\n"
	"default_all(void)\n"
	"{\n"
	);
    for (entry = head; entry != NULL; entry = entry->next) {
	assert(entry->name);
	if (entry->loc == NULL) {
	    fprintf(stderr, "NO LOCATION FOR %s\n", entry->name);
	    continue;
	}
	if (entry->default_value == NULL) {
	    fprintf(stderr, "NO DEFAULT FOR %s\n", entry->name);
	    continue;
	}
#ifdef OLD
	if (!strcmp(entry->type, "string")) {
	    fprintf(fp, "\t%s = xstrdup(\"%s\");\n",
		entry->loc, entry->default_value);
	} else if (!strcmp(entry->type, "string_optional")) {
	    fprintf(fp, "\t%s = xstrdup(\"%s\");\n",
		entry->loc, entry->default_value);
	} else if (!strcmp(entry->type, "pathname_check")) {
	    fprintf(fp, "\t%s = xstrdup(\"%s\");\n",
		entry->loc, entry->default_value);
	} else {
	    fprintf(fp, "\t%s = %s;\n",
		entry->loc, entry->default_value);
	}
#else
	fprintf(fp, "\tparse_line(\"%s %s\");\n",
		entry->name,
		entry->default_value);
#endif
    }
    fprintf(fp, "}\n\n");
}

static void
gen_parse(Entry * head, FILE * fp)
{
    Entry *entry;

    fprintf(fp,
	"int\n"
	"parse_line(char *buff)\n"
	"{\n"
	"\tint\tresult = 1;\n"
	"\tchar\t*token;\n"
	"\n"
	"\tif ((token = strtok(buff, w_space)) == NULL) {\n"
	"\t\t/* ignore empty lines */\n"
	);

    for (entry = head; entry != NULL; entry = entry->next) {
	fprintf(fp,
	    "\t} else if (!strcmp(token, \"%s\")) {\n",
	    entry->name
	    );
	if (entry->loc == NULL) {
	    fprintf(fp,
		"\t\tparse_%s();\n",
		entry->type
		);
	} else {
	    fprintf(fp,
		"\t\tparse_%s(&%s);\n",
		entry->type, entry->loc
		);
	}
    }

    fprintf(fp,
	"\t} else {\n"
	"\t\tresult = 0; /* failure */\n"
	"\t}\n"
	"\treturn(result);\n"
	"}\n\n"
	);
}

static void
gen_dump(Entry * head, FILE * fp)
{
    Entry *entry;

    fprintf(fp,
	"void\n"
	"dump_all(void)\n"
	"{\n"
	);

    for (entry = head; entry != NULL; entry = entry->next) {
	if (entry->loc == NULL) {
	    fprintf(fp, "\tprintf(\"%s = \");\n", entry->type);
	    fprintf(fp, "\tdump_%s();\n", entry->type);
	} else {
	    fprintf(fp, "\tprintf(\"%s = \");\n", entry->loc);
	    fprintf(fp, "\tdump_%s(%s);\n", entry->type, entry->loc);
	}
	fprintf(fp, "\tprintf(\"\\n\");\n");
	fprintf(fp, "\n");
    }
    fprintf(fp, "}\n\n");
}

static void
gen_conf(Entry * head, FILE * fp)
{
    Entry *entry;

    for (entry = head; entry != NULL; entry = entry->next) {
	Line *line;

	fprintf(fp, "#  TAG: %s", entry->name);
	if (entry->comment)
		fprintf(fp, "\t%s", entry->comment);
	fprintf(fp, "\n");
	for (line = entry->doc; line != NULL; line = line->next) {
	    fprintf(fp, "#%s\n", line->data);
	}
	if (entry->doc != NULL) {
	    fprintf(fp, "\n");
	}
    }
}
