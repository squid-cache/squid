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
 * util.c --
 *
 * Program utility functions.
 *
 */

#include "main.h"
#include "util.h"

/* debug() -
 *
 * Print formatted message of func() to stderr if MODE_DEBUG is set.
 *
 */
void debug(char *func, const char *msg,...) {
  char prog[MAXLEN], dbuf[MAXLEN], cbuf[MAXLEN];
  size_t sz, x;
  va_list ap;
  if (!(conf.mode & MODE_DEBUG))
    return;

  if (conf.program[0] == '\0')
    strcpy(prog, DEFAULT_PROGRAM_NAME);
  else
    strncpy(prog, conf.program, sizeof(prog));
  if ((func == NULL) || (msg == NULL) || (strlen(prog) > 256)) {
    /* FAIL */
    snprintf(dbuf, sizeof(dbuf), "%s: debug() EPIC FAILURE.\n", prog);
    fputs(dbuf, stderr);
    return;
  }
  sz = sizeof(dbuf);
  strncpy(cbuf, prog, sizeof(cbuf));
  strcat(cbuf, ": [DB] ");
  strncat(cbuf, func, sizeof(cbuf));
  strcat(cbuf, "() - ");
  va_start(ap, msg);
  x = vsnprintf(dbuf, sz, msg, ap);
  va_end(ap);
  if (x > 0) {
    strncat(cbuf, dbuf, x);
    fputs(cbuf, stderr);
    memset(dbuf, '\0', strlen(dbuf));
  }
  else {
    /* FAIL */
    snprintf(dbuf, sz, "%s: debug(%s) FAILURE: %zd\n", prog, dbuf, x);
    fputs(dbuf, stderr);
  }
}

/* debugx() -
 *
 * Print formatted message to stderr if MODE_DEBUG is set, without preformatting.
 *
 */
void debugx(const char *msg,...) {
  char prog[MAXLEN], dbuf[MAXLEN];
  size_t sz, x;
  va_list ap;
  if (!(conf.mode & MODE_DEBUG))
    return;

  if (conf.program[0] == '\0')
    strcpy(prog, DEFAULT_PROGRAM_NAME);
  else
    strncpy(prog, conf.program, sizeof(prog));
  if ((msg == NULL) || (strlen(prog) > 256)) {
    /* FAIL */
    snprintf(dbuf, sizeof(dbuf), "%s: debugx() EPIC FAILURE.\n", prog);
    fputs(dbuf, stderr);
    return;
  }
  sz = sizeof(dbuf);
  va_start(ap, msg);
  x = vsnprintf(dbuf, sz, msg, ap);
  va_end(ap);
  if (x > 0) {
    fputs(dbuf, stderr);
    memset(dbuf, '\0', strlen(dbuf));
  }
  else {
    /* FAIL */
    snprintf(dbuf, sz, "%s: debug(%s) FAILURE: %zd\n", prog, dbuf, x);
    fputs(dbuf, stderr);
  }
}

/* printfx() -
 *
 * Print formatted message to stderr AND stdout, without preformatting.
 *
 */
void printfx(const char *msg,...) {
  char prog[MAXLEN], dbuf[MAXLEN];
  size_t sz, x;
  va_list ap;

  if (conf.program[0] == '\0')
    strcpy(prog, DEFAULT_PROGRAM_NAME);
  else
    strncpy(prog, conf.program, sizeof(prog));

  if ((msg == NULL) || (strlen(prog) > 256)) {
    /* FAIL */
    snprintf(dbuf, sizeof(dbuf), "%s: printfx() EPIC FAILURE.\n", prog);
    fputs(dbuf, stderr);
    return;
  }
  sz = sizeof(dbuf);
  va_start(ap, msg);
  x = vsnprintf(dbuf, sz, msg, ap);
  va_end(ap);
  if (x > 0) {
    dbuf[x] = '\0';
    x++;
    fputs(dbuf, stdout);
//    debug("printfx", "DATA: %s", dbuf);
    memset(dbuf, '\0', strlen(dbuf));
  }
  else {
    /* FAIL */
    snprintf(dbuf, sz, "%s: printfx(%s) FAILURE: %zd\n", prog, dbuf, x);
    fputs(dbuf, stderr);
  }

  /* stdout needs to be flushed for it to work with Squid */
  fflush(stdout);
}

/*
 * SplitString() - <string> <string-size> <char> <split-object> <obj-size>
 *
 * Breaks down string, splitting out element <char> into <split-object>, and removing it from string.
 * Will not exceed size tolerances.
 *
 * NOTE:  We could have used a strchr() pointer, but then '\0' would break it.
 *	 (Which DOES commonly exist in IP Addressing)
 *
 */
int SplitString(char *input, size_t insz, char c, char *obj, size_t objsz) {
  size_t i, j;
  int swi;
  char buf[MAXLEN];
  if ((input == NULL) || (obj == NULL) || (insz <= 0) || (objsz <= 0)) return -1;

  /* Copy input, and clear */
  memset(buf, '\0', sizeof(buf));
  memcpy(buf, input, insz);
  memset(input, '\0', insz);
  memset(obj, '\0', objsz);
  j = 0;                /* obj position */
  swi = 0;              /* found data yet ? */

  /* Scan for data, and copy */
  for (i = 0; i < insz; i++) {
    /* Scan input for first non-space character */
    if (buf[i] != c) {
      if (swi == 0) {
        swi++;          /* Data found, begin copying. */
        obj[j] = buf[i];
        j++;
      }
      else if (swi == 1) {
        obj[j] = buf[i];
        j++;
      }
      else
        break;          /* end of data */
    }
    else {
      /* Found a character c */
      if (swi == 1)
        swi++;
      else if (swi == 2)
        break;          /* end of data */
    }
  }
  obj[j] = '\0';        /* Terminate, i = point of split */

  j = 0;                /* Position of input */
  for (; i < insz; i++) {
/*	Commented out for BINARY MODE, ie. May have '\0' as legit data *
    if (buf[i] == '\0')
      break;
*/
    input[j] = buf[i];
    j++;
  }
  /* Should be correctly split back into input, and
   * split object in obj.  memset() at next call will
   * clear array data.
   */
  i = strlen(input);
  j = strlen(obj);

  return j;
}
