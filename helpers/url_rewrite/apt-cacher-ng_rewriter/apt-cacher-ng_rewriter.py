#!/usr/bin/python

#    A squid rewrite helper to rewrite URLs of requests to Ubuntu package
#    repositories to go to apt-cacher-ng.
#    Copyright (C) 2016 Karl-Philipp Richter (krichter@posteo.de)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import re
import logging
import plac

logger = logging.getLogger(__name__)
logger_formatter = logging.Formatter('%(asctime)s:%(message)s')

# result code string according to http://wiki.squid-cache.org/Features/Redirectors
RESULT_ERR = "ERR" # indicates "Success. No change for this URL."
RESULT_OK = "OK" # indicates "Success. A new URL is presented"
RESULT_BH = "BH" # indicates "Failure. The helper encountered a problem."

@plac.annotations(log_file_path=("Path to a file used for logging. Make sure the file exists and is writable by the user invoking this squid helper", "option"),
    debug=("Enables debug messages in logging", "flag"),
    apt_cacher_ng_url=("The URL of the apt-cacher-ng instance to use", "option"))
def apt_cacher_ng_rewriter(log_file_path="/usr/local/squid/var/log/apt-cacher-ng_rewriter.log", debug=False, apt_cacher_ng_url="http://localhost:3142"):
    if log_file_path == None:
        logger_handler = logging.StreamHandler(stream=sys.stderr) # must not log to stdout because it's used for communication with squid
    else:
        logger_handler = logging.FileHandler(log_file_path)
    if debug is True:
        logger_handler.setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    else:
        logger_handler.setLevel(logging.INFO)
        logger.setLevel(logging.INFO)
    logger_handler.setFormatter(logger_formatter)
    logger.addHandler(logger_handler)

    def __rewrite_url__(url):
        ret_value = "%s/%s" % (apt_cacher_ng_url.strip("/"), url.strip("http://"),)
        return ret_value

    try:
        logger.debug("reading new line")
        line = sys.stdin.readline() # EOF is indicated by returning ""
        logger.debug("new line '%s' read" % (line,))
        while line != "":
            # channel-ID and kv-pairs seem to be optional
            line_split = line.split(" ")
            # if a channel-ID is passed it is an integer<ref>http://www.squid-cache.org/Doc/config/url_rewrite_program/</ref>
            try:
                id = str(int(line_split[0]))
                url = line_split[1]
            except ValueError:
                id = ""
                url = line_split[0]
            logger.debug("id=%s; url=%s" % (id, url))
            if url.endswith(".gpg") or url.endswith("ReleaseAnnouncement"):
                logger.debug("skipping URL ending with '.gpg' or 'ReleaseAnnouncement'")
                result = RESULT_ERR
            elif re.match("^http://((.*)archive.ubuntu.com/ubuntu/(dists|pool)/.*)$", url) != None:
                url = __rewrite_url__(url)
                logger.info("rewriting to '%s'" % (url,))
                result = RESULT_OK
            elif re.match("^http://(security.ubuntu.com/ubuntu/(dists|pool)/.*)$", url) != None:
                url = __rewrite_url__(url)
                logger.info("rewriting to '%s'" % (url,))
                result = RESULT_OK
            else:
                logger.debug("skipping line '%s'" % (line,))
                result = RESULT_ERR
            def __kv_pairs__():
                if result == RESULT_ERR:
                    return url #""
                return 'rewrite-url="%s"' % (url,)
            if result == RESULT_ERR:
                reply = ""
            else:
                reply = ("%s %s %s" % (id, result, __kv_pairs__())).strip() # file.writelines doesn't add newline characters
            logger.debug("replying '%s'" % (reply,))
            sys.stdout.write(reply+"\n") # unclear whether URL is specified as forth attribute like in http://wiki.squid-cache.org/Features/Redirectors or in rewrite-url= key as in http://www.squid-cache.org/Doc/config/url_rewrite_program/
            sys.stdout.flush()
            logger.debug("reading new line")
            line = sys.stdin.readline()
        logger.debug("rewrite helper 'apt-cacher-ng_rewriter.py' finished")
    except Exception as ex:
        logger.error("Exception '%s' occured, replying 'BH' result to squid" % (str(ex),))
        sys.stdout.write("%s %s\n" % (id, RESULT_BH)) # file.writelines doesn't add newline characters
            # if id isn't assigned the program will crash which is fine because squid must have sent nonsense
        sys.stdout.flush()

if __name__ == "__main__":
    plac.call(apt_cacher_ng_rewriter)
