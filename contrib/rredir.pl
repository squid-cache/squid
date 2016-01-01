#!/usr/bin/perl -T -w
#
## Copyright (C) 1996-2016 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

#
# rredir.pl
#
# Author: Peter Eisenhauer <pe@pipetronix.de>
# First Version: 26. May 1997
#
# Description: Direct all request to files who are in a local dir to
# this directory
# 
use File::Basename;
use URI::URL;

# customization part

# Local Domainame from which no redirects should be done
$localdomain = 'pipetronix.de';
# Local domainame qouted for regexps
$regexlocaldomain = quotemeta($localdomain);
# Path under which the scripts accesses the local dir (must end with /)
$access_local_dir='/opt/utils/etc/httpd/htdocs/local-rredir/';
# Information for the redirected URL (redirect_path must end with /)
$redirect_scheme = 'http';
$redirect_host = 'ws-server.pipetronix.de';
$redirect_path = 'local-rredir/';

# end of customization part

# flush after every print
$| = 1;

# Process lines of the form 'URL ip-address/fqdn ident method'
# See release notes of Squid 1.1 for details
while ( <> ) {
    ($url, $addr, $fqdn, $ident, $method) = m:(\S*) (\S*)/(\S*) (\S*) (\S*):;

    $url = url $url;
    $host = lc($url->host);

    # do not process hosts in local domain or unqualified hostnames
    if ( $host =~ /$regexlocaldomain/ || $host !~ /\./ ) {
	next;
    }

    # just the file, without any host or path parts
    # and just in case: lowercase the file name, so you should make sure
    # all the files in the local dir are only lowercase !!
    $file = lc(basename($url->path));

    # look if in local dir, if yes redirect
    if ( $file && -r $access_local_dir . $file
	&& $file ne '.' && $file ne '..' ) {
	$url->scheme($redirect_scheme);
	$url->host($redirect_host);
	$url->path($redirect_path . $file);
    }

} continue {
    print "$url $addr/$fqdn $ident $method\n"
}
