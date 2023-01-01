#!/usr/local/bin/perl
#
## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# tcp-banger.pl
#
# Duane Wessels, Dec 1995
#
# Usage: tcp-banger.pl [host [port]] < url-list
#
# Sends a continuous stream of HTTP proxy requests to a cache.  Stdin is a
# list of URLs to request.  Run N of these at the same time to simulate a
# heavy client load.
#
# NOTE: does not simulate "real-world" events such as aborted requests
# (connections) and other network problems.

$|=1;

$host=(shift || 'localhost') ;
$port=(shift || '3128') ;

require 'sys/socket.ph';

$sockaddr = 'S n a4 x8';
($name, $aliases, $proto) = getprotobyname("tcp");
($fqdn, $aliases, $type, $len, $thataddr) = gethostbyname($host);
$thissock = pack($sockaddr, &AF_INET, 0, "\0\0\0\0");
$that = pack($sockaddr, &AF_INET, $port, $thataddr);

while (<>) {
    chop ($url = $_);

    die "socket: $!\n" unless
        socket (SOCK, &AF_INET, &SOCK_STREAM, $proto);
    die "bind: $!\n" unless
        bind (SOCK, $thissock);
    die "$host:$port: $!\n" unless
        connect (SOCK, $that);
    select (SOCK); $| = 1;
    select (STDOUT);

    print SOCK "GET $url HTTP/1.0\r\nAccept: */*\r\n\r\n";
    $_ = <SOCK>;
    ($ver,$code,$junk) = split;
    printf "%s %s\n", $code ? $code : 'FAIL', $url;
    1 while (read(SOCK,$_,4096));
    close SOCK;
}
