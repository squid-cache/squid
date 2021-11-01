#!/usr/local/bin/perl
#
## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# cache-compare.pl
#
# Duane Wessels, Dec 1995
#
# A simple perl script to compare how long it takes to fetch an object
# from a number of different caches.
#
# stdin is a list of URLs.  Set the @getfrom array to a list of caches
# to fetch each URL from.  Include 'SOURCE' in @getfrom to fetch from
# the source host also.  For each URL, print the byte count, elapsed
# time and average data rate.  At the end print out some averages.
#
# NOTE: uses the Perl function syscall() to implement gettimeofday(2).
# Assumes that gettimeofday is syscall #116 on the system
# (see /usr/include/sys/syscall.h).
#
# BUGS:
# Should probably cache the gethostbyname() calls.

@getfrom = ('SOURCE', 'localhost:3128', 'bo:3128');

require 'sys/socket.ph';
$gettimeofday = 1128;        # cheating, should use require syscall.ph

while (<>) {
    chop ($url = $_);
    print "$url:\n";

    foreach $k (@getfrom) {
        printf "%30.30s:\t", $k;
        if ($k eq 'SOURCE') {
            ($b_sec,$b_usec) = &gettimeofday;
            $n = &get_from_source($url);
            ($e_sec,$e_usec) = &gettimeofday;
        } else {
            ($host,$port) = split (':', $k);
            ($b_sec,$b_usec) = &gettimeofday;
            $n = &get_from_cache($host,$port,$url);
            ($e_sec,$e_usec) = &gettimeofday;
        }
        next unless ($n > 0);
        $d = ($e_sec - $b_sec) * 1000000 + ($e_usec - $b_usec);
        $d /= 1000000;
        $r = $n / $d;
        printf "%8.1f b/s (%7d bytes, %7.3f sec)\n",
            $r, $n, $d;
        $bps_sum{$k} += $r;
        $bps_n{$k}++;
        $bytes_sum{$k} += $n;
        $sec_sum{$k} += $d;
    }
}

print "AVERAGE b/s rates:\n";
foreach $k (@getfrom) {
    printf "%30.30s:\t%8.1f b/s   (Alt: %8.1f b/s)\n",
        $k,
        $bps_sum{$k} / $bps_n{$k},
        $bytes_sum{$k} / $sec_sum{$k};
}

exit 0;

sub get_from_source {
    local($url) = @_;
    local($bytes) = 0;
    unless ($url =~ m!([a-z]+)://([^/]+)(.*)$!) {
        printf "get_from_source: bad URL\n";
        return 0;
    }
    $proto = $1;
    $host = $2;
    $url_path = $3;
    unless ($proto eq 'http') {
        printf "get_from_source: I only do HTTP\n";
        return 0;
    }
    $port = 80;
    if ($host =~ /([^:]+):(\d+)/) {
        $host = $1;
        $port = $2;
    }
    return 0 unless ($SOCK = &client_socket($host,$port));
    print $SOCK "GET $url_path HTTP/1.0\r\nAccept */*\r\n\r\n";
    $bytes += $n while (($n = read(SOCK,$_,4096)) > 0);
    close $SOCK;
    return $bytes;
}

sub get_from_cache {
    local($host,$port,$url) = @_;
    local($bytes) = 0;
    return 0 unless ($SOCK = &client_socket($host,$port));
    print $SOCK "GET $url HTTP/1.0\r\nAccept */*\r\n\r\n";
    $bytes += $n while (($n = read(SOCK,$_,4096)) > 0);
    close $SOCK;
    return $bytes;
}

sub client_socket {
    local ($host, $port) = @_;
    local ($sockaddr) = 'S n a4 x8';
    local ($name, $aliases, $proto) = getprotobyname('tcp');
    local ($connected) = 0;

    # Lookup addresses for remote hostname
    #
    local($w,$x,$y,$z,@thataddrs) = gethostbyname($host);
    unless (@thataddrs) {
        printf "Unknown Host: $host\n";
        return ();
    }

    # bind local socket to INADDR_ANY
    #
    local ($thissock) = pack($sockaddr, &AF_INET, 0, "\0\0\0\0");
    unless (socket (SOCK, &AF_INET, &SOCK_STREAM, $proto)) {
        printf  "socket: $!\n";
        return ();
    }
    unless (bind (SOCK, $thissock)) {
        printf "bind: $!\n";
        return ();
    }

    # Try all addresses
    #
    foreach $thataddr (@thataddrs) {
        local ($that) = pack($sockaddr, &AF_INET, $port, $thataddr);
        if (connect (SOCK, $that)) {
            $connected = 1;
            last;
        }
    }
    unless ($connected) {
        printf "$host:$port: $!\n";
        return ();
    }

    # Set socket to flush-after-write and return it
    #
    select (SOCK); $| = 1;
    select (STDOUT);
    return (SOCK);
}

sub gettimeofday {
    $tvp="\0\0\0\0\0\0\0\0";
    syscall($gettimeofday, $tvp, $tz);
    return unpack('ll', $tvp);
}

