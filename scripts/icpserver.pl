#!/usr/local/bin/perl
#
## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# parse and answer ICP type 1 requests via unicast/multicast UDP
# cf. <URL:http://excalibur.usc.edu/icpdoc/icp.html>
#
# returns ICP response code, e.g. 2 == HIT, 3 == MISS, 4 == ERROR
# by looking at CERN or Netscape style cache directory $cachedir
#
# martin hamilton <m.t.hamilton@lut.ac.uk>
#  Id: icpserver,v 1.11 1995/11/24 16:20:13 martin Exp martin

# usage: icpserver [-c cachedir] [-n] [-p port] [multicast_group]
#
# -c    -> set cache directory
# -n    -> use Netscape cache format (default is CERN)
# -p    -> port number to listen on (default 3130)
# -v    -> verbose - writes activitiy log to stderr
#
# group -> multicast group to listen on

require "getopts.pl";
&Getopts("c:np:v");

@CODES=("xxx", "QUERY", "HIT", "MISS", "ERROR");

$CACHEDIR=$opt_c||"/usr/local/www/cache";
$PORT=$opt_p||3130;
$SERVER=$ARGV[0]||"0.0.0.0";
$SERVERIP= ($SERVER =~ m!\d+.\d+.\d+.\d+!) ?
    pack("C4", split(/\./, $SERVER)) : (gethostbyname($SERVER))[4]; # lazy!

$SOCKADDR = 'S n a4 x8';

socket(S, 2, 2, 17) || socket(S, 2, 1, 17) || die "Couldn't get socket: $!";
$us1 = pack($SOCKADDR, 2, $PORT, $SERVERIP);
$us2 = pack($SOCKADDR, 2, $PORT, pack("C4", 0,0,0,0));
bind(S, $us1) || bind(S, $us2) || die "Couldn't bind socket: $!";
#bind(S, $us2) || die "Couldn't bind socket: $!";

if ($SERVER ne "0.0.0.0") { # i.e. multicast
    $whoami = (`uname -a`)[0];
    $IP_ADD_MEMBERSHIP=5;
    $whoami =~ /SunOS [^\s]+ 5/ && ($IP_MULTICAST_TTL=19);
    $whoami =~ /IRIX [^\s]+ 5/ && ($IP_MULTICAST_TTL=23);
    $whoami =~ /OSF1/ && ($IP_MULTICAST_TTL=12);
    # any more funnies ?

    setsockopt(S, 0, $IP_ADD_MEMBERSHIP, $SERVERIP."\0\0\0\0")
        || die "Couldn't join multicast group $SERVER: $!";
}

# Common header for ICP datagrams ... (size in bytes - total 20)
#   opcode         1              Numeric code indicating type of message
#   version        1              Version of the protocol being used
#   length         2              Total length of packet
#   reqnum         4              Request number assigned by client
#   authenticator  8              Authentication information (future)
#   senderid       4              Identification (host id) of sender

# Type 1 query ...
#   requester      4              Host id of original requester URL
#   url            variable       URL whose status is to be checked

# Type 2 and 3 responses just contain URL, don't return anything else

# Might be fast enough to get away without forking or non-blocking I/O ... ?
while(1) {
    $theiraddr = recv(S, $ICP_request, 1024, 0);
    ($junk, $junk, $sourceaddr, $junk) = unpack($SOCKADDR, $theiraddr);
    @theirip = unpack('C4', $sourceaddr);

    $URL_length = length($ICP_request) - 24;
    $request_template = 'CCnx4x8x4a4a' . $URL_length;
    ($type, $version, $length, $requester, $URL) =
        unpack($request_template, $ICP_request);

    $URL =~ s/\.\.\///g; # be cautious - any others to watch out for ?

    # lookup object in cache
    $hitmisserr = 3;
    if ($type eq 1 && $URL =~ m!^([^:]+):/?/?([^/]+)/(.*)!) {
        $scheme = $1; $hostport = $2; $path = $3;
        if ($path eq "") { $path = "index.html"; }

        if ($opt_n) {
            ($host, $port) = split(/:/, $hostport); # strip off port number
            $port = ":$port" if ($port);
            $match = "";
            foreach (split(/\./, $hostport)) {
                $match = "$_/$match"; # little-endian -> big-endian conversion
            }
            $match = "$CACHEDIR/hosts/$match$scheme$port.urls"; # full path
            if (-f "$match") {
                #### optimize! ####
                open(IN, "$match") && do {
                    while(<IN>) { /^$URL / && ($hitmisserr = 2, last); }
                    close(IN);
                    }
            }
        } else {
            $hitmisserr = 2 if -f "$CACHEDIR/$scheme/$hostport/$path";
        }
    }

    print "$type $hitmisserr ", join(".", @theirip), " $URL\n" if $opt_v;

    $response_template = 'CCnx4x8x4A' . length($URL);
    $ICP_response =
        pack($response_template, $hitmisserr, 2, 20 + length($URL), $URL);
    send(S, $ICP_response, 0, $theiraddr) || die "Couldn't send request: $!";
}

