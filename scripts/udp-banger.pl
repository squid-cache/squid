#!/usr/local/bin/perl

# udp-banger.pl 
#
# Duane Wessels, Dec 1995
#
# Usage: udp-banger.pl [host [port]] < url-list
#
# Sends a continuous stream of ICP queries to a cache.  Stdin is a list of
# URLs to request.  Run N of these at the same time to simulate a heavy
# neighbor cache load.

use Fcntl;
use Getopt::Std;
use IO::Socket;

$|=1;

getopts('qlnr');

$host=(shift || 'localhost') ;
$port=(shift || '3130') ;

# just copy this from src/proto.c
@CODES=(
    "ICP_INVALID",
    "ICP_QUERY",
    "UDP_HIT",
    "UDP_MISS",
    "ICP_ERR",
    "ICP_SEND",
    "ICP_SENDA",
    "ICP_DATABEG",
    "ICP_DATA",
    "ICP_DATAEND",
    "ICP_SECHO",
    "ICP_DECHO",
    "ICP_OP_UNUSED0",
    "ICP_OP_UNUSED1",
    "ICP_OP_UNUSED2",
    "ICP_OP_UNUSED3",
    "ICP_OP_UNUSED4",
    "ICP_OP_UNUSED5",
    "ICP_OP_UNUSED6",
    "ICP_OP_UNUSED7",
    "ICP_OP_UNUSED8",
    "UDP_RELOADING",
    "UDP_DENIED",
    "UDP_HIT_OBJ",
    "ICP_END"
);

$sock = IO::Socket::INET->new(PeerAddr => "$host:$port", Proto => 'udp');
die "socket: $!\n" unless defined($sock);

chop($me=`uname -a|cut -f2 -d' '`);
$myip=(gethostbyname($me))[4];

$flags = fcntl ($sock, &F_GETFL, 0);
$flags |= &O_NONBLOCK;
die "fcntl O_NONBLOCK: $!\n" unless
	fcntl ($sock, &F_SETFL, $flags);

$flags = 0;
$flags |= 0x80000000;
$flags |= 0x40000000 if ($opt_n);
$flags = ~0;
$rn = 0;

$start = time;
while (<>) {
	chop;

	if ($opt_l) { # it's a Squid log file
		@stuff = split(/\s+/, $_);
		$_ = $stuff[6];
	}

        $len = length($_) + 1;
        $request_template = sprintf 'CCnNNa4a4x4a%d', $len;
        $request = pack($request_template,
                1,              # C opcode
                2,              # C version
                24 + $len,      # n length
                ++$rn,          # N reqnum
                $flags,         # N flags
                '',             # a4 pad
                $myip,          # a4 shostid
                $_);            # a%d payload
	die "send: $!\n" unless
		send($sock, $request, 0);
	$nsent++;
        $rin = '';
        vec($rin,fileno($sock),1) = 1;
        ($nfound,$timeleft) = select($rout=$rin, undef, undef, 2.0);
	next if ($nfound == 0);
	while (1) {
        	last unless ($theiraddr = recv($sock, $reply, 1024, 0));
        	next if $opt_q; # quietly carry on
		$nrecv++;
		if ($opt_r) {
			# only print send/receive rates
			if (($nsent & 0xFF) == 0) {
	    			$dt = time - $start;
	    			printf "SENT %d %f/sec; RECV %d %f/sec\n",
					$nsent,
					$nsent / $dt,
					$nrecv,
					$nrecv / $dt;
			}
		} else {
			# print the whole reply
  			($junk, $junk, $sourceaddr, $junk) = unpack($sockaddr, $theiraddr);
  			@theirip = unpack('C4', $sourceaddr);
        		($type,$ver,$len,$flag,$p1,$p2,$payload) = unpack('CCnx4Nnnx4A', $reply);
        		print join('.', @theirip) . ' ' . $CODES[$type] . " $_";
			print " hop=$p1" if ($opt_n);
			print " rtt=$p2" if ($opt_n);
			print "\n";
		}
        }
}

