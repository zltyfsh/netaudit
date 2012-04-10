#
# Copyright (c) 2012, Per Carlson
#
# This program is free software; you can redistribute it and/or 
# modify it under the same terms as Perl 5.14. For more details, 
# see the full text of the licenses in the directory LICENSES.
#

package Netaudit::Plugin::JunOS;

use feature 'switch';
use strict;
use warnings;

use Regexp::Common;
use Regexp::IPv6 qw{ $IPv6_re };

use Netaudit::Constants;

### RegExps ###

my $HOSTNAME = qr{ [-\p{Alnum}\.]+ }xms;
my $PROMPT    = '/> $/';
my @HANDLES   = (qr{ Juniper \s Networks }xms);
my $INTERFACE = qr{ (?:xe|ge|so) - \d+ / \d+ / \d+ (?:\. \d+)* }xms;

##### do this plugin handle the device? #####
sub handles {
    my ( $self, $sysdescr ) = @_;
    return scalar grep { $sysdescr =~ m/$_/ } @HANDLES;
}

##### Return the prompt to use #####
sub prompt { return $PROMPT }

##### Set up environment #####
sub init {
    my ( $self, $conn ) = @_;
    # disable "--more--" prompt
    $conn->cmd("set cli screen-length 0");
}

##### Routing summary #####
sub route_summary {
    my ( $self, $conn, $db ) = @_;
    return $AUDIT_FAIL unless $conn && $db;

# Example output:
# inet.0: 93144 destinations, 185828 routes (93136 active, 0 holddown, 14 hidden)
#            Direct:     31 routes,     30 active
#             Local:     35 routes,     34 active
#               BGP: 185295 routes,  92605 active
#            Static:     39 routes,     39 active
#             IS-IS:    428 routes,    428 active
#
# inet6.0: 8159 destinations, 15944 routes (8159 active, 0 holddown, 0 hidden)
#            Direct:      8 routes,      6 active
#             Local:      6 routes,      6 active
#               BGP:  15586 routes,   7803 active
#            Static:      3 routes,      3 active
#             IS-IS:    341 routes,    341 active

    my $in_inet0 = 0;
    my $in_inet6 = 0;
    my %h;

    foreach my $line ( $conn->cmd("show route summary") ) {
        $line =~ s!/P{IsPrint}!!g;    # remove all non-printables
        chomp($line);

        given ($line) {
            when (/^inet\.0:/)  { $in_inet0 = 1; }
            when (/^inet6\.0:/) { $in_inet6 = 1; }

            when (/^\s*$/) {
                if ($in_inet0) {
                    $h{afi} = "ipv4";
                    $db->insert( 'route_summary', \%h );
                    $in_inet0 = 0;
                }
                elsif ($in_inet6) {
                    $h{afi} = "ipv6";
                    $db->insert( 'route_summary', \%h );
                    $in_inet6 = 0;
                }
                %h = ();
            }

            when (/^\s+ Direct: .*? (\d+) \s active/xms) { $h{connected} = $1; }
            when (/^\s+ Local:  .*? (\d+) \s active/xms) { $h{local}     = $1; }
            when (/^\s+ BGP:    .*? (\d+) \s active/xms) { $h{bgp}       = $1; }
            when (/^\s+ Static: .*? (\d+) \s active/xms) { $h{static}    = $1; }
            when (/^\s+ IS-IS:  .*? (\d+) \s active/xms) { $h{isis}      = $1; }
        }
    }

    # flush hash
    if ( $in_inet0 && %h ) {
        $h{afi} = "ipv4";
        $db->insert( 'route_summary', \%h );
        $in_inet0 = 0;
    }
    elsif ( $in_inet6 && %h ) {
        $h{afi} = "ipv6";
        $db->insert( 'route_summary', \%h );
        $in_inet6 = 0;
    }

    return $AUDIT_OK;
}

##### ISIS Topology #####

sub isis_topology {
    my ( $self, $conn, $db ) = @_;
    return $AUDIT_FAIL unless $conn && $db;

    my @lines = $conn->cmd("show isis spf brief level 2");

# Example output:
# IPV4 Unicast IS-IS level 2 SPF results:
# Node             Metric     Interface   NH   Via             SNPA
# oslo-OSLOS3DA-pe7.02 1000100xe-5/1/0.0  IPV4 cr2.osls        0:24:dc:9d:ef:16
#                             xe-5/0/0.0  IPV4 cr2.osls        0:24:dc:9d:ea:95
# krsand-VESTR24A-pe2.00 1199 xe-5/2/0.0  IPV4 oslo-SAN110-p2  0:1e:13:cc:25:76
#                             xe-5/0/1.0  IPV4 oslo-SAN110-p2  0:1e:13:cc:26:10
# ar1.gk.00        1100       xe-4/1/0.0  IPV4 cr1.xa19        0:12:1e:54:b4:73
#                             xe-5/1/0.0  IPV4 cr2.osls        0:24:dc:9d:ef:16
#                             xe-5/0/0.0  IPV4 cr2.osls        0:24:dc:9d:ea:95
# oslo-OSLOS3DA-pe7.00 100    xe-5/1/0.0  IPV4 cr2.osls        0:24:dc:9d:ef:16
#                             xe-5/0/0.0  IPV4 cr2.osls        0:24:dc:9d:ea:95
# cr1.nord41.00    250        xe-5/1/1.0  IPV4 trondh-PRINSG39-p2  0:1e:13:cb:45:29
# cr1.nord41.00    250        xe-5/1/1.0  IPV4 trondh-PRINSG39-p2  0:1e:13:cb:45:29
#   155 nodes
#
# IPV6 Unicast IS-IS level 2 SPF results:
# Node             Metric     Interface   NH   Via             SNPA
# krsand-VESTR24A-pe2.00 10050xe-5/2/1.0  IPV6 ar6.oslofn3     0:13:c3:98:61:0
# ar1.gk.00        1100       xe-4/1/0.0  IPV6 cr1.xa19        0:12:1e:54:b4:73
#                             xe-5/1/0.0  IPV6 cr2.osls        0:24:dc:9d:ef:16
#                             xe-5/0/0.0  IPV6 cr2.osls        0:24:dc:9d:ea:95
# oslo-OSLOS3DA-pe7.00 100    xe-5/1/0.0  IPV6 cr2.osls        0:24:dc:9d:ef:16
#                             xe-5/0/0.0  IPV6 cr2.osls        0:24:dc:9d:ea:95
# cr1.nord41.00    250        xe-5/1/1.0  IPV6 trondh-PRINSG39-p2  0:1e:13:cb:45:29
# cr1.nord41.00    250        xe-5/1/1.0  IPV6 trondh-PRINSG39-p2  0:1e:13:cb:45:29
#   125 nodes

    my ( $host, $metric );
    while (@lines) {
        my $line = shift @lines;
        $line =~ s!/P{IsPrint}!!g;    # remove all non-printables
        chomp($line);

        given ($line) {
            # skip headers
            when ( /^IPV(?:4|6) Unicast/ || /^Node/ ) { }

            # match lines beginning with a node/hostname
            when (/^($HOSTNAME \. \d+)  # hostname ($1)
	     			\s+                 
	     			(\d+)               # metric ($2)
	     			\s*                 # not always a space between metric and interface
	     			($INTERFACE)        # interface ($3)
	     			\s+ 
	     			(IPV4 | IPV6)		# afi, ($4)
			/xms) {    
                $host   = $1;
                $metric = $2;

                if ( $metric != 0 ) {    # skip our self
                    $db->insert(
                        'isis_topology',
                        {
                            host      => $host,
                            metric    => $metric,
                            interface => $3,
                            afi       => lc($4)
                        }
                    );
                }
            }

            # match continuation lines, i.e. where a host
            # have more than one nexthop interface
            when (/^\s+                  
	     			($INTERFACE)   	# interface ($1)
	     			\s+ 
	     			(\w+)         	# afi ($2)
			/xms) {    
                $db->insert(
                    'isis_topology',
                    {
                        host        => $host,
                          metric    => $metric,
                          interface => $1,
                          afi       => lc($2)
                    }
                );
            }
        }
    }

    return $AUDIT_OK;
}

##### ISIS Neighbors #####

sub isis_neighbours {
    my ( $self, $conn, $db ) = @_;
    return $AUDIT_FAIL unless $conn && $db;

    foreach my $line ( $conn->cmd("show isis adjacency") ) {
        $line =~ s!/P{IsPrint}!!g;    # remove all non-printables
        chomp($line);

        # Example output:
        # Interface             System         L State        Hold (secs) SNPA
        # xe-4/1/0.0            cr1.xa19       2  Up                   20
        # xe-4/3/0.0            oslo-SAN110-pe4 2 Up                   22
        # xe-5/0/0.0            cr2.osls       2  Up                   23
        # xe-5/0/1.0            oslo-SAN110-p2 2  Up                   27
        # xe-5/1/0.0            cr2.osls       2  Up                   23
        # xe-5/1/1.0            trondh-PRINSG39-p2 2 Up                29
        # xe-5/2/0.0            oslo-SAN110-p2 2  Up                   20
        # xe-5/2/1.0            ar6.oslofn3    2  Up                   29
        # xe-5/3/0.0            br1.fn3        2  Up                   24
        # xe-5/3/1.0            br1.fn3        2  Up                   19

        given ($line) {
            # skip heading
            when (/^Interface/) { }    # do nothing

            when (/($INTERFACE)   # Interface: $1
	     			\s+
	     			($HOSTNAME)    # System: $2
	     			\s+ \d+ \s+
	     			(\w+)
			/xms) {                          # State: $3
                $db->insert(
                    'isis_neighbour',
                    {
                        interface => $1,
                        neighbour => $2,
                        state     => lc($3)
                    }
                );
            }
        }
    }

    return $AUDIT_OK;
}

##### BGP summary #####

sub bgp {
    my ( $self, $conn, $db ) = @_;
    return $AUDIT_FAIL unless $conn && $db;

    my ( $peer, $asn );
    foreach my $line ( $conn->cmd("show bgp summary") ) {
        $line =~ s!/P{IsPrint}!!g;    # remove all non-printables
        chomp($line);

# Example command output:
#
# Groups: 3 Peers: 6 Down peers: 0
# Table          Tot Paths  Act Paths Suppressed    History Damp State    Pending
# inet.0            183528      91744          0          0          0          0
# inet.2                 0          0          0          0          0          0
# bgp.l3vpn.0        13994       6997          0          0          0          0
# bgp.l3vpn.2            0          0          0          0          0          0
# inet6.0            15572       7796          0          0          0          0
# inet6.2                0          0          0          0          0          0
# Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State\
#   #Active/Received/Accepted/Damped...
# 10.65.192.198          2116   11186397     339889       0       9    10w1d12h Establ
#   bgp.l3vpn.0: 6997/6997/6997/0
#   terra_1435.inet.0: 28/28/28/0
#   bluecom_dmz.inet.0: 48/85/85/0
#   terra_1425.inet.0: 23/23/23/0
#   terra_1405.inet.0: 19/19/19/0
#   terra_1473.inet.0: 21/21/21/0
#   ngrp-butikk.inet.0: 6803/6818/6818/0
# 10.65.192.199          2116   11336490     343685       0       9     10w2d7h Establ
#   bgp.l3vpn.0: 0/6997/6997/0
#   terra_1435.inet.0: 0/28/28/0
#   bluecom_dmz.inet.0: 0/85/85/0
#   terra_1425.inet.0: 0/23/23/0
#   terra_1405.inet.0: 0/19/19/0
#   terra_1473.inet.0: 0/21/21/0
#   ngrp-butikk.inet.0: 0/6818/6818/0
# 193.75.0.70            2116    9105673    1138794       0       3    34w1d16h Establ
#   inet.0: 80301/91765/91759/0
#   inet.2: 0/0/0/0
# 193.75.0.79            2116    8777302    1138732       0       4    34w1d16h Establ
#   inet.0: 11443/91763/91757/0
#   inet.2: 0/0/0/0
# 2001:8c0:2116::70        2116    8438487     764121       0       6    34w1d16h Establ
#   inet6.0: 6994/7791/7791/0
#   inet6.2: 0/0/0/0
# 2001:8c0:2116::79        2116    8912692     764082       0       6    34w1d16h Establ
#   inet6.0: 802/7781/7781/0
#   inet6.2: 0/0/0/0

        given ($line) {
            # skip headers and summary lines
            when (   /^Groups/
                  || /^Table/
                  || /^Peer/
                  || /^inet\.\d+/
                  || /^bgp.l3vpn/
                  || /^inet6\.\d+/ ) { }  # do nothing

            # match IPv4 peer line
            when (/^($RE{net}{IPv4}) \s+ (\d+)/xms) {
                $peer = $1;
                $asn  = $2;
            }

            # match IPv4 peer line
            when (/^($IPv6_re) \s+ (\d+)/xms) {
                $peer = $1;
                $asn  = $2;
            }

            # match afi and accepted prefixes
            when ( m!^ \s+ 
	      			([\w\.]+):  # afi ($1)
	      			\s+
	      			\d+         # active
	      			/
	      			\d+         # received
	      			/
	      			(\d+)       # accepted ($2)
	     	!xms) {
                my $prefixes = $2;
                given ($1) {
                    when (/^inet\.0$/) {
                        $db->insert(
                            'bgp',
                            {
                                peer     => $peer,
                                asn      => $asn,
                                afi      => "ipv4",
                                prefixes => $prefixes
                            }
                        );
                    }

                    when (/^inet6\.0$/) {
                        $db->insert(
                            'bgp',
                            {
                                peer     => $peer,
                                asn      => $asn,
                                afi      => "ipv6",
                                prefixes => $prefixes
                            }
                        );
                    }

                    when (/^bgp\.l3vpn\.0/) {
                        $db->insert(
                            'bgp',
                            {
                                peer     => $peer,
                                asn      => $asn,
                                afi      => "vpnv4",
                                prefixes => $prefixes
                            }
                        );
                    }

                    when (/(.*)\.inet\.0$/) {
                        $db->insert(
                            'bgp',
                            {
                                peer     => $peer,
                                asn      => $asn,
                                vrf      => $1,
                                afi      => "vpnv4",
                                prefixes => $prefixes
                            }
                        );
                    }
                }
            }
        }
    }

    return $AUDIT_OK;
}

#---

1;
