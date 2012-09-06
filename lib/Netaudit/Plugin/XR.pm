#
# Copyright (c) 2012, Per Carlson
#
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl 5.14. For more details,
# see the full text of the licenses in the directory LICENSES.
#

package Netaudit::Plugin::XR;

use feature 'switch';
use strict;
use warnings;

use Regexp::Common;
use Regexp::IPv6 qw{ $IPv6_re };

use Netaudit::Constants;

### RegExps ###

my $HOSTNAME  = qr! [-\p{Alnum}\.]+ !xms;
my $PROMPT    = '/RP\/\d+\/(RP)*\d+\/CPU\d+:[-\p{Alnum}\.]+#\s*/';

my @HANDLES   = (
  qr{ Cisco \s IOS \s XR \s Software }xms
);

my $MAC       = qr{ [0-f]{4} \. [0-f]{4} \. [0-f]{4} }xms;

my $INTERFACE = qr{ 
  (?:Te|Gi [a-zA-Z]*)      # interface type
	(?:\d+ /){3} \d+         # chassis / slot / module / port 
	(?:\. \d+ )*             # optional sub-interface
}xms;

##### do this plugin handle the device? #####

sub handles {
  my ($self, $sysdescr) = @_;
  return scalar grep { $sysdescr =~ m/$_/ } @HANDLES;
}

##### Return the prompt to use #####

sub prompt { return $PROMPT }

##### Set up environment #####

sub init {
  my ($self, $conn) = @_;

  # disable "--more--" prompt
  $conn->cmd("terminal length 0");

  # no timestamps in show commands
  # official version first...
  $conn->cmd("terminal exec prompt no-timestamp");

  # and the 3.6.3 hack later
  $conn->cmd("terminal no-timestamp");
  return;
}

##### routing summary #####

sub route_summary {
  my ($self, $conn, $db) = @_;
  return $AUDIT_FAIL unless $conn && $db;

  # Example output:
  # IPv4 Unicast:
  # -------------
  #
  # Route Source    Routes    Backup    Deleted    Memory (bytes)
  # connected       19        1         0          2720
  # local           20        0         0          2720
  # local LSPV      1         0         0          136
  # bgp 2116        401132    26        6          54557944
  # isis ISIS       412       19        0          80096
  # dagr            0         0         0          0
  # Total           401584    46        6          54643616
  #
  # IPv6 Unicast:
  # -------------
  #
  # Route Source    Routes    Backup    Deleted    Memory (bytes)
  # connected       19        1         0          3280
  # local           20        0         0          3280
  # bgp 2116        7821      0         0          1282644
  # isis ISIS       324       19        0          81508
  # Total           8184      20        0          1370712

  my ($h);
  foreach my $line ($conn->cmd("show route afi-all summary")) {
    $line =~ s!/P{IsPrint}!!g;    # remove all non-printables
    chomp($line);

    given ($line) {

      # track afi
      when (/^ (IPv4 | IPv6) \s Unicast/xms) { $h->{afi} = lc($1); }

      # capture each protocol
      when (/^connected \s+ (\d+)/xms)       { $h->{connected} = $1; }
      when (/^static \s+ (\d+)/xms)          { $h->{static}    = $1; }
      when (/^local \s+ (\d+)/xms)           { $h->{local}     = $1; }
      when (/^bgp \s+ \d+ \s+ (\d+)/xms)     { $h->{bgp}       = $1; }
      when (/^isis \s+ [-\w]+ \s+ (\d+)/xms) { $h->{isis}      = $1; }

      # when we hits total, store data
      when (/^Total/) {
        $db->insert('route_summary', $h);
        $h = ();
      }
    }
  }
  return $AUDIT_OK;
}

##### ISIS Topology #####

sub isis_topology {
  my ($self, $conn, $db) = @_;
  return $AUDIT_FAIL unless $conn && $db;

  my ($afi);

  foreach my $line ($conn->cmd("show isis afi-all topology level 2")) {
    $line =~ s!/P{IsPrint}!!g;    # remove all non-printables
    chomp($line);

    # Example output:
    #
    # IS-IS ISIS paths to IPv4 Unicast (Level-2) routers
    # System Id       Metric  Next-Hop        Interface       SNPA
    # ar2.s138        599     cr1.fn3         Te0/3/0/0       *PtoP*
    # ar2.s138        599     cr1.fn3         Te0/1/0/0       *PtoP*
    # gr1.tx          16777613  cr1.fn3         Te0/3/0/0       *PtoP*
    # gr1.tx          16777613  cr1.fn3         Te0/1/0/0       *PtoP*
    # oslo-SAN110-p2  --
    # stavang-FABV8-p2  100     stavang-FABV8-p2  Te0/0/0/0       *PtoP*
    #
    # IS-IS ISIS paths to IPv6 Unicast (Level-2) routers
    # System Id       Metric  Next-Hop        Interface       SNPA
    # ar2.s138        599     cr1.fn3         Te0/3/0/0       *PtoP*
    # ar2.s138        599     cr1.fn3         Te0/1/0/0       *PtoP*
    # gr1.tx          **
    # oslo-SAN110-p2  --
    # stavang-FABV8-p2  100     stavang-FABV8-p2  Te0/0/0/0       *PtoP*

    given ($line) {

      # skip headers
      when (/^System Id/) { }

      # grab afi
      when (/^IS-IS .* (IPv4 | IPv6) /xms) { $afi = lc($1); }

      # get all entries with numerical metric
      when (
        /^($HOSTNAME)       # neighbour ($1)
	     			\s+
	     			(\d+)             # metric ($2)
	     			\s+ $HOSTNAME \s+
	     			($INTERFACE)
	    	/xms
        )
      {
        $db->insert(
          'isis_topology',
          {
            host        => $1,
              metric    => $2,
              interface => $3,
              afi       => $afi
          });
      }
    }
  }
  return $AUDIT_OK;
}

##### ISIS Neighbors #####

sub isis_neighbours {
  my ($self, $conn, $db) = @_;
  return $AUDIT_FAIL unless $conn && $db;

  foreach my $line ($conn->cmd("show isis neighbors")) {
    $line =~ s!/P{IsPrint}!!g;    # remove all non-printables
    chomp($line);

# Example output:
#
# IS-IS ISIS neighbors:
# System Id      Interface        SNPA           State Holdtime Type IETF-NSF
# kongsb-KONGu1-pe1 Gi0/2/0/7        *PtoP*         Up    22       L2   Capable
# ar1.vestr49    Te0/1/0/2        *PtoP*         Up    20       L2   Capable
# drammen-STT1D-pe3 Gi0/2/0/2        *PtoP*         Up    28       L2   Capable
# drammen-STT1D-pe3 Gi0/2/0/3        *PtoP*         Up    27       L2   Capable
# ar6.oslofn3    Te0/1/0/6        *PtoP*         Up    25       L2   Capable
# br1.fn3        Te0/0/0/1        *PtoP*         Up    24       L2   Capable
# br1.fn3        Te0/0/0/2        *PtoP*         Up    25       L2   Capable
# gjovik-GJOEVIK-pe1 Gi0/2/0/5        *PtoP*         Up    29       L2   Capable
#
# Total neighbor count: 19

    given ($line) {

      # skip headers
      when (/^IS-IS/ || /^System Id/ || /^Total neighbour count/) {
      }    # do nothing

      when (
        /^($HOSTNAME)                      # neighbour, $1
	     			\s+ 
	     			($INTERFACE)                      # interface, $2
	     			\s+ (?: $MAC | \*PtoP\* ) \s+     
	     			(\w+)                             # state, $3
	    	/xms
        )
      {
        $db->insert(
          'isis_neighbour',
          {
            neighbour   => $1,
              interface => $2,
              state     => lc($3)
          });
      }
    }
  }
  return $AUDIT_OK;
}

##### BGP IPv46 summary #####

sub bgp {
  my ($self, $conn, $db) = @_;
  return $AUDIT_FAIL unless $conn && $db;

  my ($afi, $peer, $vrf);

  # first we do IPv4 and IPv6
  foreach my $line ($conn->cmd("show bgp all unicast summary")) {
    $line =~ s!/P{IsPrint}!!g;    # remove all non-printables
    chomp($line);

# Example command output:
#
# Address Family: IPv4 Unicast
# ============================
# <snip/>
# Neighbor        Spk    AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down  St/PfxRcd
# 10.100.10.133     0    32   21133   21275        0    0    0    1y01w Idle
# 172.16.1.1        0     1  565725  567598   614897    0    0     8w2d         11
# 172.16.1.3        0     1  620199  567993   614897    0    0     3w0d          6
# 172.16.1.12       0     1 1457906 1320005   614897    0    0     3w0d          5
# 172.16.1.13       0     1  904614  827594   614897    0    0     3w0d          0
# 172.16.1.14       0     1  967933  897041        0    0    0     2w4d Idle
#
#
# Address Family: IPv6 Unicast
# ============================
# <snip/>
# Neighbor        Spk    AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down  St/PfxRcd
# fd00:8c0:2116::1:1
#                   0     1  563290  563330       70    0    0     8w2d          0
# fd00:8c0:2116::1:7
#                   0     1  547539  497608        0    0    0    1d15h Idle
# fd00:8c0:2116::1:10
#                   0     1  491659  544920       70    0    0     8w2d          1

    given ($line) {
      when (/^Address \s Family: \s (IPv4 | IPv6)/xms) { $afi = lc($1); }

      when (
        /^($RE{net}{IPv4})      # peer, $1
	     			\s+ \d+ \s+
	     			(\d+)                  # asn, $2
	     			.*?                     # don't care fillings
	     			(\d+)$                 # prefixes, $3
	    	/xms
        )
      {
        $db->insert(
          'bgp',
          {
            peer       => $1,
              asn      => $2,
              prefixes => $3,
              afi      => $afi
          });
      }

      # for IPv6 peers, we need to store peer ip
      when (/^($IPv6_re)/) { $peer = $1; }

      when (
        /^ \s+ \d+ \s+
	     			(\d+)           # asn, $1
	     			.*?             # don't care fillings
	     			(\d+)$          # prefixes, $2
	    	/xms
        )
      {
        $db->insert(
          'bgp',
          {
            peer       => $peer,
              asn      => $1,
              prefixes => $2,
              afi      => $afi
          });
      }
    }
  }

  # and then the IPv4 peerings in VRF's
  foreach my $line ($conn->cmd("show bgp vrf all summary")) {
    $line =~ s!/P{IsPrint}!!g;    # remove all non-printables
    chomp($line);

   # Example command output:
   #
   # VRF: vpn11
   #
   # BGP VRF vpn11, state: Active
   # BGP Route Distinguisher: 1:11
   # VRF ID: 0x509b1b34
   # BGP router identifier 172.16.1.2, local AS number 1
   # BGP table state: Active
   # Table ID: 0xe0000002
   # BGP main routing table version 148
   #
   # BGP is operating in STANDALONE mode.
   #
   # Process       RecvTblVer    bRIB/RIB  LabelVer  ImportVer  SendTblVer
   # Speaker              148         148       148        148         148
   #
   # Neighbor    Spk    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  St/PfxRcd
   # 11.0.3.2      0    10   32845   33644      148    0    0    3d21h        2

    given ($line) {

      # grab VRF name
      when (/^VRF: \s+ (.*) $/xms) { $vrf = $1; }

      # then neighbour and prefixes
      when (
        /^($RE{net}{IPv4})   # peer, $1
	     			\s+ \d+ \s+
	     			(\d+)               # asn, $2
	     			.*?
	     			(\d+)$
			/xms
        )
      {    # prefixes, $3
        $db->insert(
          'bgp',
          {
            peer       => $1,
              asn      => $2,
              afi      => "vpnv4",
              vrf      => $vrf,
              prefixes => $3
          });
      }
    }
  }

  # and finally, VPNv4 peerings
  foreach my $line ($conn->cmd("show bgp vpnv4 unicast summary")) {
    $line =~ s!/P{IsPrint}!!g;    # remove all non-printables
    chomp($line);

  # Example comamnd output:
  #
  # BGP router identifier 172.16.1.2, local AS number 1
  # BGP generic scan interval 60 secs
  # BGP table state: Active
  # Table ID: 0x0
  # BGP main routing table version 156
  # BGP scan interval 60 secs
  #
  # BGP is operating in STANDALONE mode.
  #
  # Process      RecvTblVer    bRIB/RIB  LabelVer  ImportVer  SendTblVer
  # Speaker             156         156       156        156         156
  #
  # Neighbor     Spk    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  St/PfxRcd
  # 172.16.1.1     0     1    5784    5793      156    0    0    3d23h       72
  # 172.16.1.6     0     1       0       0        0    0    0 00:00:00 Idle
  # 172.16.1.10    0     1       0       0        0    0    0 00:00:00 Active

    given ($line) {
      when (
        /^($RE{net}{IPv4})   # peer, $1
	     			\s+ \d+ \s+
	     			(\d+)               # asn, $2
	     			.*?                  # dont' care filler
	     			(\d+)$              # prefixes, $3
	    	/xms
        )
      {
        $db->insert(
          'bgp',
          {
            peer       => $1,
              asn      => $2,
              afi      => "vpnv4",
              prefixes => $3
          });
      }
    }
  }
  return $AUDIT_OK;
}

#---

1;
