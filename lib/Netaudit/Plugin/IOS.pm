#
# Copyright (c) 2012, Per Carlson
#
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl 5.14. For more details,
# see the full text of the licenses in the directory LICENSES.
#

package Netaudit::Plugin::IOS;

use Mojo::Base 'Netaudit::Plugin::Base';

use Regexp::Common;
use Regexp::IPv6 qw{ $IPv6_re };

use Netaudit::Constants;

### RegExps ###

my $PROMPT    = '/[\p{Alnum}\.-]+[#>]\s*/';
my $TIMESTAMP = qr{ ^(Load for|Time source is) }xms;

my @HANDLES = (
  qr{ Cisco \s IOS \s Software }xms,
  qr{ Cisco \s Internetwork \s Operating \s System \s Software }xms
);

my $MAC = qr! [0-f]{4} \. [0-f]{4} \. [0-f]{4} !xms;

my $INTERFACE = qr{ 
  (?:Gi|Fa [a-zA-Z]*)      # interface type
	\d+ / \d+                # slot / port|module
	(?: / \d+ )*             # port (if module)
	(?: \. \d+ )*            # optional sub-interface
}xms;

# SNMP OID's

my $oid = {
  'vrf' => {
    # IETF experimental L3VPN-MIB
    'ActiveInterfaces'     => '.1.3.6.1.3.118.1.2.2.1.6',
    'AssociatedInterfaces' => '.1.3.6.1.3.118.1.2.2.1.7',
  },

  'pwe3' => {
    # Cisco experimental PW MIB
    'PeerAddr'   => '.1.3.6.1.4.1.9.10.106.1.2.1.9',
    'ID'         => '.1.3.6.1.4.1.9.10.106.1.2.1.10',
    'Name'       => '.1.3.6.1.4.1.9.10.106.1.2.1.21',
    'OperStatus' => '.1.3.6.1.4.1.9.10.106.1.2.1.26',
  }};

# do this plugin handle the device?

sub handles {
  my ($self, $sysdescr) = @_;

  return scalar grep { $sysdescr =~ m/$_/ } @HANDLES;
}

# return the prompt to use

sub prompt {
  return $PROMPT;
}

# constructor

sub new {
  my $self = shift->SUPER::new(@_);

  # disable "--more--" prompt
  $self->cli->cmd("terminal length 0");

  # no timestamps in show commands
  $self->cli->cmd("terminal no exec prompt timestamp");

  return $self;
}

##### routing summary #####

sub route_summary {
  my ($self) = @_;

  my %h;

  my $RE_ISIS = qr{
    ^ 
    isis 
    \s+ 
	  (?: [-a-zA-Z]+ \s+ )*  # optional isis name
	  (\d+)                  # networks
    \s+
	  (\d+)                  # subnets
  }xms;

  my $RE_BGP = qr{
    ^
    bgp 
    \s+ 
	  \d+       # asn
    \s+
	  (\d+)     # networks
    \s+
	  (\d+)     # subnets
  }xms;

  # do ipv4 first
  foreach my $line ($self->cli->cmd("show ip route summary")) {
    $line =~ s!/P{IsPrint}!!g;    # remove all non-printables
    chomp($line);

    # Example output:
    #
    # IP routing table name is Default-IP-Routing-Table(0)
    # Route Source    Networks    Subnets     Overhead    Memory (bytes)
    # connected       0           8           512         1216
    # static          0           0           0           0
    # isis            0           15          960         2280
    #   Level 1: 0 Level 2: 15
    # bgp 30          0           3           192         456
    #   External: 0 Internal: 3 Local: 0
    # internal        4                                   4688
    # Total           4           26          1664        8640
    #
    # * OR * the following isis lines:
    #
    # Route Source    Networks    Subnets     Replicates  Overhead    Memory (bytes)
    # isis BT-Lab     0           23          0           1380        3956
    #   Level 1: 0 Level 2: 23 Inter-area: 0

    $h{afi} = "ipv4";
    for ($line) {
      when (m{ ^ connected \s+ (\d+) \s+ (\d+) }xms) {
        $h{'connected'} = $1 + $2;
      }

      when (m{ ^ static \s+ (\d+) \s+ (\d+) }xms) {
        $h{'static'} = $1 + $2;
      }

      when (m{ ^ internal \s+ (\d+) }xms) {
        $h{'local'} = $1;
      }

      when (/$RE_ISIS/) {
        $h{'isis'} = $1 + $2;
      }

      when (/$RE_BGP/) {
        $h{'bgp'} = $1 + $2;
      }
    }
  }
  $self->db->insert('route_summary', \%h);

  # and then ipv6

  my $RE_v6_ONELINE = qr{
    ^ 
    \s+ (\d+) \s+ local     ,*  # $1
	  \s+ (\d+) \s+ connected ,*  # $2
		\s+ (\d+) \s+ static    ,*  # $3
		\s+  \d+  \s+ RIP       ,*        
		\s+ (\d+) \s+ BGP       ,*  # $4
		\s+ (\d+) \s+ IS-IS     ,*  # $5
		\s+  \d+  \s+ OSPF      ,*       
  }xms;

  my $RE_v6_ISIS = qr{
    ^ 
    isis
    \s+ 
	  (?: [-a-zA-Z]+ \s+ )*   # optional isis name
	  (\d+)                   # networks
  }xms;

  my $RE_v6_BGP = qr{
    ^
    bgp 
    \s+ 
	  \d+       # asn 
    \s+
	  (\d+)     # networks
  }xms;

  foreach my $line ($self->cli->cmd("show ipv6 route summary")) {
    $line =~ s!/P{IsPrint}!!g;    # remove all non-printables
    chomp($line);

    # Example output:
    #
    # IPv6 Routing Table Summary - 28 entries
    #   6 local, 3 self->cliected, 1 static, 0 RIP, 4 BGP 14 IS-IS, 0 OSPF
    #   Number of prefixes:
    #     /8: 1, /10: 1, /40: 5, /64: 2, /124: 9, /128: 10
    #
    # * OR *
    #
    # IPv6 routing table name is default(0) global scope - 27 entries
    # IPv6 routing table default maximum-paths is 16
    # Route Source    Networks    Overhead    Memory (bytes)
    # connected       2           176         248
    # local           4           352         496
    # ND              0           0           0
    # isis BT-Lab     16          1408        1984
    #   Level 1: 0  Level 2: 16  Inter-area: 0  Summary: 0
    # bgp 1           4           352         496
    #   Internal: 4  External: 0  Local: 0
    # static          1           88          124
    #   Static: 1  Per-user static: 0
    # Total           27          2376        3348
    #
    #   Number of prefixes:
    #     /8: 1, /40: 5, /64: 3, /124: 9, /128: 9

    $h{afi} = "ipv6";
    for ($line) {
      when (/$RE_v6_ONELINE/) {
        $h{'local'}     = $1;
        $h{'connected'} = $2;
        $h{'static'}    = $3;
        $h{'bgp'}       = $4;
        $h{'isis'}      = $5;
      }

      when (m{ ^ connected \s+ (\d+) }xms) {
        $h{'connected'} = $1;
      }

      when (m{ ^ local \s+ (\d+) }xms) {
        $h{'local'} = $1;
      }

      when (m{ ^ static \s+ (\d+) }xms) {
        $h{'static'} = $1;
      }

      when (/$RE_v6_ISIS/) {
        $h{'isis'} = $1;
      }

      when (/$RE_v6_BGP/) {
        $h{'bgp'} = $1;
      }
    }
  }
  $self->db->insert('route_summary', \%h);

  return $AUDIT_OK;
}

##### ISIS Topology #####

sub isis_topology {
  my ($self) = @_;

  my ($host, $metric);

  my $RE_ISIS = qr{
    ^ 
    ($HOSTNAME)      # host, $1
	  \s+ 
	  (\d+)            # metric, $2
	  \s*              # optional space
	  $HOSTNAME        # next hop router
	  \s+
	  ($INTERFACE)     # next hop interface, $3
	  \s*              # optional space
	  # if there are some tunneling used, the SNPA will be '*Tunnel*'
	  # instead of MAC address
	  (?:$MAC | \*Tunnel\*)
  }xmso;

  my $RE_ISIS_CONT = qr{
    ^
	  \s+              # leading space
	  $HOSTNAME        # next hop router
	  \s+
	  ($INTERFACE)     # next hop interface, $1
	  \s*              # optional space
	  # if there are some tunneling used, the SNPA will be '*Tunnel*'
	  # instead of MAC address
	  (?:$MAC | \*Tunnel\*)
  }xmso;

  # we need two runs here. 12k do support "sh isis * top", but not all 7200

  # do ipv4 first
  foreach my $line ($self->cli->cmd("show isis topology level-2")) {
    chomp($line);

    # Example output:
    #
    # IS-IS paths to level-2 routers
    # System Id             Metric  Next-Hop              Interface   SNPA
    # ar2.s138              600     cr1.fn3               Gi14/0/0    2c21.72b4.5717
    # gr1.tx                16777614cr1.fn3               Gi14/0/0    2c21.72b4.5717
    # ar1.td                5200    oslo-SAN110-p2        Gi0/0/0     001e.13cc.257c
    #                               cr1.fn3               Gi14/0/0    2c21.72b4.5717
    # oslo-OEAK19-pe2       5000    oslo-OEAK19-pe2       Gi15/0/0.1000005.9aad.bc08
    # ar6.oslofn3           --

    for ($line) {
      # skip header lines
      when (m{ ^ (?: IS-IS | System \s Id ) }xms) { }

      # match lines beginning with a node/hostname
      # with a numerical metric
      when (/$RE_ISIS/) {
        $host   = $1;
        $metric = $2;

        $self->db->insert(
          'isis_topology',
          {
            'host'      => $host,
            'metric'    => $metric,
            'interface' => $3,
            'afi'       => "ipv4",
          }
        );
      }

      # match continuation lines, i.e. where a host
      # have more than one nexthop interface
      when (/$RE_ISIS_CONT/) {
        $self->db->insert(
          'isis_topology',
          {
            'host'      => $host,
            'metric'    => $metric,
            'interface' => $1,
            'afi'       => "ipv4"
          }
        );
      }
    }
  }

  # and then ipv6
  foreach my $line ($self->cli->cmd("show isis ipv6 topology level-2")) {
    chomp($line);

    # Example output:
    #
    # IS-IS IPv6 paths to level-2 routers
    # System Id             Metric  Next-Hop              Interface   SNPA
    # ar2.s138              600     cr1.fn3               Gi14/0/0    2c21.72b4.5717
    # gr1.tx                **
    # ar6.oslofn3           --

    for ($line) {
      # skip header lines
      when (m{ ^ (?: IS-IS | System \s Id ) }xms) { }

      # match lines beginning with a node/hostname
      # with a numerical metric
      when (/$RE_ISIS/) {
        $host   = $1;
        $metric = $2;

        $self->db->insert(
          'isis_topology',
          {
            'host'      => $host,
            'metric'    => $metric,
            'interface' => $3,
            'afi'       => "ipv6",
          }
        );
      }

      # match continuation lines, i.e. where a host
      # have more than one nexthop interface
      when (/$RE_ISIS_CONT/) {
        $self->db->insert(
          'isis_topology',
          {
            'host'      => $host,
            'metric'    => $metric,
            'interface' => $1,
            'afi'       => "ipv6"
          }
        );
      }
    }
  }

  return $AUDIT_OK;
}

##### ISIS Neighbours #####

sub isis_neighbour {
  my ($self) = @_;

  my $RE_ISIS = qr{
    ^ 
    ($HOSTNAME)     # hostname ($1)
	  \s*             # optional space
	  ($INTERFACE)    # interface ($2)
	  \s+ 
    (?: $MAC | \*Tunnel\* ) 
    \s+
	  (\w+)           # state ($3)
  }xmso;

  foreach my $line ($self->cli->cmd("show clns neighbors")) {
    chomp($line);

    # Example output:
    # System Id      Interface          SNPA                State  HT   Type Protocol
    # cr1.fn3        Gi14/0/0           2c21.72b4.5717      Up     25   L2   M-ISIS
    # krsand-VESTR24AGi3/2              001a.e398.10aa      Up     27   L2   M-ISIS
    # oslo-OEAK19-pe2Gi15/0/0.100       0005.9aad.bc08      Up     25   L2   IS-IS
    # oslo-SAN110-p2 Gi0/0/0            001e.13cc.257c      Up     29   L2   M-ISIS

    for ($line) {
      # skip headers
      when (m{ ^ System \s Id }xms) { }

      when (/$RE_ISIS/) {
        $self->db->insert(
          'isis_neighbour',
          {
            'neighbour' => $1,
            'interface' => $2,
            'state'     => lc($3)
          }
        );
      }
    }
  }
  return $AUDIT_OK;
}

##### BGP summary #####

sub bgp {
  my ($self) = @_;

  my ($peer, $asn, $vrf, $afi);

  my $RE_BGP_v4 = qr{
    ^ 
    ($RE{net}{IPv4})   # peer ($1)
    \s+
	  \d+                # bgp version
    \s+
	  (\d+)              # asn ($2)
	  .*?                # filler
	  (\d+)              # prefixes ($3), we only cares about peers 
                       # with (0 or more) prefixes
    $
  }xmso;

  # do ipv4 first
  foreach my $line ($self->cli->cmd("show ip bgp ipv4 unicast summary")) {
    chomp($line);

    # Example output (filtered):
    # Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
    # 193.75.0.70     4        2116 66587215 1202576 272009126    3    0 34w2d      400696
    # 193.75.0.79     4        2116 62693885 1202909 272009126    1    0 34w2d      400694
    # 195.204.182.62  4       64589 2091200 1815495        0    0    0 2w5d     Idle (Admin)
    # 195.204.183.38  4       41741  777842 25756405        0    0    0 15w2d    Init

    for ($line) {

      when (/$RE_BGP_v4/) {
        $self->db->insert(
          'bgp',
          {
            'peer'     => $1,
            'asn'      => $2,
            'afi'      => "ipv4",
            'prefixes' => $3
          }
        );
      }
    }
  }

  # then ipv6

  my $RE_BGP_v6 = qr{
    ^
    ($IPv6_re)  # peer ($1)
    \s+ 
    \d+         # bgp version
    \s+
	  (\d+)       # asn ($2)
	  .*?         # filler
	  (\d+)       # prefixes ($3), we only care about numerical prefixes
	  $
  }xmso;

  my $RE_BGP_v6_CONT = qr{
    ^
    \s+ 
    \d+         # bgp version
    \s+
	  (\d+)       # asn ($1)
	  .*?         # filler
	  (\d+)       # prefixes ($2), we only care about numerical prefixes
	  $
  }xms;

  foreach my $line ($self->cli->cmd("show bgp ipv6 unicast summary")) {
    chomp($line);

    # Example output (filtered):
    # Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
    # FD00:8C0:3::62  4          11       0       0        0    0    0 never    Active
    # 2001:8C0:2116::70
    #                 4        2116 14524576 1191233 19977862    0    0 34w2d        7813
    # 2001:8C0:2116::79
    #                 4        2116 15733319 1191203 19977862    0    0 34w2d        7814
    # 2001:8C0:9B02:2::2
    #                 4       43516  619627 7042270 19977850    0    0 7w2d            1

    for ($line) {
      # when only ipv6 address on the line, store peer...
      when (m{ ^ ($IPv6_re) \s* $ }xms) {
        $peer = $1;
      }

      # ... and get the rest of the parameters
      when (/$RE_BGP_v6_CONT/) {
        $self->db->insert(
          'bgp',
          {
            'peer'     => $peer,
            'asn'      => $1,
            'afi'      => "ipv6",
            'prefixes' => $2
          }
        );
      }

      # when all are on one line
      when (/$RE_BGP_v6/) {
        $self->db->insert(
          'bgp',
          {
            'peer'     => $1,
            'asn'      => $2,
            'afi'      => "ipv6",
            'prefixes' => $3
          }
        );
      }
    }
  }

  # and finally vpnv4

  my $RE_BGP_vrf = qr{
    ^ 
    BGP \s neighbor \s is \s 
	  ($RE{net}{IPv4})             # peer ($1)
    ,
	  \s+ 
    vrf                          # do have a VRF
    \s+
	  ([^,]+)                      # VRF (anything until next ,) ($2)
    ,
	  \s+ remote \s AS \s+
	  (\d+)                        # asn ($3)
  }xmso;

  my $RE_BGP_vpnv4 = qr{
    ^ 
    BGP \s neighbor \s is \s 
	  ($RE{net}{IPv4})             # peer ($1)
    ,
	  \s+ remote \s AS \s+
	  (\d+)                        # asn ($2)
  }xmso;

  my $RE_BGP_prefixes = qr{
    ^ 
    \s+ 
    Prefixes \s Current: 
	  \s+ 
    \d+           # sent
    \s+
	  (\d+)         # received ($1)
  }xms;

  foreach my $line ($self->cli->cmd("show ip bgp vpnv4 all neighbors")) {
    chomp($line);

    # Example command output (filtered):
    # BGP neighbor is 10.15.15.5,  vrf tad-internal,  remote AS 8979, external link
    #   BGP version 4, remote router ID 10.20.21.2
    #   BGP state = Established, up for 7w2d
    # <snip/>
    #                                  Sent       Rcvd
    #   Prefix activity:               ----       ----
    #     Prefixes Current:               8          1 (Consumes 612 bytes)
    #     Prefixes Total:               195          1
    #     Implicit Withdraw:            174          0
    #     Explicit Withdraw:              9          0
    #     Used as bestpath:             n/a          6
    #     Used as multipath:            n/a          0
    #     Saved (soft-reconfig):        n/a          3 (Consumes 204 bytes)
    #
    # BGP neighbor is 10.65.192.198,  remote AS 2116, internal link
    #   BGP version 4, remote router ID 10.65.192.198
    #   BGP state = Established, up for 10w2d
    # <snip/>
    #  For address family: VPNv4 Unicast
    # <snip/>
    #                                  Sent       Rcvd
    #   Prefix activity:               ----       ----
    #     Prefixes Current:            4961      31195 (Consumes 5657464 bytes)
    #     Prefixes Total:           1018346    2514790
    #     Implicit Withdraw:          53537    1787774
    #     Explicit Withdraw:         964997     695821
    #     Used as bestpath:             n/a      82907
    #     Used as multipath:            n/a          0

    for ($line) {
      # IPv4 peering in VRF
      when (/$RE_BGP_vrf/) {
        $peer = $1;
        $vrf  = $2;
        $asn  = $3;
        $afi  = "";
      }

      # VPNv4 peering
      when (/$RE_BGP_vpnv4/) {
        $peer = $1;
        $asn  = $2;
        $vrf  = undef;
        $afi  = "";
      }

      # get afi
      when (m{ ^ \s+ For \s address \s family: \s (\w+) }xms) {
        $afi = lc($1);
      }

      # get number of current prefixes received
      when (/$RE_BGP_prefixes/) {
        # we are only interested in vpnv4
        if ($afi eq 'vpnv4') {
          my $h = {
            peer     => $peer,
            asn      => $asn,
            afi      => "vpnv4",
            prefixes => $1
          };
          $h->{vrf} = $vrf if $vrf;
          $self->db->insert('bgp', $h);
          $peer = $asn = $vrf = $afi = undef;
        }
      }
    }
  }
  return $AUDIT_OK;
}

#---

sub interface {
  my ($self) = @_;

  my $cb = sub {
    my ($href) = @_;
    $self->db->insert('interface', $href);
  };

  # use stock interfaces from N::SNMP;
  return $self->snmp->interface($cb) ? $AUDIT_OK : $AUDIT_NODATA;
}

#--

sub vrf {
  my ($self) = @_;

  my $cb = sub {
    my ($href) = @_;
    $self->db->insert('vrf', $href);
  };

  # try stock vrfs from N::SNMP first
  return $AUDIT_OK if $self->snmp->vrf($cb);

  # if that failed try again with cisco mib
  return $AUDIT_OK if $self->snmp->vrf($cb, $oid->{'vrf'});

  # if we got here, there are no data
  return $AUDIT_NODATA;
}

#--

sub pwe3 {
  my ($self) = @_;

  my $cb = sub {
    my ($href) = @_;
    $self->db->insert('pwe3', $href);
  };

  # try stock vrfs from N::SNMP first
  return $AUDIT_OK if $self->snmp->pwe3($cb);

  # if that failed try again with cisco mib
  return $AUDIT_OK if $self->snmp->pwe3($cb, $oid->{'pwe3'});

  # if we got here, there are no data
  return $AUDIT_NODATA;
}

__PACKAGE__->meta->make_immutable;

1;
