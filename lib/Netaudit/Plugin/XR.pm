#
# Copyright (c) 2012, Per Carlson
#
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl 5.14. For more details,
# see the full text of the licenses in the directory LICENSES.
#

package Netaudit::Plugin::XR;

use Mojo::Base 'Netaudit::Plugin::Base';

use Regexp::Common;
use Regexp::IPv6 qw{ $IPv6_re };

use Netaudit::Constants;

### RegExps ###

my $PROMPT   = '/RP\/\d+\/(RP)*\d+\/CPU\d+:[-\p{Alnum}\.]+#\s*/';
my @HANDLES = (qr{ Cisco \s IOS \s XR \s Software }xms);
my $MAC = qr{ [0-f]{4} \. [0-f]{4} \. [0-f]{4} }xms;

my $INTERFACE = qr{ 
  (?:Te|Gi [a-zA-Z]*)      # interface type
	(?:\d+ /){3} \d+         # chassis / slot / module / port 
	(?:\. \d+ )*             # optional sub-interface
}xms;

# SNMP OID's
my $oid = {
  'vrf' => {
    # Cisco experimental L3VPN-MIB
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

##### Set up environment #####

sub new {
  my $self = shift->SUPER::new(@_);

  # disable "--more--" prompt
  $self->cli->cmd("terminal length 0");

  # no timestamps in show commands
  # official version first...
  $self->cli->cmd("terminal exec prompt no-timestamp");

  # and the 3.6.3 hack later
  $self->cli->cmd("terminal no-timestamp");

  return $self;
}

##### routing summary #####

sub route_summary {
  my ($self) = @_;

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
  foreach my $line ($self->cli->cmd("show route afi-all summary")) {
    $line =~ s!/P{IsPrint}!!g;    # remove all non-printables
    chomp($line);

    for ($line) {
      # track afi
      when (m{ ^ (IPv4 | IPv6) \s Unicast }xms) {
        $h->{afi} = lc($1);
      }

      # capture each protocol
      when (m{ ^ connected \s+ (\d+) }xms)       { $h->{connected} = $1; }
      when (m{ ^ static \s+ (\d+) }xms)          { $h->{static}    = $1; }
      when (m{ ^ local \s+ (\d+) }xms)           { $h->{local}     = $1; }
      when (m{ ^ bgp \s+ \d+ \s+ (\d+) }xms)     { $h->{bgp}       = $1; }
      when (m{ ^ isis \s+ [-\w]+ \s+ (\d+) }xms) { $h->{isis}      = $1; }

      # when we hits total, store data
      when (m{ ^ Total }xms) {
        $self->db->insert('route_summary', $h);
        $h = ();
      }
    }
  }
  return $AUDIT_OK;
}

##### ISIS Topology #####

sub isis_topology {
  my ($self) = @_;

  my ($afi);

  my $RE_ISIS = qr{
    ^
    ($HOSTNAME)       # peer ($1)
	  \s+
	  (\d+)             # metric ($2)
	  \s+
    $HOSTNAME         # next hop router
    \s+
	  ($INTERFACE)      # next hop interface ($3)
  }xmso;

  foreach my $line ($self->cli->cmd("show isis afi-all topology level 2")) {
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

    for ($line) {
      # skip header
      when (m{ ^ System \ Id }xms) { }

      # grab afi
      when (m{ ^ IS-IS .* (IPv4 | IPv6) }xms) {
        $afi = lc($1);
      }

      # get all entries with numerical metric
      when (/$RE_ISIS/) {
        $self->db->insert(
          'isis_topology',
          {
            host      => $1,
            metric    => $2,
            interface => $3,
            afi       => $afi
          }
        );
      }
    }
  }
  return $AUDIT_OK;
}

##### ISIS Neighbors #####

sub isis_neighbour {
  my ($self) = @_;

  my $RE_ISIS = qr{
    ^
    ($HOSTNAME)                # neighbour, $1
	  \s+ 
	  ($INTERFACE)               # interface, $2
	  \s+ 
    (?: $MAC | \*PtoP\* ) 
    \s+     
	  (\w+)                      # state, $3
	}xmso;

  foreach my $line ($self->cli->cmd("show isis neighbors")) {
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

    for ($line) {
      # skip headers
      when (m{^ (?: IS-IS | System \s Id | Total \s neighbour \s count ) }) { }

      when (/$RE_ISIS/) {
        $self->db->insert(
          'isis_neighbour',
          {
            neighbour => $1,
            interface => $2,
            state     => lc($3)
          }
        );
      }
    }
  }
  return $AUDIT_OK;
}

##### BGP IPv46 summary #####

sub bgp {
  my ($self) = @_;

  my ($afi, $peer, $vrf);

  my $RE_BGPv4 = qr{
    ^
    ($RE{net}{IPv4})      # peer, $1
	  \s+ 
    \d+                   # Spk
    \s+
	  (\d+)                 # AS, $2
	  .*?                   # don't care about rest until...
	  (\d+)                 # ...prefixes, $3
    $
  }xmso;

  my $RE_BGPv6 = qr{
    ^ 
    \s+ 
    \d+          # Spk
    \s+
	  (\d+)        # AS, $1
	  .*?          # don't care about rest until...
	  (\d+)        # ...prefixes, $2
    $
  }xms;

  # first we do IPv4 and IPv6
  foreach my $line ($self->cli->cmd("show bgp all unicast summary")) {
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

    for ($line) {
      when (m{ ^ Address \s Family: \s (IPv4 | IPv6) }xms) {
        $afi = lc($1);
      }

      when (/$RE_BGPv4/) {
        $self->db->insert(
          'bgp',
          {
            peer     => $1,
            asn      => $2,
            prefixes => $3,
            afi      => $afi
          }
        );
      }

      # for IPv6 peers, we need to store peer ip
      when (m{ ^ ($IPv6_re) }xms) {
        $peer = $1;
      }

      when (/$RE_BGPv6/) {
        $self->db->insert(
          'bgp',
          {
            peer     => $peer,
            asn      => $1,
            prefixes => $2,
            afi      => $afi
          }
        );
      }
    }
  }

  my $RE_BGP_vrf = qr{
    ^
    ($RE{net}{IPv4})  # Peer, $1
	  \s+
    \d+               # Spk
    \s+
	  (\d+)             # AS, $2
	  .*?               # don't care until...
	  (\d+)             # ...prefixes, $3
    $
  }xmso;

  # and then the IPv4 peerings in VRF's
  foreach my $line ($self->cli->cmd("show bgp vrf all summary")) {
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

    for ($line) {
      # grab VRF name
      when (m{ ^ VRF: \s+ (.*) $ }xms) {
        $vrf = $1;
      }

      # then neighbour and prefixes
      when (/$RE_BGP_vrf/) {
        $self->db->insert(
          'bgp',
          {
            peer     => $1,
            asn      => $2,
            afi      => "vpnv4",
            vrf      => $vrf,
            prefixes => $3
          }
        );
      }
    }
  }

  # and finally, VPNv4 peerings

  my $RE_BGP_vpnv4 = qr{
    ^
    ($RE{net}{IPv4})  # peer, $1
	  \s+
    \d+               # Spk
    \s+
	  (\d+)             # AS, $2
	  .*?               # dont' care until...
	  (\d+)             # prefixes, $3
    $
  }xmso;

  foreach my $line ($self->cli->cmd("show bgp vpnv4 unicast summary")) {
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

    for ($line) {
      when (/$RE_BGP_vpnv4/) {
        $self->db->insert(
          'bgp',
          {
            peer     => $1,
            asn      => $2,
            afi      => "vpnv4",
            prefixes => $3
          }
        );
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

  # if we got here we hav no data
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

  # if we got here we hav no data
  return $AUDIT_NODATA;
}

1;
