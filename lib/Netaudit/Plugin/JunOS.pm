#
# Copyright 2012,2013,2014 Per Carlson
#
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl 5.14. For more details,
# see the full text of the licenses in the directory LICENSES.
#

package Netaudit::Plugin::JunOS;

use Mojo::Base 'Netaudit::Plugin::Base';

use Regexp::Common;
use Regexp::IPv6 qw{ $IPv6_re };

use Netaudit::Constants;
use Netaudit::DNS;

no if $] >= 5.017011, warnings => 'experimental::smartmatch';

### RegExps ###

my $PROMPT   = '/> $/';
my @HANDLES = (qr{ Juniper \s Networks .* JUNOS }xms);
my $INTERFACE = qr{ (?:xe|ge|so) - \d+ / \d+ / \d+ (?:\. \d+)* }xms;

# SNMP OID's, columns and textual-conventions,
my $experimental_vrf = {
  # IETF experimental L3VPN-MIB
  'ActiveInterfaces'     => '.1.3.6.1.3.118.1.2.2.1.6',
  'AssociatedInterfaces' => '.1.3.6.1.3.118.1.2.2.1.7',
};

# from JUNIPER-VPN-MIB
my $jnxVpnPwTable = '.1.3.6.1.4.1.2636.3.26.1.4.1';
my $jnxVpnRemotePeIdAddress = '10';    # column in VpnPwTable
my $jnxVpnPwStatus          = '15';    # column in VpnPwTable

my $jnxVpnTable           = '.1.3.6.1.4.1.2636.3.26.1.2.1';
my $jnxVpnConfiguredSites = '8';
my $jnxVpnActiveSites     = '9';

my %jnxVpnType_Rev = (
  'other'      => 1,
  'bgpIpVpn'   => 2,
  'bgpL2Vpn'   => 3,
  'bgpVpls'    => 4,
  'l2Circuit'  => 5,
  'ldpVpls'    => 6,
  'opticalVpn' => 7,
  'vpOxc'      => 8,
  'ccc'        => 9,
  'bgpAtmVpn'  => 10,
);

my %jnxVpnPwStatus = (
  '0' => 'unknown',
  '1' => 'down',
  '2' => 'up',
);

##### do this plugin handle the device? #####

sub handles {
  my ($self, $sysdescr) = @_;
  return scalar grep { $sysdescr =~ m/$_/ } @HANDLES;
}

##### Return the prompt to use #####

sub prompt {
  return $PROMPT;
}

##### Set up environment #####

sub new {
  my $self = shift->SUPER::new(@_);

  # disable "--more--" prompt
  $self->cli->cmd("set cli screen-length 0");

  return $self;
}

##### Routing summary #####

sub route_summary {
  my ($self) = @_;

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
  my $h;

  $self->log->info('running "show route summary"');
  foreach my $line ($self->cli->cmd("show route summary")) {
    $line =~ s!/P{IsPrint}!!g;    # remove all non-printables
    chomp($line);

    for ($line) {
      # get afi
      when (m{ ^ inet\.0: }xms)  { $in_inet0 = 1; }
      when (m{ ^ inet6\.0: }xms) { $in_inet6 = 1; }

      # a blank line separates the afi's
      when (m{ ^ \s* $ }xms) {
        if ($in_inet0) {
          $h->{'afi'} = "ipv4";
          $self->db->insert('route_summary', $h);
          $self->log->insert('route_summary', $h);
          $in_inet0 = 0;
        }
        elsif ($in_inet6) {
          $h->{'afi'} = "ipv6";
          $self->db->insert('route_summary', $h);
          $self->log->insert('route_summary', $h);
          $in_inet6 = 0;
        }
        $h = undef;
      }

      when (m{ ^ \s+ Direct: .*? (\d+) \s active }xms) { $h->{'connected'} = $1; }
      when (m{ ^ \s+ Local:  .*? (\d+) \s active }xms) { $h->{'local'}     = $1; }
      when (m{ ^ \s+ BGP:    .*? (\d+) \s active }xms) { $h->{'bgp'}       = $1; }
      when (m{ ^ \s+ Static: .*? (\d+) \s active }xms) { $h->{'static'}    = $1; }
      when (m{ ^ \s+ IS-IS:  .*? (\d+) \s active }xms) { $h->{'isis'}      = $1; }
    }
  }

  # the last section doesn't have a trailing blank line
  # flush hash on exit
  if ($in_inet0 && $h) {
    $h->{afi} = "ipv4";
    $self->db->insert('route_summary', $h);
    $self->log->insert('route_summary', $h);
    $in_inet0 = 0;
  }
  elsif ($in_inet6 && $h) {
    $h->{afi} = "ipv6";
    $self->db->insert('route_summary', $h);
    $self->log->insert('route_summary', $h);
    $in_inet6 = 0;
  }

  return $AUDIT_OK;
}

##### ISIS Topology #####

sub isis_topology {
  my ($self) = @_;

  my $RE_ISIS = qr{
    ^
    ($HOSTNAME)         # hostname ($1)
    \.
    \d+                 # LSP number
	  \s+                 
	  (\d+)               # metric ($2)
	  \s*                 # not always a space between metric and interface
	  ($INTERFACE)        # interface ($3)
	  \s+ 
	  (IPV4 | IPV6)		    # NH afi, ($4)
  }xmso;

  my $RE_ISIS_CONT = qr{
    ^
    \s+                  
	  ($INTERFACE)   	# interface ($1)
	  \s+ 
	  (\w+)         	# NH afi ($2)
  }xmso;

  $self->log->info('running "show isis spf brief level 2"');
  my @lines = $self->cli->cmd("show isis spf brief level 2");

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

  my ($host, $metric);
  while (@lines) {
    my $line = shift @lines;
    $line =~ s!/P{IsPrint}!!g;    # remove all non-printables
    chomp($line);

    for ($line) {
      # skip headers
      when (m{ ^ (?: IPV(?:4|6) \s Unicast | Node ) }xms) { }

      # match lines beginning with a node/hostname
      when (/$RE_ISIS/) {
        $host   = $1;
        $metric = $2;

        if ($metric != 0) {       # skip our self
          my $h = {
            'host'      => $host,
            'metric'    => $metric,
            'interface' => $3,
            'afi'       => lc($4),
          };
          $self->db->insert('isis_topology', $h);
          $self->log->insert('isis_topology', $h);
        }
      }

      # match continuation lines, i.e. where a host
      # have more than one nexthop interface
      when (/$RE_ISIS_CONT/) {
        my $h = {
          'host'      => $host,
          'metric'    => $metric,
          'interface' => $1,
          'afi'       => lc($2),
        };
        $self->db->insert('isis_topology', $h);
        $self->log->insert('isis_topology', $h);
      }
    }
  }

  return $AUDIT_OK;
}

##### ISIS Neighbors #####

sub isis_neighbour {
  my ($self) = @_;

  my $RE_ISIS = qr{
    ($INTERFACE)   # Interface ($1)
	  \s+
	  ($HOSTNAME)    # System ($2)
	  \s+
    \d+            # Level
    \s+
	  (\w+)          # State ($3)
  }xmso;

  $self->log->info('running "show isis adjacency"');
  foreach my $line ($self->cli->cmd("show isis adjacency")) {
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

    for ($line) {
      # skip heading
      when (m{ ^ Interface }xms) { }

      when (/$RE_ISIS/) {
        my $h = {
          'interface' => $1,
          'neighbour' => $2,
          'state'     => lc($3),
        };
        $self->db->insert('isis_neighbour', $h);
        $self->log->insert('isis_neighbour', $h);
      }
    }
  }

  return $AUDIT_OK;
}

##### BGP summary #####

sub bgp {
  my ($self) = @_;

  my $RE_HEADER = qr{
    ^
    (?: 
      Groups
      |
      Table
      |
      Peer
      |
      inet
      |
      bgp
    )
  }xms;

  my $RE_BGP = qr{
    ^
    \s+ 
	  ([\w\.]+)   # afi ($1)
    :
	  \s+
	  \d+         # active
	  /
	  \d+         # received
	  /
	  (\d+)       # accepted ($2)
  }xms;

  my ($peer, $asn);
  $self->log->info('running "show bgp summary"');
  foreach my $line ($self->cli->cmd("show bgp summary")) {
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
      when (/$RE_HEADER/) { }

      # match IPv4 peer line
      when (m{ ^ ($RE{net}{IPv4}) \s+ (\d+) }xmso) {
        $peer = $1;
        $asn  = $2;
      }

      # match IPv4 peer line
      when (m{ ^ ($IPv6_re) \s+ (\d+) }xmso) {
        $peer = $1;
        $asn  = $2;
      }

      # match afi and accepted prefixes
      when (/$RE_BGP/) {
        my $prefixes = $2;
        for ($1) {
          # inet.0 contains global IPv4 prefixes
          when (m{ ^ inet \. 0 $ }xms) {
            my $h = {
              'peer'     => $peer,
              'asn'      => $asn,
              'afi'      => "ipv4",
              'prefixes' => $prefixes,
            };
            $self->db->insert('bgp', $h);
            $self->log->insert('bgp', $h);
          }

          # inet6.0 contains global IPv6 prefixes
          when (m{ ^ inet6 \. 0 $ }xms) {
            my $h = {
              'peer'     => $peer,
              'asn'      => $asn,
              'afi'      => "ipv6",
              'prefixes' => $prefixes,
            };
            $self->db->insert('bgp', $h);
            $self->log->insert('bgp', $h);
          }

          # bgp.inet.0 contains VPNv4 prefixes
          when (m{ ^ bgp \. l3vpn \. 0 }xms) {
            my $h = {
              'peer'     => $peer,
              'asn'      => $asn,
              'afi'      => "vpnv4",
              'prefixes' => $prefixes,
            };
            $self->db->insert('bgp', $h);
            $self->log->insert('bgp', $h);
          }

          # <vrf>.inet.0 contains IPv4 prefixes in VRF
          when (m{ (.*) \. inet \. 0 $ }xms) {
            my $h = {
              'peer'     => $peer,
              'asn'      => $asn,
              'afi'      => "vpnv4",
              'vrf'      => $1,
              'prefixes' => $prefixes,
            };
            $self->db->insert('bgp', $h);
            $self->log->insert('bgp', $h);
          }
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
    my ($h) = @_;
    $self->db->insert('interface', $h);
    $self->log->insert('interface', $h);
  };

  # use stock interfaces from N::SNMP;
  return $self->snmp->interface($cb) ? $AUDIT_OK : $AUDIT_NODATA;
}

#--

sub vrf {
  my ($self) = @_;

  my $cb = sub {
    my ($h) = @_;
    $self->db->insert('vrf', $h);
    $self->log->insert('vrf', $h);
  };

  # try stock vrfs from N::SNMP first
  return $AUDIT_OK if $self->snmp->vrf($cb);

  # then try experimental IETF MIB
  return $AUDIT_OK if $self->snmp->vrf($cb, $experimental_vrf);

  # if that failed try with Juniper MIB
  my $RE_VPN_TABLE = qr{
    (\d+)         # column in the table ($1)
    \. 
    (\d+)         # the vpntype ($2)
    \.
    (.*)          # the vrf name encoded in "dotted ascii" ($3)
    $
  }xmso;

  my $href =
    $self->snmp->get_columns($jnxVpnTable, $jnxVpnConfiguredSites,
    $jnxVpnActiveSites);

  # give up if no data here either
  return $AUDIT_NODATA unless $href;

  my $result = undef;
  foreach my $k (keys %{$href}) {
    my ($column, $vpntype, $vrf) = ($k =~ /$RE_VPN_TABLE/);

    # we do only look for MPLS BGP VPNs
    next unless ($vpntype eq $jnxVpnType_Rev{'bgpIpVpn'});

    # store vrfname (if not already done)
    $result->{$vrf}->{'vrf'} ||= $self->snmp->chr2str($vrf);

    for ($column) {
      when ($jnxVpnConfiguredSites) {
        $result->{$vrf}->{'associated'} = $href->{$k};
      };

      when ($jnxVpnActiveSites) {
        $result->{$vrf}->{'active'} = $href->{$k};
      };
    }
  }

  return $AUDIT_NODATA unless $result;

  # store collected data in database
  map { 
    $self->db->insert('vrf', $result->{$_});
    $self->log->insert('vrf', $result->{$_}); 
  } keys %{$result};

  return $AUDIT_OK;
}

#--

sub pwe3 {
  my ($self) = @_;

  my $cb = sub {
    my ($h) = @_;
    $self->db->insert('pwe3', $h);
    $self->log->insert('pwe3', $h);
  };

  # try stock vrfs from N::SNMP first
  return $AUDIT_OK if $self->snmp->pwe3($cb);

  # if that failed try with Juniper MIB
  my $RE_PW_TABLE = qr{
    (\d+)         # column in the table ($1)
    \. 
    (\d+)         # the vpntype ($2)
    \.
    (.*)          # the interface name encoded in "dotted ascii" ($3)
    \. 
    (\d+)         # the pwindex, which isn't the VC ID ($4)
    $
  }xmso;

  my $href =
    $self->snmp->get_columns($jnxVpnPwTable, $jnxVpnRemotePeIdAddress,
    $jnxVpnPwStatus);

  # give up if no data here either
  return $AUDIT_NODATA unless $href;

  my $result = undef;
  foreach my $k (keys %{$href}) {
    my ($column, $vpntype, $ifname, $index) = ($k =~ /$RE_PW_TABLE/);

    # we do only support LDP-based PtP circuits, aka l2Circuits
    next unless ($vpntype eq $jnxVpnType_Rev{'l2Circuit'});

    # store ifname (if not already done)
    $result->{$index}->{'interface'} ||= $self->snmp->chr2str($ifname);

    for ($column) {
      when ($jnxVpnRemotePeIdAddress) {
        $result->{$index}->{'peer'} = gethostname($href->{$k});
      };

      when ($jnxVpnPwStatus) {
        $result->{$index}->{'status'} = $jnxVpnPwStatus{$href->{$k}};
      };
    }
  }

  return $AUDIT_NODATA unless $result;

  # store collected data in database
  map { 
    $self->db->insert('pwe3', $result->{$_});
    $self->log->insert('pwe3', $result->{$_}); 
  } keys %{$result};

  return $AUDIT_OK;
}

1;
