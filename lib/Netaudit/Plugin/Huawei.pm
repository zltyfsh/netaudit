#
# Copyright 2015 Per Carlson
#
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl 5.14. For more details,
# see the full text of the licenses in the directory LICENSES.
#

package Netaudit::Plugin::Huawei;

use Mojo::Base 'Netaudit::Plugin::Base';

use Regexp::Common;
use Regexp::IPv6 qw{ $IPv6_re };

use Netaudit::Constants;
use Netaudit::DNS;

no if $] >= 5.017011, warnings => 'experimental::smartmatch';

### RegExps ###

my $PROMPT = '/<[\p{Alnum}\.-]+>\s*/';
my @HANDLES
  = (qr{ Huawei \s+ Versatile \s+ Routing \s+ Platform \s+ Software }iax);

my $INTERFACE = qr{
  (?: GE | 100GE | Eth-Trunk )  # interface types
  \d+                           # slot
  (?: / \d+ )?                  # optional module
  (?: / \d+ )?                  # optional port
  (?: \. \d+ )?                 # optional sub-interface
}x;

# SNMP OID's

my $oid = {
  vrf => {
    # Huawei experimental L3VPN-MIB
    #ActiveInterfaces     => '.1.3.6.1.4.1.2011.5.12.3',
    #AssociatedInterfaces => '.1.3.6.1.4.1.2011.5.12.3',
  },

  pwe3 => {
    # Huawei experimental PW MIB
    PeerAddr   => '.1.3.6.1.4.1.2011.10.2.78.2.1.4',
    ID         => '.1.3.6.1.4.1.2011.10.2.78.2.1.2',
    OperStatus => '.1.3.6.1.4.1.2011.10.2.78.2.1.11',
    # Name      => '.1.3.6.1.4.1.2011.10.2.78.2.1.?', # (no such OID)
  }};

# constructor

sub new {
  my $self = shift->SUPER::new(@_);

  # disable "--- More ---" prompt
  $self->cli->cmd("screen-length 0 temporary");

  return $self;
}

# do this plugin handle the device?

sub handles {
  my ($self, $sysdescr) = @_;
  return scalar grep { $sysdescr =~ m/$_/ } @HANDLES;
}

# return the prompt to use

sub prompt {
  return $PROMPT;
}

##### routing summary #####

sub route_summary {
  my ($self) = @_;

  my ($cmd, $h);

  # do ipv4 first
  $cmd = q{display ip routing-table statistics};
  $self->log->info("running '$cmd'");
  foreach my $line ($self->cli->cmd($cmd)) {
    $line =~ s!/P{IsPrint}!!g;    # remove all non-printables
    chomp($line);

    # Example output:
    #
    # Summary Prefixes : 47
    # Proto      total      active     added      deleted    freed
    #            routes     routes     routes     routes     routes
    # DIRECT     8          8          8          0          0
    # STATIC     0          0          0          0          0
    # RIP        0          0          0          0          0
    # OSPF       0          0          0          0          0
    # IS-IS      41         39         41         0          0
    # BGP        0          0          0          0          0
    # Total      49         47         49         0          0
    #
    # Let us look for "active" routes

    $h->{afi} = "ipv4";
    for ($line) {
      when (m{ ^ DIRECT \s+ \d+ \s+ (\d+) }xms) {
        $h->{connected} = $1;
      }

      when (m{ ^ STATIC \s+ \d+ \s+ (\d+) }xms) {
        $h->{static} = $1;
      }

      when (m{ ^ IS-IS \s+ \d+ \s+ (\d+) }xms) {
        $h->{isis} = $1;
      }

      when (m{ ^ BGP \s+ \d+ \s+ (\d+) }xms) {
        $h->{bgp} = $1;
      }
    }
  }
  $self->db->insert('route_summary', $h);
  $self->log->insert('route_summary', $h);

  # and then ipv6
  $cmd = q{display ipv6 routing-table statistics};
  $self->log->info("running '$cmd'");
  foreach my $line ($self->cli->cmd($cmd)) {
    $line =~ s!/P{IsPrint}!!g;    # remove all non-printables
    chomp($line);

    # Example output:
    #
    # Summary Prefixes : 0
    # Protocol   route       active      added       deleted     freed
    # DIRECT     0           0           0           0           0
    # STATIC     0           0           0           0           0
    # RIPng      0           0           0           0           0
    # OSPFv3     0           0           0           0           0
    # IS-IS      0           0           0           0           0
    # BGP        0           0           0           0           0
    # Total      0           0           0           0           0

    $h->{afi} = "ipv6";
    for ($line) {
      when (m{ ^ DIRECT \s+ \d+ \s+ (\d+) }xms) {
        $h->{connected} = $1;
      }

      when (m{ ^ STATIC \s+ \d+ \s+ (\d+) }xms) {
        $h->{static} = $1;
      }

      when (m{ ^ IS-IS \s+ \d+ \s+ (\d+) }xms) {
        $h->{isis} = $1;
      }

      when (m{ ^ BGP \s+ \d+ \s+ (\d+) }xms) {
        $h->{bgp} = $1;
      }
    }
  }
  $self->db->insert('route_summary', $h);
  $self->log->insert('route_summary', $h);

  return $AUDIT_OK;
}

##### ISIS Topology #####

sub isis_topology {
  my ($self) = @_;

  my ($cmd, $host, $metric);

  my $RE_ISIS = qr{
    ^
    >
    ($HOSTNAME)       # host, $1
    \.\d+             # lsp-id
    \s+
    ./././.           # Node flags
    \s+
    (\d+)             # metric, $2
  }xmso;

  my $RE_ISIS_CONT = qr{
    ^
    \s+              # leading space
    ->               # marker
    ($HOSTNAME)      # next hop router
    \.\d+
  }xmso;

  # do ipv4 first
  $cmd = 'display isis spf-tree level-2';
  $self->log->info(qq{running '$cmd'});
  foreach my $line ($self->cli->cmd($cmd)) {
    chomp($line);

    # Example output:
    #
    # Node              NodeFlag  Distance  Link                 LinkFlag   LinkCost
    # ------------------------------------------------------------------------------
    # >melker.00         -/-/-/-   2105
    #                                       ->lotta.00               D     1000
    #                                       ->martin.00              U     1000
    # >marte.00          -/-/-/-   2105
    #                                       ->martin.00              U     1000
    #                                       ->mce.00                 D     10000
    # >lotta.00          -/-/-/-   3105
    #                                       ->melker.00              U     1000
    # >martin.00         -/-/-/-   1105
    #                                       ->melker.00              D     1000
    #                                       ->marte.00               D     1000
    #                                       ->mina.00                U     1000
    # >riskake.00        -/-/-/-   0
    #                                       ->storeby.00             D     5
    #

    for ($line) {
      # match lines beginning with a node/hostname
      # with a numerical metric (distance),but skip those
      # with metric 0 (pointing to it self).

      when (/$RE_ISIS/) {
        if ($2 == 0) { $host = undef; next }
        $host   = $1;
        $metric = $2;
      }

      # match continuation lines with the neighbours
      when (/$RE_ISIS_CONT/) {
        next unless $host;
        my $h
          = {host => $host, metric => $metric, nexthop => $1, afi => 'ipv4',};

        $self->db->insert('isis_topology', $h);
        $self->log->insert('isis_topology', $h);
      }
    }
  }

  # and then ipv6
  $cmd = q{display isis spf-tree ipv6 level-2};
  $self->log->info("running '$cmd'");
  foreach my $line ($self->cli->cmd($cmd)) {
    chomp($line);

    # Example output:
    #
    # Node               NodeFlag  Distance  Link                 LinkFlag   LinkCost
    # ------------------------------------------------------------------------------
    # >melker.00         -/-/-/-   4261412880
    #                                         ->lotta.00               F     1000
    #                                         ->martin.00              F     1000
    # >marte.00          -/-/-/-   4261412880
    #                                         ->martin.00              F     1000
    #                                         ->mce.00                 F     10
    # >lotta.00          -/-/-/-   4261412880
    #                                         ->melker.00              F     1000
    # >martin.00         -/-/-/-   4261412880
    #                                         ->melker.00              F     1000
    #                                         ->marte.00               F     1000
    #                                         ->mina.00                F     1000
    # >brum.00           -/-/-/-   4261412880
    #                                         ->storeby.00             F     1000
    # >mina.00           -/-/-/-   4261412880
    #                                         ->martin.00              F     1000
    #                                         ->storeby.00             F     100
    # >storeby.00        -/-/-/-   4261412880
    #                                         ->brum.00                F     1000
    #                                         ->mina.00                F     100
    # >riskake.00        -/-/-/-   0
    #

    for ($line) {
      # match lines beginning with a node/hostname
      # with a numerical metric (distance),but skip those
      # with metric 0 (pointing to it self).

      when (/$RE_ISIS/) {
        if ($2 == 0) { $host = undef; next }
        $host   = $1;
        $metric = $2;
      }

      # match continuation lines with the neighbours
      when (/$RE_ISIS_CONT/) {
        next unless $host;
        my $h
          = {host => $host, metric => $metric, nexthop => $1, afi => 'ipv6',};

        $self->db->insert('isis_topology', $h);
        $self->log->insert('isis_topology', $h);
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
    \s+             # space
    ($INTERFACE)    # interface ($2)
    \s+
    \d+             # circuit id
    \s+
    (\w+)           # state ($3)
  }xmso;

  my $RE_ISIS_CONT = qr{
    ^
    ([-.\p{Alnum}]+)   # remainder of hostname ($1)
    \*?     # optional star
    \s*     # optional whitespace
    $
  }xmso;

  my $h;

  my $flush = sub {
    # make sure we have a valid hostname (it might've been picked up
    # from several lines).
    if ($h->{neighbour} =~ $HOSTNAME) {
      $self->db->insert('isis_neighbour', $h);
      $self->log->insert('isis_neighbour', $h);
    }

    undef $h;
  };

  my $cmd = q{display isis peer};
  $self->log->info("running '$cmd'");
  foreach my $line ($self->cli->cmd($cmd)) {
    chomp($line);

    # Example output:
    #
    # System Id     Interface          Circuit Id        State HoldTime Type     PRI
    # --------------------------------------------------------------------------------
    # trondh-TDJERN-p GE1/0/2            0000000000         Up   29s      L2       --
    # e1*
    # trondheim-pe1   GE1/0/3            0000000000         Up   21s      L2       --
    # cr2.sve20*      GE1/0/4            0000000002         Up   26s      L2       --
    # trondh-PRINSG39 GE1/0/7            0000000000         Up   30s      L2       --
    # -pe2*
    #
    # Total Peer(s): 4
    #

    for ($line) {
      when (/$RE_ISIS/) {
        # Flush data...
        $flush->() if $h;

        # ..and cache new data
        $h = {neighbour => $1, interface => $2, state => lc($3)};
      }

      when (/$RE_ISIS_CONT/) {
        # Pad neighbour
        $h->{neighbour} .= $1;
      }

      default {
        $flush->() if $h;
      }
    }
  }

  return $AUDIT_OK;
}

##### BGP summary #####

sub bgp {
  my ($self) = @_;

  my ($cmd, $peer, $asn, $vrf, $afi);

  my $RE_BGP_v4 = qr{
    ^
    \s*
    ($RE{net}{IPv4})   # peer ($1)
    \s+
    \d+                # bgp version
    \s+
    (\d+)              # asn ($2)
    .*?                # filler
    (\d+)              # prefixes ($3)
    $
  }xmso;

  # do ipv4 first
  $cmd = q{display bgp peer};
  $self->log->info("running '$cmd'");
  foreach my $line ($self->cli->cmd($cmd)) {
    chomp($line);

    # Example output:
    #
    # Peer            V          AS  MsgRcvd  MsgSent  OutQ  Up/Down       State  PrefRcv
    # 10.60.2.2       4        1600        0        0     0 00:00:20        Idle        0
    #

    for ($line) {
      when (/$RE_BGP_v4/) {
        my $h = {peer => $1, asn => $2, afi => 'ipv4', prefixes => $3};

        $self->db->insert('bgp', $h);
        $self->log->insert('bgp', $h);
      }
    }
  }

  # then ipv6
  my $RE_BGP_v6 = qr{
    ^
    \s*
    ($IPv6_re)  # peer ($1)
    \s+
    \d+         # bgp version
    \s+
    (\d+)       # asn ($2)
    .*?         # filler
    (\d+)       # prefixes ($3)
    $
  }xmso;

  $cmd = q{display bgp ipv6 peer};
  $self->log->info("running '$cmd'");
  foreach my $line ($self->cli->cmd($cmd)) {
    chomp($line);

    # Example output
    # Peer            V          AS  MsgRcvd  MsgSent  OutQ  Up/Down       State  PrefRcv
    # 2001:DB8::1     4        1600        0        0     0 00:04:44        Idle        0
    # 2001:DB8:DEAD:BEEF:F00:F00:F00:F00 4        1601        0        0     0 00:02:45        Idle        0

    for ($line) {
      when (/$RE_BGP_v6/) {
        my $h = {peer => lc($1), asn => $2, afi => 'ipv6', prefixes => $3};

        $self->db->insert('bgp', $h);
        $self->log->insert('bgp', $h);
      }
    }
  }

  # and finally vpnv4
  my $RE_BGP_vpnv4 = qr{
    ^
    \s*
    ($RE{net}{IPv4})   # peer ($1)
    \s+
    \d+                # BGP version
    \s+
    (\d+)              # asn ($2)
    .*?                # filler
    (\d+)              # prefixes ($3)
    $
  }xmso;

  $cmd = q{display bgp vpnv4 all peer};
  $self->log->info("running '$cmd'");
  foreach my $line ($self->cli->cmd($cmd)) {
    chomp($line);

    # Example command output:
    #
    # BGP local router ID : 172.16.1.22
    # Local AS number : 1
    # Total number of peers : 2                 Peers in established state : 0
    #
    #  Peer            V          AS  MsgRcvd  MsgSent  OutQ  Up/Down       State  PrefRcv
    #  172.16.1.2      4           1        0        0     0 00:00:59      Active        0
    #
    #  Peer of IPv4-family for vpn instance :
    #
    #  VPN-Instance foo, Router ID 172.16.1.22:
    #  Peer            V          AS  MsgRcvd  MsgSent  OutQ  Up/Down       State  PrefRcv
    #  10.60.1.1       4        1600        0        0     0 00:03:22        Idle        0

    for ($line) {
      # VRF info
      when (/VPN-Instance \s+ (\S+)/) {
        $vrf = $1;
      }

      # peering
      when (/$RE_BGP_vpnv4/) {
        my $h = {peer => $1, asn => $2, afi => $vrf ? 'ipv4' : 'vpnv4',
          vrf => $vrf,};

        $self->db->insert('bgp', $h);
        $self->log->insert('bgp', $h);
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

  # if that failed try again with huawei mib
#  return $AUDIT_OK if $self->snmp->vrf($cb, $oid->{'vrf'});

  # if we got here, there are no data
  return $AUDIT_NODATA;
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

  # if that failed try again with huawei mib
  return $AUDIT_OK if $self->snmp->pwe3($cb, $oid->{'pwe3'});

  # Resort to old fashioned screen scraping
  return $self->pwe3_cli;
}

sub pwe3_cli {
  my $self = shift;

  my $result = $AUDIT_NODATA;
  my $entry;

  my $flush = sub {
    $self->db->insert('pwe3', $entry);
    $self->log->insert('pwe3', $entry);

    $result = $AUDIT_OK;

    undef $entry;
  };

  my $get_value = sub {
    my $line = shift;
    my (undef, $val) = split /:/, $line;
    $val =~ s/^\s+|\s+$//g;
    return $val;
  };

  my $cmd = q{display mpls l2vc brief};
  $self->log->info("running '$cmd'");
  foreach my $line ($self->cli->cmd($cmd)) {
    chomp($line);

    # Example output:
    #
    # Total LDP VC : 11     5 up       6 down
    #
    # *Client Interface     : GigabitEthernet0/3/8.22220100
    #  Administrator PW     : no
    #  AC status            : up
    #  VC state             : down
    #  Label state          : 0
    #  Token state          : 0
    #  VC ID                : 21163333
    #  VC Type              : VLAN
    #  session state        : up
    #  Destination          : 172.16.1.13
    #  link state           : down
    #
    # *Client Interface     : GigabitEthernet0/3/8.789
    #  Administrator PW     : no
    #  AC status            : up
    #  VC state             : up
    #  Label state          : 0
    #  Token state          : 0
    #  VC ID                : 2822111100
    #  VC Type              : VLAN
    #  session state        : up
    #  Destination          : 172.16.1.10
    #  link state           : up
    #
    # *Client Interface     : GigabitEthernet0/3/8.13240242
    #  Administrator PW     : no
    #  AC status            : up
    #  VC state             : down
    #  Label state          : 0
    #  Token state          : 0
    #  VC ID                : 2802322201
    #  VC Type              : Ethernet
    #  session state        : up
    #  Destination          : 172.16.1.13
    #  link state           : down

    for ($line) {
      when (/^\s*$/) {
        # A new-line terminates a section, time to flush data
        $flush->() if $entry;
      }

      when (/Client \s Interface/x) {
        $entry->{interface} = $get_value->($line)
      }
      when (/Destination/x) {
        $entry->{peer} = gethostname($get_value->($line))
      }
      when (/VC \s state/x) { $entry->{status} = $get_value->($line) }
      when (/VC \s ID/x)    { $entry->{vcid}   = $get_value->($line) }
    }
  }

  # flush last $entry?
  $flush->() if $entry;

  return $result;
}

1;
