#
# Copyright (c) 2012, Per Carlson
#
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl 5.14. For more details,
# see the full text of the licenses in the directory LICENSES.
#

package Netaudit::SNMP;

use Mouse;
use Net::SNMP;
use Carp;

use Netaudit::Constants;
use Netaudit::DNS;

# SNMP OIDs

my $oid = {
  # from SNMPv2 MIB
  'sysDescr'  => '.1.3.6.1.2.1.1.1.0',    # scalar
  'sysUptime' => '.1.3.6.1.2.1.1.3.0',    # scalar

  'interface' => {
    # from IF-MIB
    'ifIndex'       => '.1.3.6.1.2.1.2.2.1.1',
    'ifDescr'       => '.1.3.6.1.2.1.2.2.1.2',
    'ifType'        => '.1.3.6.1.2.1.2.2.1.3',
    'ifMtu'         => '.1.3.6.1.2.1.2.2.1.4',
    'ifAdminStatus' => '.1.3.6.1.2.1.2.2.1.7',
    'ifOperStatus'  => '.1.3.6.1.2.1.2.2.1.8',
    'ifHighSpeed'   => '.1.3.6.1.2.1.31.1.1.1.15',

    # from IP-MIB
    # no point of enabling this, no device supports it any way
    # 'ipv4InterfaceEnableStatus' => '.1.3.6.1.2.1.4.28.1.3',
    'ipv6InterfaceEnableStatus' => '.1.3.6.1.2.1.4.30.1.5',
  },

  'vrf' => {
    # From MPLS-L3VPN-STD-MIB
    'ActiveInterfaces'     => '.1.3.6.1.2.1.10.166.11.1.2.2.1.7',
    'AssociatedInterfaces' => '.1.3.6.1.2.1.10.166.11.1.2.2.1.8',
  },

  'pwe3' => {
    # PW-STD-MIB
    'PeerAddr'   => '.1.3.6.1.2.1.10.246.1.2.1.9',
    'ID'         => '.1.3.6.1.2.1.10.246.1.2.1.12',
    'Name'       => '.1.3.6.1.2.1.10.246.1.2.1.32',
    'OperStatus' => '.1.3.6.1.2.1.10.246.1.2.1.38',
  },
};

#-- Attributes

has 'hostname' => (
  is       => 'ro',
  required => 1,
);

has 'domain' => (
  is      => 'ro',
  default => 'udp/ipv4',
);

has 'community' => (
  is      => 'ro',
  default => 'public',
);

has 'session' => (
  is       => 'ro',
  isa      => 'Net::SNMP',
  init_arg => undef,
  writer   => '_session',
  lazy     => 1,
  builder  => '_build_session',
);

has 'if_status' => (
  is        => 'ro',
  isa       => 'HashRef',
  init_args => undef,
  # From IF-MIB
  default => sub {
    {
      '1' => "up",
      '2' => "down",
      '3' => "testing",
      '4' => "unknown",
      '5' => "dormant",
      '6' => "notPresent",
      '7' => "lowerLayerDown",
    }
  },
);

has 'vc_status' => (
  is        => 'ro',
  isa       => 'HashRef',
  init_args => undef,
  # From PW-TC-STD-MIB
  default => sub {
    {
      '1' => "up",
      '2' => "down",
      '3' => "testing",
      '4' => "dormant",
      '5' => "notPresent",
      '6' => "lowerLayerDown",
    }
  },
);

has 'ip_status' => (
  is        => 'ro',
  isa       => 'HashRef',
  init_args => undef,
  # From IP-MIB
  default => sub {
    {
      '1' => "up",
      '2' => "down",
    }
  },
);

has 'if_types' => (
  is        => 'ro',
  isa       => 'ArrayRef',
  init_args => undef,
  # From IANAifTypeMIB
  default => sub {
    [
      6,      # ethernetCsmacd, all ethernet-like interfaces, as per RFC3635
      24,     # softwareLoopback
      39,     # sonet, SONET or SDH
      131,    # tunnel, Encapsulation interface
      150,    # mplsTunnel, MPLS Tunnel Virtual Interface
      161,    # ieee8023adLag, IEEE 802.3ad Link Aggregate
      166,    # mpls
    ]
  },
);

#---

sub _build_session {
  my $self = shift;

  my ($s, $e) = Net::SNMP->session(
    -domain    => $self->domain,
    -hostname  => $self->hostname,
    -community => $self->community,
    -version   => '2c',
    -timeout   => 1,
    -retries   => 2,
  );

  return unless $s;
  return $self->_session($s);
}

#---

sub chr2str {
  my $self = shift;

  # get char by char
  my @a = split(/\./, shift);

  # first entry is length. we don't need that
  shift @a;

  my $str;
  map { $str .= chr($_) } @a;

  return $str;
}

#---

# convert a numeric ip-address to dotted decimal
sub ip2dot {
  my ($self, $ip) = @_;
  my ($b1, $b2, $b3, $b4);

  # got a hex string? if so, get a 10base value
  $ip = hex($ip) if ($ip =~ /^0x/);

  $b1 = $ip % 256;
  $ip = $ip >> 8;
  $b2 = $ip % 256;
  $ip = $ip >> 8;

  $b3 = $ip % 256;
  $ip = $ip >> 8;
  $b4 = $ip;

  return sprintf("%d.%d.%d.%d", $b4, $b3, $b2, $b1);
}

#---

sub _strip_oid {
  my ($self, $baseoid, $href) = @_;

  # nothing to do on an empty data set
  return unless $href;

  # sanity checks
  croak "No baseoid" unless $baseoid;
  croak "SNMP data isn't a hashref" unless ref($href) eq 'HASH';

  my $result = undef;
  foreach my $k (keys %{$href}) {
    my ($index) = ($k =~ m{ $baseoid \. (.*) }xms);
    $result->{$index} = $href->{$k} if $index;
  }

  return $result;
}

#---

sub close {
  my ($self) = @_;

  $self->session->close() if $self->session;
  return;
}

#---

sub walk {
  my ($self, $oid) = @_;

  # sanity checks
  croak "No SNMP session" unless $self->session;
  croak "No oid" unless $oid;

  my $href = $self->session->get_table(-baseoid => $oid);
  return $self->_strip_oid($oid, $href);
}

#---

sub get {
  my ($self, $oid) = @_;

  # sanity checka
  croak "No SNMP session" unless $self->session;
  croak "No oid" unless $oid;

  my $href = $self->session->get_request(-varbindlist => [$oid]);
  return if (!defined($href) || $href->{$oid} eq 'noSuchObject');

  return $href->{$oid} || undef;
}

#---

sub get_columns {
  my ($self, $baseoid, @columns) = @_;

  # sanity checks
  croak "No SNMP session" unless $self->session;
  croak "No baseoid"      unless $baseoid;
  croak "No columns"      unless @columns;

  my @oids = map { $baseoid . "." . $_ } @columns;

  my $href = $self->session->get_entries(-columns => \@oids);
  return $self->_strip_oid($baseoid, $href);
}

#---

sub sysdescr {
  my ($self) = @_;
  return $self->get($oid->{sysDescr});
}

#---

sub interface {
  my ($self, $cb, $mib) = @_;

  # sanity checks
  croak "No SNMP session"           unless $self->session;
  croak "No callback"               unless $cb;
  croak "Callback isn't a code ref" unless ref($cb) eq 'CODE';

  # use standard mib if not given
  $mib ||= $oid->{'interface'};

  my $href;

  # walk all mib trees
  foreach my $k (keys %{$mib}) {
    $href->{$k} = $self->walk($mib->{$k});
  }

  return unless $href;

  # gather the information based on ifIndex
  foreach my $i (keys %{$href->{'ifIndex'}}) {
    # we are only interested in interfaces having a ifType
    # matching an item in the if_types list
    next unless grep { $_ == $href->{'ifType'}->{$i} } @{$self->if_types};

    my $v6status = $href->{'ipv6InterfaceEnableStatus'}->{$i} || "";

    # call callback with our data
    &$cb({
      descr       => $href->{'ifDescr'}->{$i},
      mtu         => $href->{'ifMtu'}->{$i},
      adminstatus => $self->if_status->{$href->{'ifAdminStatus'}->{$i}},
      operstatus  => $self->if_status->{$href->{'ifOperStatus'}->{$i}},

      #	ipv4status  => $ipEnableStatus { $v6status },
      ipv6status => $self->ip_status->{$v6status},
      speed      => $href->{'ifHighSpeed'}->{$i},
    });
  }

  return 1;
}

#---

sub pwe3 {
  my ($self, $cb, $mib) = @_;

  # sanity checks
  croak "No SNMP session"           unless $self->session;
  croak "No callback"               unless $cb;
  croak "Callback isn't a code ref" unless ref($cb) eq 'CODE';

  # set default mib
  $mib ||= $oid->{'pwe3'};

  # walk the ID part of the tree
  my $href = $self->walk($mib->{'ID'});
  return unless $href;

  # we need to index things by the VCid (don't trust the SNMP index
  # being deterministic)
  my %index = ();
  foreach (keys %{$href}) {
    $index{$href->{$_}} = $_;
  }

  foreach my $vcid (keys %index) {
    my ($i, $ifname, $status, $peer);
    $i      = $index{$vcid};
    $ifname = $self->get($mib->{'Name'} . ".$i");
    $status = $self->get($mib->{'OperStatus'} . ".$i");
    $peer   = $self->get($mib->{'PeerAddr'} . ".$i");
    $peer   = $self->ip2dot($peer);
    $peer   = gethostname($peer);

    &$cb({
      peer      => $peer,
      interface => $ifname,
      status    => $self->vc_status->{$status},
    });
  }

  return 1;
}

#---

sub vrf {
  my ($self, $cb, $mib) = @_;

  # sanity checks
  croak "No SNMP session"           unless $self->session;
  croak "No callback"               unless $cb;
  croak "Callback isn't a code ref" unless ref($cb) eq 'CODE';

  # set default mib
  $mib ||= $oid->{'vrf'};

  my $vrfs_active = $self->walk($mib->{'ActiveInterfaces'});
  return unless $vrfs_active;

  my $vrfs_assoc = $self->walk($mib->{'AssociatedInterfaces'});

  foreach my $k (keys %{$vrfs_active}) {
    &$cb({
      vrf        => $self->chr2str($k),
      active     => $vrfs_active->{$k} || 0,
      associated => $vrfs_assoc->{$k}  || 0,
    });
  }

  return 1;
}

#---

__PACKAGE__->meta->make_immutable;

1;

