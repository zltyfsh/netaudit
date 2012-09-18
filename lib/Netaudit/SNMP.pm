#
# Copyright (c) 2012, Per Carlson
#
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl 5.14. For more details,
# see the full text of the licenses in the directory LICENSES.
#

package Netaudit::SNMP;

=pod

=head1 NAME

Netaudit::SNMP - SNMP framework and polling of standards MIBs

=head1 SYNOPSIS

  my $snmp = Netaudit::SNMP->new(
    hostname  => 'foo',
    community => 'bar',
  );

  my $sd = $snmp->sysdescr;

  print "value = ", $snmp->get($oid);

=head1 DESCRIPTION

Netaudit::SNMP provides a simple framework for C<get> an OID, C<walk> a SNMP-table 
and C<get_columns> from a SNMP-table.

Additionally there are ready made subs for collecting data from standard
SNMP-tables, such as C<sysdescr>, C<vpn>, C<pwe3> and C<interfaces>.

=cut

use Mouse;
use Net::SNMP;
use Carp;

use Netaudit::Constants;
use Netaudit::DNS;

# SNMP OIDs and values

my $oid = {
  # from SNMPv2 MIB
  'sysDescr'  => '.1.3.6.1.2.1.1.1.0',    # scalar

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

# From IF-MIB
my $if_status = {
  '1' => "up",
  '2' => "down",
  '3' => "testing",
  '4' => "unknown",
  '5' => "dormant",
  '6' => "notPresent",
  '7' => "lowerLayerDown",
};


# From PW-TC-STD-MIB
my $vc_status = {
  '1' => "up",
  '2' => "down",
  '3' => "testing",
  '4' => "dormant",
  '5' => "notPresent",
  '6' => "lowerLayerDown",
};

# From IP-MIB
my $ip_status = {
  '1' => "up",
  '2' => "down",
};

# From IANAifTypeMIB
my $if_types = [
  6,      # ethernetCsmacd, all ethernet-like interfaces, as per RFC3635
  24,     # softwareLoopback
  39,     # sonet, SONET or SDH
  131,    # tunnel, Encapsulation interface
  150,    # mplsTunnel, MPLS Tunnel Virtual Interface
  161,    # ieee8023adLag, IEEE 802.3ad Link Aggregate
  166,    # mpls
];

=head1 ATTRIBUTES

=head2 C<hostname>

The name of the host to open the SNMP-connection to.

=cut

has 'hostname' => (
  is       => 'ro',
  required => 1,
);

=head2 C<domain>

The "domain" of the SNMP-connection, i.e. the datagram protocol together
with the IP-address family.
Default is "udp/ipv4".

=cut

has 'domain' => (
  is      => 'ro',
  default => 'udp/ipv4',
);

=head2 C<community>

The SNMPv2c community.

=cut

has 'community' => (
  is      => 'ro',
  default => 'public',
);

=head2 C<session>

The internal Net::SNMP session object.

=cut

has 'session' => (
  is       => 'ro',
  isa      => 'Net::SNMP',
  init_arg => undef,
  writer   => '_session',
  lazy     => 1,
  builder  => '_build_session',
);


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


=head1 METHODS

=head2 C<new>

  $snmp = Netaudit::SNMP->new(
    hostname  => 'foo',
    community => 'bar'
  );

Creates a new Netaudit::SNMP object.
Required attributes are C<hostname> and C<community>, while
C<domain> is optional.

=head2 C<chr2str>

  $ascii = $snmp->chr2str('6.102.111.111.98.97.114');
  print $ascii;  # prints foobar

In some tables, ASCII text are encoded in the OID it self, i.e
as "length.ASCII.ASCII. ... .ASCII".
C<chr2str> convert such a "dotted string" to a plain string.

=cut

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


=head2 C<ip2dot>

  $ip = $snmp->ip2dot('0xC0020001');
  print $ip;   # prints 192.2.0.1

In SNMP sometimes IPv4-addresses are stored as a raw
32-bit integer, either in decimal format or in hex.
C<ip2dot> converts this integer to a normal "quad dotted"
string representation.

=cut

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


=head2 C<close>

Close the SNMP connection freeing the resources.

=cut

sub close {
  my ($self) = @_;

  $self->session->close() if $self->session;
  return;
}


=head2 C<walk>

  my $table_ref = $snmp->walk($oid);

Walks the SNMP (table) based at OID.
Returns an hashreference with the leading OID
stripped way.

=cut

sub walk {
  my ($self, $oid) = @_;

  # sanity checks
  croak "No SNMP session" unless $self->session;
  croak "No oid" unless $oid;

  my $href = $self->session->get_table(-baseoid => $oid);
  return $self->_strip_oid($oid, $href);
}


=head2 C<get>

  my $value = $snmp->get($oid);

Get a a single OID value.
Returns undef is the OID doesn't exist, else the 
value at the OID.

=cut

sub get {
  my ($self, $oid) = @_;

  # sanity checka
  croak "No SNMP session" unless $self->session;
  croak "No oid" unless $oid;

  my $href = $self->session->get_request(-varbindlist => [$oid]);
  return if (!defined($href) || $href->{$oid} eq 'noSuchObject');

  return $href->{$oid} || undef;
}


=head2 C<get_columns>

  my $col_ref = $snmp->get_columns($base_oid, $col1, $col2);

Get sepecified columns (indexes) in a SNMP table.
Returns a hash reference keyed by the columns.

=cut

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


=head2 C<sysdescr>

  my $sysdescr = $snmp->sysdescr;

Returns the sysDescr from SNMPv2 MIB.

=cut

sub sysdescr {
  my ($self) = @_;
  return $self->get($oid->{sysDescr});
}


=head2 C<interface>

  my $cb = sub {
    my $href = shift;
    foreach my ($k, $v) (each %$href) {
      print "$k : $href->{$k\n";
    }
  };

  my $interface = $snmp->interface($cb);

Walks the IF-MIB interfaces table and for each row returned
calls the callback C<cb> with the row (indexed by ifIndex) 
content as an hash reference.
The hash reference contain the following keys:

=over 2

=item C<descr>

The description of the interface (ifDescr)

=item C<mtu>

The interface MTU (ifMtu) 

=item C<speed>

The interface speed (ifHighSpeed) in bits per second. 

=item C<adminstatus>

The administrative status of the interface (ifAdminStatus) as
a string ("up", "down", "testing", "unknown", "dormant",
"notPresent", or "lowerLayerDown").

=item C<operstatus>

The operational status of the interface (ifOperStatus) as
a string ("up", "down", "testing", "unknown", "dormant",
"notPresent", or "lowerLayerDown").

=item C<ipv6status>

The IPv6 status of the interface (ipv6InterfaceEnableStatus from
IP-MIB) as a string ('up', or 'down').

=back

The table do only include interfaces of the following types (ifType):

=over 2

=item C<ethernetCsmacd>, ifType = 6

=item C<softwareLoopback>, ifType = 24

=item C<sonet>, ifType = 39

=item C<tunnel>, ifType = 131

=item C<mplsTunnel>, ifType = 150

=item C<iee8023adLag>, ifType = 161

=item C<mpls>, ifType = 166

=back

=cut

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
    next unless grep { $_ == $href->{'ifType'}->{$i} } @{$if_types};

    my $v6status = $href->{'ipv6InterfaceEnableStatus'}->{$i} || "";

    # call callback with our data
    &$cb({
      descr       => $href->{'ifDescr'}->{$i},
      mtu         => $href->{'ifMtu'}->{$i},
      adminstatus => $if_status->{$href->{'ifAdminStatus'}->{$i}},
      operstatus  => $if_status->{$href->{'ifOperStatus'}->{$i}},

      #	ipv4status  => $ipEnableStatus { $v6status },
      ipv6status => $ip_status->{$v6status},
      speed      => $href->{'ifHighSpeed'}->{$i},
    });
  }

  return 1;
}


=head2 C<pwe3>

  my $cb = sub {
    my $href = shift;
    foreach my ($k, $v) (each %$href) {
      print "$k : $href->{$k\n";
    }
  };

  my $pwe3 = $snmp->pwe3($cb);

Walks pwTable in PW-STD-MIB and for each row returned
calls the callback C<cb> with the row (indexed by pwIndex) content as an 
hash reference.
The hash reference contain the following keys:

=over 2

=item C<interface>

The name of the interface the pseudo-wire is attached
to (pwName).

=item C<peer>

The hostname of the remote peer.
As pwPeerAddr is an (encoded) IP-address, the value is first
decoded to an IP(v4)-address, which is then tried resolved to
a hostname.

=item C<status>

The cwoperationaladministrative status of the pseudewire (pwOperStatus) 
as a string ("up", "down", "testing", "dormant", "notPresent", or 
"lowerLayerDown").

=back

A reference to a MIB-table might be supplied as a second argument
to the method.
This MIB-table must be a hash reference with the following keys
with the related OID as value:

=over 2

=item C<ID>

The OID of the index in the table

=item C<Name>

The OID where the name of the interface the pseudowire is
ättached to.

=item C<OperStat>

The OID where the operational status of the pseudowire.
Must adhere to the same textual convention as PwOperStatusTC
in PW-STD-TC-MIB.

=item C<PeerAddr>

The OID where the address of the remote peer is stored.
Must be an InetAddress as specified in INET-ADDRESS-MIB.

=back

=cut

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
      status    => $vc_status->{$status},
    });
  }

  return 1;
}


=head2 C<vrf>

  my $cb = sub {
    my $href = shift;
    foreach my ($k, $v) (each %$href) {
      print "$k : $href->{$k\n";
    }
  };

  my $vrf = $snmp->vrf($cb);

Walks mplsL3VpnVrfTable in MPLS-L3VPN-STD-MIB and for each row returned
(indexed by mplsL3VpnVrfname) calls the callback C<cb> with the row content 
as an hash reference.
The hash reference contain the following keys:

=over 2

=item C<vrf>

The human-readable name of the VRF.

=item C<active>

The total number of interfaces connected to this VRF with
ifOperStatus = up(1).

=item C<associated>

The total number of interfaces connected to this VRF
(independent of ifOperStatus type).

=back

A reference to a MIB-table might be supplied as a second argument
to the method.
This MIB-table must be a hash reference with the following keys
with the related OID as value:

=over 2

=item C<ActiveInterfaces>

The OID where the number of active interfaces are stored.

=item C<AssociatedInterfaces>

The OID where the number of active interfaces are stored.

=back

=cut

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


# helper methods

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


__PACKAGE__->meta->make_immutable;

1;

