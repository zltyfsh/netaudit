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

# SNMP OIDs

my %oid = (
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

    'stdVPN' => {
        # From MPLS-L3VPN-STD-MIB
        'ActiveInterfaces'     => '.1.3.6.1.2.1.10.166.11.1.2.2.1.7',
        'AssociatedInterfaces' => '.1.3.6.1.2.1.10.166.11.1.2.2.1.8',
    },

    'ciscoVPN' => {
        # Cisco experimental L3VPN-MIB
        'ConfiguredVrfs'       => '.1.3.6.1.3.118.1.1.1.0',     # scalar
        'ActiveVrfs'           => '.1.3.6.1.3.118.1.1.2.0',     # scalar
        'ConnectedInterfaces'  => '.1.3.6.1.3.118.1.1.3.0',     # scalar
        'ActiveInterfaces'     => '.1.3.6.1.3.118.1.2.2.1.6',
        'AssociatedInterfaces' => '.1.3.6.1.3.118.1.2.2.1.7',
    },

    'stdPW' => {
        # PW-STD-MIB
        'PeerAddr'   => '.1.3.6.1.2.1.10.246.1.2.1.9',
        'ID'         => '.1.3.6.1.2.1.10.246.1.2.1.12',
        'Name'       => '.1.3.6.1.2.1.10.246.1.2.1.32',
        'OperStatus' => '.1.3.6.1.2.1.10.246.1.2.1.38',
    },

    'ciscoPW' => {
        # Cisco experimental PW MIB
        'PeerAddr'   => '.1.3.6.1.4.1.9.10.106.1.2.1.9',
        'ID'         => '.1.3.6.1.4.1.9.10.106.1.2.1.10',
        'Name'       => '.1.3.6.1.4.1.9.10.106.1.2.1.21',
        'OperStatus' => '.1.3.6.1.4.1.9.10.106.1.2.1.26',
    },
);

# From IF-MIB
my %ifOperStatus = (
    1 => "up",
    2 => "down",
    3 => "testing",
    4 => "unknown",
    5 => "dormant",
    6 => "notPresent",
    7 => "lowerLayerDown",
);

# From IP-MIB
my %ipEnableStatus = (
    1   => "up",
    2   => "down",
    doh => "",
);

# From PW-TC-STD-MIB
my %VcOperStatus = (
    1 => "up",
    2 => "down",
    3 => "testing",
    4 => "dormant",
    5 => "notPresent",
    6 => "lowerLayerDown",
);

# From IANAifTypeMIB
my @ifTypes = (
    6 ,  # ethernetCsmacd, for all ethernet-like interfaces regardless of speed, as per RFC3635
    24,  # softwareLoopback
    39,  # sonet, SONET or SDH
    131, # tunnel, Encapsulation interface
    150, # mplsTunnel, MPLS Tunnel Virtual Interface
    161, # ieee8023adLag, IEEE 802.3ad Link Aggregate
    166, # mpls
);

#-- Attributes

has 'hostname'  => ( is => 'ro', required => 1 );
has 'domain'    => ( is => 'ro', default  => 'udp/ipv4' );
has 'community' => ( is => 'ro', default  => 'public' );
has 'session'   => (
    is       => 'ro',
    isa      => 'Net::SNMP',
    init_arg => undef,
    writer   => '_session',
    lazy     => 1,
    builder  => '_build_session',
);

#---

sub _build_session {
    my $self = shift;

    my ( $s, $e ) = Net::SNMP->session(
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

sub _chr2str {
    # get char by char
    my @a = split( /\./, shift );

    # first entry is length. we don't need that
    shift @a;

    my $str = '';
    foreach (@a) {
        $str .= chr($_);
    }

    return $str;
}

#---

# convert a numeric ip-address to dotted decimal
sub _ip2dot {
    my ($ip) = @_;
    my ( $b1, $b2, $b3, $b4 );

    # got a hex string? if so, get a 10base value
    $ip = hex($ip) if ( $ip =~ /^0x/ );

    $b1 = $ip % 256;
    $ip = $ip >> 8;
    $b2 = $ip % 256;
    $ip = $ip >> 8;

    $b3 = $ip % 256;
    $ip = $ip >> 8;
    $b4 = $ip;

    return sprintf( "%d.%d.%d.%d", $b4, $b3, $b2, $b1 );
}

#---

sub close {
    my $self = shift;

    $self->session->close() if $self->session;
	return;
}

#---

sub walk {
    my ( $self, $oid ) = @_;

    # sanity check
    return unless $self->session && $oid;

    my $href = $self->session->get_table( -baseoid => $oid );
    return unless $href;

    my $result = undef;
    foreach my $k ( keys %{$href} ) {
        my ($index) = ( $k =~ m!$oid\.(.*)! );
        $result->{$index} = $href->{$k} if ( defined $index );
    }

    return $result;
}

#---

sub get {
    my ( $self, $oid ) = @_;

    # sanity check
    return unless $self->session && $oid;

    my @oids = ($oid);

    my $href = $self->session->get_request( -varbindlist => \@oids );
    return if ( !defined($href) || $href->{$oid} eq 'noSuchObject' );

    return $href->{$oid} || undef;
}

#---

sub sysdescr {
    my ($self) = @_;
    return $self->get( $oid{sysDescr} );
}

#---

sub interfaces {
    my ( $self, $db ) = @_;
    my (%mib);

    # walk all mib trees
    foreach my $k ( keys %{ $oid{'interface'} } ) {
        $mib{$k} = $self->walk( $oid{'interface'}{$k} );
    }

    return $AUDIT_NODATA unless %mib;

    # gather the information based on ifIndex
    foreach my $i ( keys %{ $mib{'ifIndex'} } ) {
        # we are only interested in interfaces having a ifType
        # matching an item in the @ifTypes list
        next unless scalar grep { $_ == $mib{'ifType'}{$i} } @ifTypes;

        my $v6status = $mib{'ipv6InterfaceEnableStatus'}{$i} || "";
        $db->insert(
            'interface',
            {
                descr       => $mib{'ifDescr'}{$i},
                mtu         => $mib{'ifMtu'}{$i},
                adminstatus => $ifOperStatus{ $mib{'ifAdminStatus'}{$i} },
                operstatus  => $ifOperStatus{ $mib{'ifOperStatus'}{$i} },
                #		  ipv4status  => $ipEnableStatus { $v6status },
                ipv6status => $ipEnableStatus{$v6status},
                speed      => $mib{'ifHighSpeed'}{$i},
            }
        );
    }
    return $AUDIT_OK;
}

#---

sub pwe3 {
    my ( $self, $db ) = @_;

    my $mib  = 'stdPW';
    my $href = $self->walk( $oid{$mib}{'ID'} );
    if ( !$href ) {
        # error, std mib isn't supported
        # try cisco mib
        $mib  = 'ciscoPW';
        $href = $self->walk( $oid{$mib}{'ID'} );

        # if neither standard nor cisco mib exists, we have little
        # else to do than return
        return $AUDIT_NODATA unless $href;
    }

    # we need to index things by the VCid (don't trust the SNMP index
    # being deterministic)
    my %index = ();
    foreach ( keys %{$href} ) {
        $index{ $href->{$_} } = $_;
    }

    my @array;

    foreach my $vcid ( keys %index ) {
        my ( $i, $ifname, $status, $peer );
        $i      = $index{$vcid};
        $ifname = $self->get( $oid{$mib}{'Name'} . ".$i" );
        $status = $self->get( $oid{$mib}{'OperStatus'} . ".$i" );
        $peer   = $self->get( $oid{$mib}{'PeerAddr'} . ".$i" );
        $peer   = _ip2dot($peer);

        $db->insert(
            'pwe3',
            {
                peer      => $peer,
                interface => $ifname,
                status    => $VcOperStatus{$status},
            }
        );
    }

    return $AUDIT_OK;
}

#---

sub vrfs {
    my ( $self, $db ) = @_;
    my ( $vrfs_active, $vrfs_assoc, @array );

    # there are two MIB trees get data from, one standardized
    # and one cisco proprietary.
    my $mib = 'stdVPN';
    if ( !$self->get( $oid{$mib}{'ConfiguredVrfs'} ) ) {
        # error, std mib isn't supported
        # try cisco mib
        $mib = 'ciscoVPN';

        # if neither standard nor cisco mib exists, we have little
        # else to do than return
        return $AUDIT_NODATA unless $self->get( $oid{$mib}{'ConfiguredVrfs'} );
    }

    $vrfs_active = $self->walk( $oid{$mib}{'ActiveInterfaces'} );
    $vrfs_assoc  = $self->walk( $oid{$mib}{'AssociatedInterfaces'} );

    foreach my $k ( keys %{$vrfs_active} ) {
        $db->insert(
            'vrf',
            {
                vrf        => _chr2str($k),
                active     => $vrfs_active->{$k} || 0,
                associated => $vrfs_assoc->{$k} || 0,
            }
        );
    }
    return $AUDIT_OK;
}

#---

1;

