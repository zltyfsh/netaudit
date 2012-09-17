#
# Copyright (c) 2012, Per Carlson
#
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl 5.14. For more details,
# see the full text of the licenses in the directory LICENSES.
#

package Netaudit::Plugin::Base;

use Mouse;
use Carp;

# attributes

has 'db' => (
  is       => 'ro',
  isa      => 'Netaudit::Db',
  required => 1,
);

has 'cli' => (
  is       => 'ro',
  isa      => 'Net::Telnet',
  required => 1,
);

has 'snmp' => (
  is       => 'ro',
  isa      => 'Netaudit::SNMP',
  required => 1,
);

# methods

sub handles { return }

sub prompt { return }

# these MUST be overridden by childs

sub route_summary { croak "route_summary isn't overridden" }

sub isis_topology { croak "isis_topology isn't overridden" }

sub isis_neighbour { croak "isis_neighbour isn't overridden" }

sub bgp { croak "bgp isn't overridden" }

sub interface { croak "interface isn't overridden" }

sub vrf { croak "vrf isn't overridden" }

sub pwe3 { croak "pwe3 isn't overridden" }

__PACKAGE__->meta->make_immutable;

1;

