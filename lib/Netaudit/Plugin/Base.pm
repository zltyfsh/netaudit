#
# Copyright (c) 2012, Per Carlson
#
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl 5.14. For more details,
# see the full text of the licenses in the directory LICENSES.
#

package Netaudit::Plugin::Base;

use Mojo::Base -base;
use Carp;

# attributes

has [ qw{ db cli snmp } ];

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

1;

