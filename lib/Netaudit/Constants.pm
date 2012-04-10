#
# Copyright (c) 2012, Per Carlson
#
# This program is free software; you can redistribute it and/or 
# modify it under the same terms as Perl 5.14. For more details, 
# see the full text of the licenses in the directory LICENSES.
#

package Netaudit::Constants;

use strict;
use warnings;
use Readonly;

use base qw{ Exporter };
our @EXPORT = qw{ $VERSION $AUDIT_OK $AUDIT_NODATA $AUDIT_FAIL $SCHEMA_VER };

our $VERSION = 1.00;

# Success/failure codes for all audit subs
Readonly my $AUDIT_FAIL   => 0;
Readonly my $AUDIT_OK     => 1;
Readonly my $AUDIT_NODATA => 2;

# Our schema version
Readonly my $SCHEMA_VER => 1;

1;
