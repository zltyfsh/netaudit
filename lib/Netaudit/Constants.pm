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

use version; our $VERSION = qv('3.0.3');

use base qw{ Exporter };
our @EXPORT = qw{
  $VERSION
  $AUDIT_OK
  $AUDIT_NODATA
  $AUDIT_FAIL
  $HOSTNAME
};

use Readonly;

# Success/failure codes for all audit subs
Readonly our $AUDIT_FAIL   => 0;
Readonly our $AUDIT_OK     => 1;
Readonly our $AUDIT_NODATA => 2;

# A generic representaion of a hostname
Readonly our $HOSTNAME => qr/
  (?:
    \p{Alnum}+ - \p{Alnum}+ - \p{Alnum}+   # BaneTele model
    |
    \p{Alnum}+ - \p{Alnum}+                # Pronea model
    |
    \p{Alnum}+ \. \p{Alnum}+               # Catch model
    |
    \p{Alnum}+                             # Labben model
  )
/xms;

1;
