#
# Copyright (c) 2012, Per Carlson
#
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl 5.14. For more details,
# see the full text of the licenses in the directory LICENSES.
#

package Netaudit::DNS;

use strict;
use warnings;
use Socket qw{ inet_aton AF_INET };

use base qw{ Exporter };
our @EXPORT = qw{
  gethostname
};

sub gethostname {
  my ($addr) = @_;

  my $iaddr = inet_aton($addr);
  my $name = gethostbyaddr($iaddr, AF_INET);

  return defined $name ? $name : $addr;
}

1;
