#
# Copyright (c) 2012, Per Carlson
#
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl 5.14. For more details,
# see the full text of the licenses in the directory LICENSES.
#

package Netaudit::Config;

=pod

=head1 NAME

Netaudit::Config - generic config file handling

=head1 SYNOPSIS

  use Netaudit::Config;

  my $cfg = Netaudit::Config->new(
    filename => $default,
  ) or die "Cannot find any config file\n";

  print "Using config file: $cfg->filename\n";

=head1 DESCRTPTION

Netaudit::Config serves as a config file handler
for both netaudit and netreport.
It tries to open the config file given in ->new, and
if that fails tries to find one in standard places.

The content of the config file must adhere to the 
specification in L<Config::Simple>.

=cut

use Mouse;
use List::Util qw{ first };
use File::Spec::Functions;
use Config::Simple;
use FindBin;

# search paths for config files
#<<< perltify, keep your fingers away!
my @CONFIGFILES = (
  'netaudit.conf',
  "$ENV{HOME}/.netaudit",
  '/usr/local/etc/netaudit.conf',
  '/etc/netaudit.conf',
);
#<<<


=head1 ATTRIBUTES

=head2 C<filename>

The C<filename> of the config file.
Can be included in the call to ->new.

=cut

has 'filename' => (
  is  => 'ro',
  isa => 'Str',
);


=head2 C<database>

The F<filename> the SQLite database is stored in.
Default is 'netaudit.db'.

=cut

has 'database' => (
  is       => 'ro',
  isa      => 'Str',
  init_arg => undef,
  default  => 'netaudit.db',
);


=head2 C<schema>

The SQLite schema file to use when creating new database files.

=cut

has 'schema' => (
  is       => 'ro',
  isa      => 'Str',
  init_arg => undef,
);


=head2 C<community>

The SNMP community.
Default is 'public'.

=cut

has 'community' => (
  is       => 'ro',
  isa      => 'Str',
  init_arg => undef,
  default  => 'public',
);


=head2 C<username>

The telnet C<username> to use.
Default is 'netaudit'.

=cut

has 'username' => (
  is       => 'ro',
  isa      => 'Str',
  init_arg => undef,
  default  => 'netaudit',
);


=head2 C<password>

The Telnet c>password> to use.
Default is ''.

=cut

has 'password' => (
  is       => 'rw',
  isa      => 'Str',
  init_arg => undef,
  default  => '',
);


=head2 C<range>

A reference to an array with IP-ranges.
Each IP-range iss given on the format 'prefix/prefix_length', 
i.e. '10.0.0.0/24'.
Default is an empty array reference.

=cut

has 'range' => (
  is       => 'ro',
  isa      => 'ArrayRef',
  init_arg => undef,
  default  => sub { [] },
);


=head1 METHODS

=head2 C<new>

  my $cfg = Netaudit::Config->new;

or

  my $cfg = Netaudit::Config->new(
    filename => $default_config_file
  );

Creates a new Netaudit::Config object.

Tries to find a configuration file to open at the following
paths, from first to last:

=over 2

=item * F<filename> specified in ->new

=item * F<netaudit.conf>

=item * F<~/.netaudit>

=item * F</usr/local/etc/netaudit.conf>

=item * F</etc/netaudit.conf>

=back

The first readable file found are used, i.e. there isn't a
hierarchy of config files.

=cut

sub BUILD {
  my $self = shift;

  # place filename attribute in new first in list (if given)
  unshift @CONFIGFILES, $self->{filename} if length $self->{filename};
  my $cf = first { -r $_ } @CONFIGFILES;
  die "No config file found\n" unless length $cf;

  my $cfg = Config::Simple->new($cf)
    or die "Failed to open $cf: ", Config::Simple->error(), "\n";

  # store teh config filename
  $self->{filename} = $cf;

  # set our attributes from the config file, overriding the
  # defaults
  $self->{database} = $cfg->param('database') || $self->{database};
  $self->{schema} = $cfg->param('schema')
    || catfile($FindBin::Bin, '../share/netaudit', 'schema.sql');
  $self->{community} = $cfg->param('community') || $self->{community};
  $self->{range}     = [$cfg->param('range')];
  $self->{username}  = $cfg->param('username') || $self->{username};
  $self->{password}  = $cfg->param('password') || $self->{password};

  return;
}

1;
