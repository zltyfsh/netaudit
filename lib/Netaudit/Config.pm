#
# Copyright 2012,2013,2014 Per Carlson
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

use Mojo::Base -base;
use List::Util qw{ first };
use File::Spec::Functions;
use Config::Simple;

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

has 'filename';


# private attributes

# The filename the SQLite database is stored in.
# Default is 'netaudit.db'.
has 'database' => 'netaudit.db';


# The SNMP community.  Default is 'public'.
has 'community' => 'public';


# The telnet username to use. Default is 'netaudit'.
has 'username' => 'netaudit';


# The Telnet password to use.
has 'password';


# A reference to an array with IP-ranges.
# Each IP-range is given on the format 'prefix/prefix_length',
# i.e. '10.0.0.0/24'.
# Default is an empty array reference.
has 'range' => sub { [] };

# The telnet timeout
has 'timeout' => 30;

# the log_level to use. default is "error"
has 'log_level' => 'error';


# the log_file to use. default is /dev/null
has 'log_file';


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

The first readable file found is used, i.e. there isn't a
hierarchy of config files.

=cut

sub new {
  my $self = shift->SUPER::new(@_);

  # place filename attribute in new first in list (if given)
  unshift @CONFIGFILES, $self->filename if length $self->filename;
  my $cf = first { -r $_ } @CONFIGFILES;
  die "No config file found\n" unless length $cf;

  my $cfg = Config::Simple->new($cf)
    or die "Failed to open $cf: ", Config::Simple->error(), "\n";

  # store the config filename
  $self->filename($cf);

  # set our attributes from the config file, overriding the
  # defaults
  $self->database($cfg->param('database'))   if $cfg->param('database');
  $self->community($cfg->param('community')) if $cfg->param('community');
  $self->range([$cfg->param('range')])       if $cfg->param('range');
  $self->username($cfg->param('username'))   if $cfg->param('username');
  $self->password($cfg->param('password'))   if $cfg->param('password');
  $self->log_level($cfg->param('log_level')) if $cfg->param('log_level');
  $self->log_file($cfg->param('log_file'))   if $cfg->param('log_file');
  $self->timeout($cfg->param('timeout'))     if $cfg->param('timeout');

  return $self;
}

1;
