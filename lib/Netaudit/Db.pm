#
# Copyright (c) 2012, Per Carlson
#
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl 5.14. For more details,
# see the full text of the licenses in the directory LICENSES.
#

package Netaudit::Db;

=pod 

=head1 NAME

Netaudit::Db - SQLite3 datebase interaction

=head1 SYNOPSIS

  use Netaudit::Db;

  my $dbh = Netaudit::Db->new(
    database => 'my.db',
    schema   => 'schema.sql',
  );

  $dbh->newrun;
  $dbh->hostname('foo');

  $dbh->insert('table', $href);

  $dbh->disconnect;

=head1 DESCRIPTION

Netaudit::Db is mostly a wrapper around DBI to make selects a bit 
easier.
Probably this would be obtained even easier by using DBIx::Simple,
but that's an opprotunity in future releases :-)

Additionally there are some methods for inserting tailored data into
the various tables, e.g C<newrun>, and C<insert>.

=cut

use Mouse;
use Carp;
use DBI;
use Netaudit::Constants;
use Readonly;

Readonly my $SCHEMA_VER => 1;

=head1 ATTRIBUTES

=head2 C<database>

The filename with the SQLite3 database.

=cut

has 'database' => (
  is       => 'rw',
  isa      => 'Str',
  required => 1,
);


=head2 C<schema>

The schema to use when creating an empty database.

=cut

has 'schema' => (
  is      => 'rw',
  default => undef,
);


=head2 C<hostname>

The hostname for which subsequent inserts are stored for.

=cut

has 'hostname' => (
  is => 'rw',
  isa => 'Str',
);

=head2 C<run>

The current run for which database entries are stored at.

=cut

has 'run' => (
  is       => 'ro',
  init_arg => undef,
  writer   => '_run',
);

=head2 C<dbh>

The handle to the database

=cut

has 'dbh' => (
  is       => 'ro',
  init_arg => undef,
  writer   => '_dbh',
);


=head1 METHODS

=head2 C<new>

  my $db = NetAudit::Db->new(
    database  => 'my.db',
    schema    => 'schema.sql'
  );

Connects to the SQLite database stored in C<database>.
If the database doesn't exist, a new one is created by using the
template in C<schema>.

Returns a Netaudit::Db object on success, or dies on errors.

=cut

sub BUILD {
  my ($self) = @_;

  my $dbh = DBI->connect("dbi:SQLite:dbname=" . $self->database);
  die sprintf("Opening database failed: %s", $DBI::errstr)
    unless ($dbh);

  $self->_dbh($dbh);

  # make DB raise exception on failures, but not print them.
  $dbh->{RaiseError} = 1;
  $dbh->{PrintError} = 0;

  # turn FOREIGN KEYS enforcement on (we use this to make removal of a
  # run super simple)
  $dbh->do("PRAGMA foreign_keys = ON");

  # do the database have a compliant version?
  my ($version) = eval { $dbh->selectrow_array("SELECT version FROM db") };

  # if we got an answer, check version compability
  if (defined $version) {
    die "The database have a non-compliant version. See UPGRADE\n"
      unless ($version eq $SCHEMA_VER);
  }

  # if no answer, the database is probably empty. load schema
  else {
    # try to init the database from the schema file
    die sprintf("Could not open schema %s: %s", $self->schema, $!)
      unless open(my $fh, "<", $self->schema);

    # do our sqlite support multiple statements?
    if ($DBD::SQLite::VERSION ge "1.30_01") {
      $dbh->{'sqlite_allow_multiple_statements'} = 1;

      # slurp schema all in once
      my $stmt = do { local $/; <$fh> };
      $dbh->do($stmt)
        or die sprintf("Executing SQL statements failed: %s", $dbh->errstr);
    }
    else {
      # read schema file statement by statement
      do {
        local $/ = "--";
        my $stmt = <$fh>;
        $dbh->do($stmt)
          or die sprintf("Executing SQL statement failed: %s", $dbh->errstr);
      } while (<$fh>);
    }
    close($fh);
  }

  return;
}


=head2 C<disconnect>

Close the database handle.

=cut

sub disconnect {
  my $self = shift;

  return unless $self->dbh;
  $self->dbh->disconnect;
  return;
}


=head2 C<newrun>

Creates a new unique run in the database.

=cut

sub newrun {
  my ($self) = @_;
  croak("No database connection")
    unless $self->dbh;

  my $epoch = time();
  my $stmt  = "INSERT INTO runs (epoch) VALUES (?)";
  my $sth   = $self->dbh->prepare($stmt);
  $sth->execute($epoch);

  # retreive the key to the just/last inserted line
  my $run = eval { $self->dbh->last_insert_id("", "", "", "") };
  croak("Could't get the id of the new run") if $@;
  $self->_run($run);
  return;
}


=head2 C<insert>

Inserts the columns from $href into database table $table,
indexed by the current L<hostname> and L<run>.

=cut

sub insert {
  my ($self, $table, $href) = @_;

  # sanity check
  croak "No database connection" unless $self->dbh;

  # add run + hostname to the hash
  $href->{run}      = $self->run;
  $href->{hostname} = $self->hostname;

  my $stmt = sprintf(
    "INSERT INTO %s (%s) VALUES (%s)",
    $table,
    join(", ", keys %{$href}),
    join(", ", map { $self->dbh->quote($_) } values %{$href}));

  return $self->dbh->do($stmt)
    or croak("Failed inserting a row: " . $self->dbh->errstr);
}


=head2 C<select_aref>

  my $aref = $db->select_aref($smtmt, @args);

=cut

sub select_aref {
  my ($self, $stmt, @args) = @_;

  croak("No database connection")
    unless $self->dbh;

  my $sth = $self->dbh->prepare($stmt);
  $sth->execute(@args) or croak $sth->errstr;

  my $aref = $sth->fetchall_arrayref();
  croak "select failed: $sth->errstr" if $sth->errstr;
  return $aref;
}


=head2 C<select_row>

  my @row = $db->select_row($stmt, @args);

Returns the first row matching C<$stmt>/C<@args>.

=cut

sub select_row {
  my ($self, $stmt, @args) = @_;

  croak("No database connection")
    unless $self->dbh;

  my $sth = $self->dbh->prepare($stmt);
  $sth->execute(@args) or croak $sth->errstr;

  my @row = $sth->fetchrow_array();
  croak "select failed: $sth->errstr" if $sth->errstr;
  return @row;
}


=head2 C<select_column>

  my @array = $db->select_column($stmt, @args);

Returns the first column in the select statement
C<$stmt>/C<@args>.

=cut

sub select_column {
  my ($self, $stmt, @args) = @_;

  my $aref = $self->dbh->selectcol_arrayref($stmt, {}, @args);
  croak "select failed: $self->dbh->errstr"
    if $self->dbh->errstr;
  return $aref ? @{$aref} : undef;
}


=head2 C<dostmt>

  $rows = $db->dostmt($stmt, @args);

Executes a "do statement" and returns the number of
affected rows. 

=cut

sub dostmt {
  my ($self, $stmt, @args) = @_;

  croak("No database connection")
    unless $self->dbh;

  my $rows = $self->dbh->do($stmt, undef, @args)
    or croak $self->dbh->errstr;

  return $rows;
}


=head2 C<gethosts>

  $aref = $db->gethosts(100);

Returns all hostnames with stored data in a run.

=cut

sub gethosts {
  my ($self, $run) = @_;

  return unless $self->getrun($run);    # check that run exists
  my $stmt = "SELECT hostname FROM device WHERE run = ?";
  my $aref = $self->select_aref($stmt, $run)
    or return;

  return map { $$_[0] } @{$aref};
}


__PACKAGE__->meta->make_immutable;

1;
