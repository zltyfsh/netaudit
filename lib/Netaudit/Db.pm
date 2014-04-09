#
# Copyright 2012,2013,2014 Per Carlson
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
  );

  $dbh->newrun;
  $dbh->hostname('foo');

  $dbh->insert('table', $href);

  $dbh->disconnect;

=head1 DESCRIPTION

Netaudit::Db is mostly a wrapper around DBI to make selects a bit 
easier.
Probably this would be obtained even easier by using DBIx::Simple,
but that's an opportunity in future releases :-)

Additionally there are some methods for inserting tailored data into
the various tables, e.g C<newrun>, and C<insert>.

=cut

use Mojo::Base -base;
use Carp;
use DBI;
use Netaudit::Constants;
use Readonly;

Readonly my $SCHEMA_VER => 2;

=head1 ATTRIBUTES

=head2 C<database>

The filename with the SQLite3 database.

=cut

has 'database';


=head2 C<hostname>

The hostname for which subsequent inserts are stored for.

=cut

has 'hostname';


# private attributes

# The current run for which database entries are stored at.
has '_run';


# The handle to the database
has '_dbh';


=head1 METHODS

=head2 C<new>

  my $db = NetAudit::Db->new(
    database  => 'my.db',
  );

Connects to the SQLite database stored in C<database>.
If the database doesn't exist, a new one is created.

Returns a Netaudit::Db object on success, or dies on errors.

=cut

sub new {
  my $self = shift->SUPER::new(@_);

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
    # do our sqlite support multiple statements?
    if ($DBD::SQLite::VERSION ge "1.30_01") {
      $dbh->{'sqlite_allow_multiple_statements'} = 1;

      # slurp schema all in once
      my $stmt = do { local $/; <DATA> };
      $dbh->do($stmt)
        or die sprintf("Executing SQL statements failed: %s", $dbh->errstr);
    }
    else {
      # read schema file statement by statement
      do {
        local $/ = "--";
        my $stmt = <DATA>;
        $dbh->do($stmt)
          or die sprintf("Executing SQL statement failed: %s", $dbh->errstr);
      } while (<DATA>);
    }
  }

  return $self;
}


=head2 C<disconnect>

Close the database handle.

=cut

sub disconnect {
  my $self = shift;

  return unless $self->_dbh;
  $self->_dbh->disconnect;
  return;
}


=head2 C<newrun>

Creates a new unique run in the database.

=cut

sub newrun {
  my ($self) = @_;
  croak("No database connection")
    unless $self->_dbh;

  my $epoch = time();
  my $stmt  = "INSERT INTO runs (epoch) VALUES (?)";
  my $sth   = $self->_dbh->prepare($stmt);
  $sth->execute($epoch);

  # retreive the key to the just/last inserted line
  my $run = eval { $self->_dbh->last_insert_id("", "", "", "") };
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
  croak "No database connection" unless $self->_dbh;

  # add run + hostname to the hash
  $href->{run}      = $self->_run;
  $href->{hostname} = $self->hostname;

  my $stmt = sprintf(
    "INSERT INTO %s (%s) VALUES (%s)",
    $table,
    join(", ", keys %{$href}),
    join(", ", map { $self->_dbh->quote($_) } values %{$href}));

  return $self->_dbh->do($stmt)
    or croak("Failed inserting a row: " . $self->_dbh->errstr);
}


=head2 C<select_aref>

  my $aref = $db->select_aref($smtmt, @args);

=cut

sub select_aref {
  my ($self, $stmt, @args) = @_;

  croak("No database connection")
    unless $self->_dbh;

  my $sth = $self->_dbh->prepare($stmt);
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
    unless $self->_dbh;

  my $sth = $self->_dbh->prepare($stmt);
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

  my $aref = $self->_dbh->selectcol_arrayref($stmt, {}, @args);
  croak "select failed: $self->_dbh->errstr"
    if $self->_dbh->errstr;
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
    unless $self->_dbh;

  my $rows = $self->_dbh->do($stmt, undef, @args)
    or croak $self->_dbh->errstr;

  return $rows;
}


=head2 C<gethosts>

  $aref = $db->gethosts(100);

Returns all hostnames with stored data in a run.

=cut

sub gethosts {
  my ($self, $run) = @_;

  return unless $self->_getrun($run);    # check that run exists
  my $stmt = "SELECT hostname FROM device WHERE run = ?";
  my $aref = $self->select_aref($stmt, $run)
    or return;

  return map { $$_[0] } @{$aref};
}


=head2 C<quote>

  $str = $db->quote("Don't");

Returns the string as a literal value to be used in SQL statements.
This sub is just a wrapper around DBI->quote.

=cut

sub quote {
  my ($self, $str) = @_;
  return $self->_dbh->quote($str);
}


sub _getrun {
  my ($self, $run) = @_;

  my $stmt = "SELECT * FROM runs WHERE run = ?";
  my $aref = $self->select_aref($stmt, $run)
    or return;

  return 1;
}


1;

__DATA__


DROP TABLE IF EXISTS db;
--
CREATE TABLE db (
       version	    INTEGER
);
--
INSERT INTO db (version) VALUES ('2');
--
CREATE TABLE IF NOT EXISTS runs (
       run 	  INTEGER PRIMARY KEY AUTOINCREMENT,
       epoch	TEXT
);
--
CREATE TABLE IF NOT EXISTS route_summary (
       run   	    INTEGER,
       hostname   TEXT,
       afi        TEXT,
       connected  INTEGER,
       static	    INTEGER,
       local	    INTEGER,
       isis	      INTEGER,
       bgp	      INTEGER,
       FOREIGN KEY(run) REFERENCES runs(run) ON DELETE CASCADE
);
--
CREATE TABLE IF NOT EXISTS isis_neighbour (
       run   	    INTEGER,
       hostname   TEXT,
       neighbour  TEXT,
       interface  TEXT,
       state	    TEXT,
       FOREIGN KEY(run) REFERENCES runs(run) ON DELETE CASCADE
);   
--
CREATE TABLE IF NOT EXISTS isis_topology (
       run   	    INTEGER,
       hostname   TEXT,
       host    	  TEXT,
       metric	    INTEGER,
       interface  TEXT,
       afi	      TEXT,
       FOREIGN KEY(run) REFERENCES runs(run) ON DELETE CASCADE
);   
--
CREATE TABLE IF NOT EXISTS bgp (
       run   	    INTEGER,
       hostname   TEXT,
       peer       TEXT,
       asn        INTEGER,
       afi        TEXT,  
       vrf	      TEXT,
       prefixes	  INTEGER,
       FOREIGN KEY(run) REFERENCES runs(run) ON DELETE CASCADE
);   
--
CREATE TABLE IF NOT EXISTS interface (
       run   	      INTEGER,
       hostname     TEXT,
       descr	      TEXT,
       mtu	        INTEGER,
       adminstatus  TEXT,
       operstatus   TEXT,
       ipv4status   TEXT,
       ipv6status   TEXT,
       speed	      INTEGER,
       FOREIGN KEY(run) REFERENCES runs(run) ON DELETE CASCADE
);   
--
CREATE TABLE IF NOT EXISTS pwe3 (
       run   	    INTEGER,
       hostname   TEXT,
       interface  TEXT,
       status	    TEXT,
       peer	      TEXT,
       FOREIGN KEY(run) REFERENCES runs(run) ON DELETE CASCADE
);   
--
CREATE TABLE IF NOT EXISTS vrf (
       run   	      INTEGER,
       hostname     TEXT,
       vrf	        TEXT,
       active	      INTEGER,
       associated   INTEGER,
       FOREIGN KEY(run) REFERENCES runs(run) ON DELETE CASCADE
);

