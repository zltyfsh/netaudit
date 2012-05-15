#
# Copyright (c) 2012, Per Carlson
#
# This program is free software; you can redistribute it and/or 
# modify it under the same terms as Perl 5.14. For more details, 
# see the full text of the licenses in the directory LICENSES.
#

package Netaudit::Db;

use Mouse;
use Carp;
use DBI;
use Netaudit::Constants;
use Readonly;

Readonly my $SCHEMA_VER => 1;

has 'database' => ( is => 'rw', required => 1 );
has 'schema'   => ( is => 'rw', default  => undef );
has 'hostname' => ( is => 'rw' );
has 'run' => ( is => 'ro', init_arg => undef, writer => '_run' );
has 'dbh' => ( is => 'ro', init_arg => undef, writer => '_dbh' );

#---

sub BUILD {
    my ($self) = @_;

    my $dbh = DBI->connect( "dbi:SQLite:dbname=" . $self->database );
    die sprintf( "Opening database failed: %s", $DBI::errstr )
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
    if ( defined $version ) {
        die "The database have a non-compliant version. See UPGRADE\n"
            unless ( $version eq $SCHEMA_VER );
    }

    # if no answer, the database is probably empty. load schema
    else {
        # try to init the database from the schema file
        die sprintf( "Could not open schema %s: %s", $self->schema, $! )
          unless open( my $fh, "<", $self->schema );

        # do our sqlite support multiple statements?
        if ( $DBD::SQLite::VERSION ge "1.30_01" ) {
            $dbh->{'sqlite_allow_multiple_statements'} = 1;

            # slurp schema all in once
            my $stmt = do { local $/; <$fh> };
            $dbh->do($stmt)
              or die sprintf( "Executing SQL statements failed: %s", $dbh->errstr );
        }
        else {
            # read schema file statement by statement
            do { 
                local $/ = "--"; 
                my $stmt = <$fh>;
                $dbh->do($stmt) 
                  or die sprintf( "Executing SQL statement failed: %s", $dbh->errstr );
            } while (<$fh>);
        }
        close($fh);
    }

    return;
}

#---

sub disconnect {
    my $self = shift;

    return unless $self->dbh;
    $self->dbh->disconnect;
    return;
}

#---

sub newrun {
    my ($self) = @_;
    croak("No database connection")
      unless $self->dbh;

    my $epoch = time();
    my $stmt  = "INSERT INTO runs (epoch) VALUES (?)";
    my $sth   = $self->dbh->prepare($stmt);
    $sth->execute($epoch);

    # retreive the key to the just/last inserted line
    my $run = eval { $self->dbh->last_insert_id( "", "", "", "" ) };
    croak("Could't get the id of the new run") if $@;
    $self->_run($run);
    return;
}

#---

sub insert {
    my ( $self, $table, $href ) = @_;

    carp("No database connection")
      unless $self->dbh;

    # add run + hostname to the hash
    $href->{run}      = $self->run;
    $href->{hostname} = $self->hostname;

    my $stmt = sprintf(
        "INSERT INTO %s (%s) VALUES (%s)",
        $table,
        join( ", ", keys %{$href} ),
        join( ", ", map { $self->dbh->quote($_) } values %{$href} )
    );

    return $self->dbh->do($stmt)
      or croak( "Failed inserting a row: " . $self->dbh->errstr );
}

#---

sub select_aref {
    my ( $self, $stmt, @args ) = @_;

    croak("No database connection")
      unless $self->dbh;

    my $sth = $self->dbh->prepare($stmt);
    $sth->execute(@args) or croak $sth->errstr;

    my $aref = $sth->fetchall_arrayref();
    croak "select failed: $sth->errstr" if $sth->errstr;
    return $aref;
}

#---

sub select_row {
    my ( $self, $stmt, @args ) = @_;

    croak("No database connection")
      unless $self->dbh;

    my $sth = $self->dbh->prepare($stmt);
    $sth->execute(@args) or croak $sth->errstr;

    my @row = $sth->fetchrow_array();
    croak "select failed: $sth->errstr" if $sth->errstr;
    return @row;
}

#---

sub select_column {
    my ( $self, $stmt, @args ) = @_;

    my $aref = $self->dbh->selectcol_arrayref($stmt, {}, @args);
    croak "select failed: $self->dbh->errstr" if $self->dbh->errstr;
    return $aref ? @{ $aref } : undef; 
}

#---

sub dostmt {
    my ( $self, $stmt, @args ) = @_;

    croak("No database connection")
      unless $self->dbh;

    my $rows = $self->dbh->do( $stmt, undef, @args )
      or croak $self->dbh->errstr;

    return $rows;
}

#---

sub gethosts {
    my ( $self, $run ) = @_;

    return unless $self->getrun($run);   # check that run exists
    my $stmt = "SELECT hostname FROM device WHERE run = ?";
    my $aref = $self->select_aref($stmt, $run) 
        or return;

    return map { $$_[0] } @{ $aref };
}

1;
