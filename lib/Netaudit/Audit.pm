#
# Copyright (c) 2012, Per Carlson
#
# This program is free software; you can redistribute it and/or 
# modify it under the same terms as Perl 5.14. For more details, 
# see the full text of the licenses in the directory LICENSES.
#

package Netaudit::Audit;

use strict;
use warnings;
use feature 'switch';

use Net::Telnet;
use Term::ANSIColor;
use POSIX qw(strftime);
use Module::Pluggable require => 1, search_path => ['Netaudit::Plugin'];

use Netaudit::Db;
use Netaudit::SNMP;
use Netaudit::Constants;

sub run {
    my ( $self, $host, $config ) = @_;
    print colored( "host: $host", "bold" ), "\n";

    my ( $comm, $snmp, $sysdescr );
    my $driver = undef;

    $snmp = Netaudit::SNMP->new(
        hostname  => $host,
        community => $config->{community}
    );

    if ( !$snmp ) {
        print colored( "Host $host is unreachable: $@", "red" ), "\n";
        eval { $snmp->close(); };    # clean up gracefully
        return;
    }

    $sysdescr = $snmp->sysdescr();
    if ( !$sysdescr ) {
        print colored( "Failed to get a sysDescr from $host: $@", "red" ), "\n";
        return;
    }

    # find the driver which handles this host based on the
    # SNMP sysDescr (contained in $res)
    foreach my $plugin ( $self->plugins ) {
        if ( $plugin->handles($sysdescr) ) {
            $driver = $plugin;
            last;
        }
    }

    if ( !$driver ) {
        print colored( "Don't know how to handle $host based on sysDescr",
            "red" ), "\n";
        return;
    }

    $comm =
      Net::Telnet->new( Host => $host, Errmode => "return", Timeout => 2 );
    $comm->max_buffer_length(3000000);    # bump the cache a bit
    $comm->prompt( $driver->prompt )
      if defined $driver->prompt;         # set prompt from driver
    if ( $config->{development} ) {
        $comm->input_log("$host.log");
    }

    unless ( $comm->login( $config->{username}, $config->{password} ) ) {
        print colored( "Can't login to $host: " . $comm->errmsg(), "red" ),
          "\n";
        eval { $comm->close(); };         # clean up without failing
        return;
    }

    # let drivers setup proper environment
    $driver->init($comm);

    # shortcut
    my $db = $config->{db};

    # set hostname to use in database object (after stripping domain)
    $db->hostname($host);

    # run audits
    # screen scraping
    print "routing summary ", ok( $driver->route_summary( $comm, $db ) );
    print "isis neighbour  ", ok( $driver->isis_neighbours( $comm, $db ) );
    print "isis topology   ", ok( $driver->isis_topology( $comm, $db ) );
    print "bgp             ", ok( $driver->bgp( $comm, $db ) );

    # snmp
    print "interfaces      ", ok( $snmp->interfaces($db) );
    print "vrfs            ", ok( $snmp->vrfs($db) );
    print "pwe3            ", ok( $snmp->pwe3($db) );

    # tidy up
    $snmp->close();
    $comm->close();
    print "\n";

    return;
}

#---

sub ok {
    my ($result) = @_;
    my $str;

    given ($result) {
        when ($AUDIT_OK)     { $str = colored( "done",          "green" ); }
        when ($AUDIT_NODATA) { $str = colored( "no data",       "green" ); }
        when ($AUDIT_FAIL)   { $str = colored( "fail",          "red" ); }
        default              { $str = colored( "unimplemented", "red" ); }
    }

    return sprintf "[%s]\n", $str;
}

#---

1;
