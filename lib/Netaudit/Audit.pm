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
use feature qw{ switch say };

use Net::Telnet;
use Term::ANSIColor;
use Module::Pluggable require => 1, search_path => ['Netaudit::Plugin'];
use List::Util qw{ first };

use Netaudit::Db;
use Netaudit::SNMP;
use Netaudit::Constants;

sub run {
  my ($self, $host, $config, $db) = @_;
  say colored("host: $host", "bold");

  my $snmp = Netaudit::SNMP->new(
    hostname  => $host,
    community => $config->community,
  );
  if (!$snmp) {
    say colored("Host $host is unreachable: $@", "red");
    eval { $snmp->close(); };    # clean up gracefully
    return;
  }

  my $sysdescr = $snmp->sysdescr();
  if (!$sysdescr) {
    say colored("Failed to get a sysDescr from $host: $@", "red");
    return;
  }

  # find the plugin which handles this host based on the
  # SNMP sysDescr (contained in $res)
  my $plugin = first { $_->handles($sysdescr) } $self->plugins;
  if (!$plugin) {
    say colored("Don't know how to handle $host based on sysDescr", "red");
    return;
  }

  # create a cli session
  my $cli = Net::Telnet->new(
    Host    => $host,
    Errmode => "return",
    Timeout => 2
  );
  if (!$cli) {
    say colored("Failed to open telnet session to $host", "red");
    return;
  }

  # bump telnet buffer
  $cli->max_buffer_length(3000000);

  # log to file if we have log/ directory
  $cli->input_log("log/$host.log") if -d 'log';

  # set prompt
  $cli->prompt($plugin->prompt) if $plugin->prompt;

  # try to login
  unless ($cli->login($config->username, $config->password)) {
    say colored("Can't login to $host: $cli->errmsg", "red");
    return;
  }

  # store hostname in database object
  $db->hostname($host);

  my $driver = $plugin->new(
    cli  => $cli,
    snmp => $snmp,
    db   => $db,
  );

  # run audits
  print "routing summary ", ok($driver->route_summary);
  print "isis neighbour  ", ok($driver->isis_neighbour);
  print "isis topology   ", ok($driver->isis_topology);
  print "bgp             ", ok($driver->bgp);
  print "interface       ", ok($driver->interface);
  print "vrf             ", ok($driver->vrf);
  print "pwe3            ", ok($driver->pwe3);

  # tidy up
  $snmp->close();
  $cli->close();
  print "\n";

  return;
}

#---

sub ok {
  my ($result) = @_;
  my $str;

  for ($result) {
    when ($AUDIT_OK)     { $str = colored("done",          "green"); }
    when ($AUDIT_NODATA) { $str = colored("no data",       "green"); }
    when ($AUDIT_FAIL)   { $str = colored("fail",          "red"); }
    default              { $str = colored("unimplemented", "red"); };
  }

  return sprintf "[%s]\n", $str;
}

#---

1;
