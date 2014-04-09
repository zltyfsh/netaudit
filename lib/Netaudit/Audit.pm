#
# Copyright (c) 2012, Per Carlson
#
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl 5.14. For more details,
# see the full text of the licenses in the directory LICENSES.
#

package Netaudit::Audit;

use Mojo::Base -base;
use Net::Telnet;
use Term::ANSIColor;
use Module::Pluggable require => 1, search_path => ['Netaudit::Plugin'];
use List::Util qw{ first };

use Netaudit::Db;
use Netaudit::SNMP;
use Netaudit::Constants;
use Netaudit::Log;

# Public attributes

# Database handle
has 'database';

# Config hash
has 'config';

# Private attributes

has '_log' => sub {
  my $self = shift;

  my $log_file = $self->config->log_file // '/dev/null';
  my $log = Netaudit::Log->new(path => $log_file);
  $log->level($self->config->log_level);

  return $log;
};


# Methods

sub run {
  my ($self, $host) = @_;
  say colored("host: $host", "bold");
  $self->_log->info("Auditing host $host");

  my $snmp = Netaudit::SNMP->new(
    hostname  => $host,
    community => $self->config->community,
  );
  if (!$snmp) {
    say colored("Host $host is unreachable: $@", "red");
    $self->_log->error("Host $host is unreachable: $@");
    eval { $snmp->close(); };    # clean up gracefully
    return;
  }

  my $sysdescr = $snmp->sysdescr();
  if (!$sysdescr) {
    say colored("Failed to get a sysDescr from $host: $@", "red");
    $self->_log->error("Failed to get a sysDescr from $host: $@");
    return;
  }
  $self->_log->debug("$host sysDescr=$sysdescr");

  # find the plugin which handles this host based on the
  # SNMP sysDescr (contained in $res)
  my $plugin = first { $_->handles($sysdescr) } $self->plugins;
  $self->_log->debug("$host plugin=$plugin");
  if (!$plugin) {
    say colored("Don't know how to handle $host based on sysDescr", "red");
    $self->_log->error("Don't know how to handle $host based on sysDescr ($sysdescr)");
    return;
  }

  # create a cli session
  my $cli = eval { Net::Telnet->new($host) };
  if ($@) {
    say colored("Failed to open telnet session to $host: $@", "red");
    $self->_log->error("Failed to open telnet session to $host: $@");
    return;
  }

  # bump telnet buffer (10 MByte)
  $cli->max_buffer_length(10 * 1024 * 1024);

  # Set the timeout
  $cli->timeout($self->config->timeout);

  # set prompt
  $cli->prompt($plugin->prompt) if $plugin->prompt;

  # try to login
  unless ($cli->login(
    Name     => $self->config->username,
    Password => $self->config->password,
    Errmode  => "return",
  )) {
    say colored("Can't login to $host: " . $cli->errmsg, "red");
    $self->_log->error("Can't login to $host: " . $cli->errmsg);
    return;
  }

  # store hostname in database object
  $self->database->hostname($host);

  my $driver = $plugin->new(
    log  => $self->_log,
    cli  => $cli,
    snmp => $snmp,
    db   => $self->database,
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
  my $result = shift;
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
