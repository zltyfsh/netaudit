use strict;
use warnings;

use Test::More;

use_ok 'Netaudit::SNMP';

my $snmp = new_ok 'Netaudit::SNMP', [ hostname => 'localhost' ];

note q(Testing ip2dot);
{
  my @tests = (
    { in => '0xc0a80102', out => '192.168.1.2'    },
    { in => 2886781183,   out => '172.16.200.255' },
    { in => 'Doh!',       out => '68.111.104.33'  },
    { in => 1234,         out => '0.0.4.210'      },
  );

  is $snmp->ip2dot($_->{in}), $_->{out} for @tests;
}

done_testing;
