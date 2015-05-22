use strict;
use warnings;
use Test::More;
use File::Find;

my @modules = ();

# find all files ending with .pm in lib/
# and convert the filename to a perl module name
find(
  sub {
    # only look for perl modules
    return unless $_ =~ / \.pm $/xms;
    my $m = $File::Find::name;
    $m =~ s!\.pm$!!;
    $m =~ s!./lib/!!;
    $m =~ s!/!::!g;
    push @modules, $m;
  },
  './lib'
);

# try using all found modules
use_ok $_ for @modules;

done_testing;
