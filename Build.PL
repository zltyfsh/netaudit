use Module::Build;

use File::Spec::Functions;

my $build = Module::Build->new (
  dist_abstract => 'Scripts for doing network audits of routers',
  dist_version_from => 'lib/Netaudit/Constants.pm',
  dist_author => 'Per Carlson <pelle@hemmop.com>',
  module_name => 'netaudit',
  license => 'perl',
  script_files => ['bin/netaudit', 'bin/netreport'],
  configure_requires => {
    'Module::Build' => 0,
  },
  requires => {
    'perl' => '5.010',
    'Net::Telnet' => 0,
    'NetAddr::IP' => 0,
    'Net::SNMP' => 0,
    'Mojolicious' => 4.82,
    'IO::Prompt' => 0,
    'Regexp::Common' => 0,
    'Regexp::IPv6' => 0,
    'DBI' => 0,
    'DBD::SQLite' => '1.26_05',  # depending on foreign keys
    'Text::Table' => 0,
    'Algorithm::Diff' => 0,
    'Config::Simple' => 0,
    'Readonly' => 0,
    'List::AllUtils' => 0,
  },
  recommends => {
    # having those enables colored output
    'Text::Aligner' => '0.06',
    'Term::ANSIColor' => '2.01',
  },
  share_files => {
    'share/upgrade1.x-2.1' => 'share/upgrade1.x-2.1',
  },
  doc_files   => {
    map( ($_ => catfile('doc', $_) ), qw[ TODO INSTALL UPGRADE ])
  },
);

$build->install_base_relpaths('share' => catdir('share', $build->module_name) );
$build->add_build_element('share');

$build->install_base_relpaths('doc' => catdir('share', 'doc', $build->module_name) );
$build->add_build_element('doc');

$build->create_build_script;
