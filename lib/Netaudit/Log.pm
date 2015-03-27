package Netaudit::Log;

use Mojo::Base 'Mojo::Log';
use Mojo::JSON qw( encode_json );

sub insert {
  my ($self, $db, $href) = @_;
  return $self->info("inserted into table $db: @{[ encode_json($href) ]}");
}

1;
