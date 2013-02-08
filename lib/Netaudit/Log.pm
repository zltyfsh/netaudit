package Netaudit::Log;

use Mojo::Base 'Mojo::Log';
use Mojo::JSON;

has 'json' => sub { Mojo::JSON->new };

sub insert {
  my ($self, $db, $href) = @_;
  return $self->info("inserted into table $db: " . $self->json->encode($href));
}

1;

