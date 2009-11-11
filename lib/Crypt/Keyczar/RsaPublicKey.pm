package Crypt::Keyczar::RsaPublicKey;
use base 'Crypt::Keyczar::Key';
use strict;
use warnings;

use Crypt::Keyczar qw(KEY_HASH_SIZE);
use Crypt::Keyczar::Util;



sub expose {
    my $self = shift;
    my $expose = {};
    $expose->{modulus} = $self->{modulus};
    $expose->{publicExponent} = $self->{publicExponent};
    $expose->{size} = $self->{size};

    return $expose;
}


sub read {
    my $class = shift;
    my $json_string = shift;

    my $obj = Crypt::Keyczar::Util::decode_json($json_string);
    my $self = bless $obj, $class;
    $self->init();
    return $self;
}


sub init {
    my $self = shift;
    my $mod = Crypt::Keyczar::Util::decode($self->{modulus});
    my $pub_exp = Crypt::Keyczar::Util::decode($self->{publicExponent});
    $mod =~ s/^\x00+//;
    $pub_exp =~ s/^\x00+//;
    my $hash = Crypt::Keyczar::Util::hash(
        pack('N1', length $mod), $mod,
        pack('N1', length $pub_exp), $pub_exp);
    $self->hash(substr $hash, 0, KEY_HASH_SIZE());
    return $self;
}


sub set {
    my $self = shift;
    my ($mod, $pub_exp) = @_;
    $self->{modulus}        = $mod;
    $self->{publicExponent} = $pub_exp;
    $self->init();
    return $self;
}


sub get_engine {
    my $self = shift;
    my @args = map { Crypt::Keyczar::Util::decode($_) } ($self->{modulus}, $self->{publicExponent});
    return Crypt::Keyczar::RsaPublicKeyEngine->new(@args);
}


1;

package Crypt::Keyczar::RsaPublicKeyEngine;
use base 'Exporter';
use strict;
use warnings;
use Crypt::Keyczar::Engine;


1;
__END__
