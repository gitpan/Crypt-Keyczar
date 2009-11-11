use Test::More tests => 4;
use strict;
use warnings;
use Crypt::Keyczar::Signer;
use Crypt::Keyczar::Verifier;
use Crypt::Keyczar::Util;
use FindBin;


my $KEYSET = "$FindBin::Bin/data/compat-java-sign";
my $signer = Crypt::Keyczar::Signer->new($KEYSET);
ok($signer);
my $sign = $signer->sign("This is some test data");
ok(Crypt::Keyczar::Util::encode($sign) eq 'AGLONb623KRxtE7FZoVS0iIph0fhD5T-Cw');

my $verifier = Crypt::Keyczar::Verifier->new($KEYSET);
ok($verifier->verify("This is some test data", $sign));
ok(!$verifier->verify("Wrong string", $sign));

