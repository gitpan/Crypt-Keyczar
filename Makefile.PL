use 5.008006;
use ExtUtils::MakeMaker;


our $WITH_OPENSSL         = 1;
our $WITH_WIN32_CRYPTOAPI = 0;
our $WITH_PERL            = 0;

my %option = (
    NAME => 'Crypt::Keyczar',
    VERSION_FROM => 'lib/Crypt/Keyczar.pm',
    PREREQ_PM => {
        'JSON' => 0.0, # 1.xx or 2.xx
        'MIME::Base64' => 0.0,
    },
    LIBS => [], # -lcrypto or other
    ($] >= 5.005 ?
        (ABSTRACT_FROM => 'lib/Crypt/Keyczar.pm',
         AUTHOR => '小山浩之 <oyama@mixi.co.jp>') : ()),
);

if ($WITH_OPENSSL) {
    $option{LIBS} = [ "-L$ENV{OPENSSL_PREFIX}/lib", '-lcrypto' ];
    $option{INC}  = "-I$ENV{OPENSSL_PREFIX}/include";
    $option{depend} = { 'Keyczar.c' => "Keyczar.xs xs/openssl.h xs/openssl/*.xst" };
    WriteMakefile(%option);
}
elsif ($WITH_WIN32_CRYPTOAPI) {
    # PATCH WELLCOME :-)
}
elsif ($WITH_PERL) {
    # use Pure Perl implementation
    # PATCH WELLCOME :-)
}
else {
    die "ERROR: $option{NAME} require libcrypto(OpenSSL) or CryptoAPI(Win32)\n";
}
