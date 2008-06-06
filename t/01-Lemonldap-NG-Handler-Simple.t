# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Lemonldap-NG-Handler.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 11;
BEGIN { use_ok( 'Lemonldap::NG::Handler::Simple', ':all' ) }

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.
my $h;
$h = bless {}, 'Lemonldap::NG::Handler::Simple';
ok(
    $h->localInit(
        {
            localStorage        => 'Cache::FileCache',
            localStorageOptions => { 'namespace' => 'MyNamespace', },
        }
    ),
    'localInit'
);

ok(
    $h->locationRulesInit(
        {
            locationRules => {
                default => 'accept',
                '^/no'  => 'deny',
                'test'  => '$groups =~ /\badmin\b/',
            },
        }
    ),
    'locationRulesInit'
);

ok( $h->defaultValuesInit(), 'defaultValuesInit' );
ok( $h->portalInit( { portal => 'http://auth.example.com' } ), 'portalInit' );
ok(
    $h->globalStorageInit(
        {
            globalStorage        => 'Apache::Session::File',
            globalStorageOptions => {},
        }
    ),
    'globalStorageInit'
);
ok( $h->forgeHeadersInit, 'forgeHeadersInit' );
ok( $h->forgeHeadersInit( { exportedHeaders => { Auth => '$uid', } } ),
    'forgeHeadersInit 2' );

ok( $h->grant('/s'),                   'grant OK' );
ok( !$h->grant('/no'),                 'grant NOK' );
ok( $h->cleanLocalStorage == DECLINED, 'cleanLocalStorage' );
