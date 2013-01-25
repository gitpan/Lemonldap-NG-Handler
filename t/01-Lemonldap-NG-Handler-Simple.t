# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Lemonldap-NG-Handler.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 15;
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
            localStorageOptions => { 'namespace' => 'lemonldap-ng-sessions', },
        }
    ),
    'localInit'
);

ok(
    $h->locationRulesInit(
        {
            locationRules => {

                # Basic rules
                default => 'accept',
                '^/no'  => 'deny',
                'test'  => '$groups =~ /\badmin\b/',

                # Bad ordered rules
                '^/a/a' => 'deny',
                '^/a'   => 'accept',

                # Good ordered rules
                '(?#1 first)^/b/a' => 'deny',
                '(?#2 second)^/b'  => 'accept',
            },
        }
    ),
    'locationRulesInit'
);

ok( $h->defaultValuesInit(), 'defaultValuesInit' );

# Test simple portal subroutine
# See t/02-* for complex portal subroutine
ok( ( $h->portalInit( { portal => 'http://auth.example.com' } ) or 1 ),
    'portalInit' );
ok( $h->portal() eq 'http://auth.example.com', 'portal' );
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

ok( $h->grant('/s'),    'basic rule "accept"' );
ok( !$h->grant('/no'),  'basic rule "deny"' );
ok( $h->grant('/a/a'),  'bad ordered rule 1/2' );
ok( $h->grant('/a'),    'bad ordered rule 2/2' );
ok( !$h->grant('/b/a'), 'good ordered rule 1/2' );
ok( $h->grant('/b'),    'good ordered rule 2/2' );
