# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Lemonldap-NG-Handler-Vhost.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

package My::Package;

use Test::More tests => 5;

BEGIN {
    use_ok('Lemonldap::NG::Handler::Initialization::GlobalInit');
}

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

my $globalinit;

open STDERR, '>/dev/null';

ok(
    $globalinit = Lemonldap::NG::Handler::Initialization::GlobalInit->new(
        customFunctions => "",
        useSafeJail     => 1,
    ),
    'constructor'
);

ok(
    $globalinit->defaultValuesInit(
        ( map { undef } 1 .. 16 ),
        {
            https        => 0,
            port         => 0,
            maintenance  => 0,
            vhostOptions => {
                www1 => {
                    vhostHttps       => 1,
                    vhostPort        => 443,
                    vhostMaintenance => 1,
                    vhostAliases     => 'www2 www3',

                }
            },
        }
    ),
    'defaultValuesInit'
);

ok(
    $globalinit->locationRulesInit(
        ( map { undef } 1 .. 8 ),
        {
            'locationRules' => {
                'www1' => {
                    'default' => 'accept',
                    '^/no'    => 'deny',
                    'test'    => '$groups =~ /\badmin\b/',
                }
            }
        }
    ),
    'locationRulesInit'
);

ok(
    $globalinit->forgeHeadersInit(
        ( map { undef } 1 .. 1 ),
        { exportedHeaders => { www1 => { Auth => '$uid', } } }
    ),
    'forgeHeadersInit'
);

