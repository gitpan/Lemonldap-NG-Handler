# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Lemonldap-NG-Handler-Vhost.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

package My::Package;

use Test::More tests => 5;

BEGIN {
    use_ok('Lemonldap::NG::Handler::Vhost');
    use_ok('Lemonldap::NG::Handler::Simple');
}

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

our @ISA = qw( Lemonldap::NG::Handler::Vhost Lemonldap::NG::Handler::Simple );
my $h;
$h = bless {}, 'My::Package';

open STDERR, '>/dev/null';

ok(
    $h->defaultValuesInit(
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
    $h->locationRulesInit(
        {
            locationRules => {
                www1 => {
                    default => 'accept',
                    '^/no'  => 'deny',
                    'test'  => '$groups =~ /\badmin\b/',
                },
            },
        }
    ),
    'locationRulesInit'
);

ok(
    $h->forgeHeadersInit(
        { exportedHeaders => { www1 => { Auth => '$uid', } } }
    ),
    'forgeHeadersInit'
);

