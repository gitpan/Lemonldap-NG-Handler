# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Lemonldap-NG-Handler-Vhost.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

package My::Package;

use Test::More tests => 4;

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

