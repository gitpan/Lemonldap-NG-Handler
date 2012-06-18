# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Lemonldap-NG-Handler-SharedConf.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 3;
BEGIN { use_ok('Lemonldap::NG::Handler::Simple') }

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

my $h;
$h = bless {}, 'Lemonldap::NG::Handler::Simple';

ok( $h->defaultValuesInit( { useSafeJail => 1, } ), 'Enabling Safe Jail' );

my $basic = $h->safe->reval("basic('login','password')");
ok( ( !defined($basic) or defined($basic) ),
    'basic extended function can be undef with recent Safe Jail' );

