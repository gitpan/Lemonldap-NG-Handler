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

ok($h->defaultValuesInit({ useSafeJail => 0, }), 'Disabling Safe Jail');
like( $h->safe->reval("basic('login','password')"), "/^Basic bG9naW46cGFzc3dvcmQ=/" , 'basic extended function working without Safe Jail');

