# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Lemonldap-NG-Handler.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';
no warnings;
use Test::More;    #qw(no_plan)

eval { require Test::MockObject }
  or plan skip_all => 'Test::MockObject required to test portal subroutine';
plan tests         => 2;

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.
use_ok( 'Lemonldap::NG::Handler::Simple', ':all' );
my $h;
$h = bless {}, 'Lemonldap::NG::Handler::Simple';

# Portal value with $vhost
# $vhost -> test.example.com

# Create a fake Apache2::RequestRec
my $mock = Test::MockObject->new();
$mock->fake_module(
    'Apache2::RequestRec' => new =>
      sub { return bless {}, 'Apache2::RequestRec' },
    hostname => sub { 'test.example.com' },
);
our $apacheRequest = Apache2::RequestRec->new();

my $portal = '"http://".$vhost."/portal"';
$h->portalInit( { portal => $portal } );
ok( ( $h->portal() eq 'http://test.example.com/portal' ),
    'Portal value with $vhost' );

