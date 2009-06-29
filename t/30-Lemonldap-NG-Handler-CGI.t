# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Lemonldap-NG-Handler-CGI.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 2;
BEGIN { use_ok('Lemonldap::NG::Handler::CGI') }

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

my $p;

# CGI Environment
$ENV{SCRIPT_NAME}     = '/test.pl';
$ENV{SCRIPT_FILENAME} = '/tmp/test.pl';
$ENV{REQUEST_METHOD}  = 'GET';
$ENV{REQUEST_URI}     = '/';
$ENV{QUERY_STRING}    = '';

ok(
    $p = Lemonldap::NG::Handler::CGI->new(
        {
            configStorage => {
                type    => "File",
                dirName => '/tmp/',
            },
            https         => 0,
            portal        => 'http://auth.example.com',
            globalStorage => 'Apache::Session::File',
        }
    ),
    'Portal object'
);

