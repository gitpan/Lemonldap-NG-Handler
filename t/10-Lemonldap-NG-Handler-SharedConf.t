# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Lemonldap-NG-Handler-SharedConf.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More;
use Cwd 'abs_path';
use File::Basename;
use File::Temp;
my $numTests = 3;
unless ( eval { require Test::MockObject } ) {
    $numTests = 1;
    warn "Warning: Test::MockObject is needed to run deeper tests\n";
}

plan tests => $numTests;

my $ini = File::Temp->new();
my $dir = dirname( abs_path($0) );
my $tmp = File::Temp::tempdir();

print $ini "[all]

[configuration]
type=File
dirName=$dir
localStorage=Cache::FileCache
localStorageOptions={                             \\
    'namespace'          => 'lemonldap-ng-config',\\
    'default_expires_in' => 600,                  \\
    'directory_umask'    => '007',                \\
    'cache_root'         => '$tmp',               \\
    'cache_depth'        => 0,                    \\
}

";

$ini->flush();

use Env qw(LLNG_DEFAULTCONFFILE);
$LLNG_DEFAULTCONFFILE = $ini->filename;

open STDERR, '>/dev/null';

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

use_ok('Lemonldap::NG::Handler');

if ( $numTests == 3 ) {

    # we don't want to use all Apache::* stuff
    $ENV{MOD_PERL}             = undef;
    $ENV{MOD_PERL_API_VERSION} = 2;

    # Create a fake Apache2::RequestRec
    my $mock = Test::MockObject->new();
    $mock->fake_module(
        'Apache2::RequestRec' => new =>
          sub { return bless {}, 'Apache2::RequestRec' },
        hostname        => sub { 'test.example.com' },
        is_initial_req  => sub { '1' },
        args            => sub { undef },
        unparsed_uri    => sub { '/' },
        uri             => sub { '/' },
        get_server_port => sub { '80' },
        get_server_name => sub { 'test.example.com' },
        remote_ip       => sub { '127.0.0.1' },
    );
    $mock->fake_module(
        'Apache2::URI' => new => sub { return bless {}, 'Apache2::URI' },
        unescape_url   => sub { return $_ },
    );
    my $ret;
    $mock->fake_module( 'Lemonldap::NG::Handler::Main::Headers',
        lmSetHeaderOut => sub { $ret = join( ':', $_[2], $_[3], ); }, );

    our $apacheRequest = Apache2::RequestRec->new();

    my $h = bless {}, 'Lemonldap::NG::Handler';

    ok(
        $h->Lemonldap::NG::Handler::run($apacheRequest),
        'run Handler with basic configuration and no cookie'
    );

    ok(
        "$ret" eq
'Location:http://auth.example.com/?url=aHR0cDovL3Rlc3QuZXhhbXBsZS5jb20v',
        'testing redirection URL from previous run'
    );

}

$LLNG_DEFAULTCONFFILE = undef;
