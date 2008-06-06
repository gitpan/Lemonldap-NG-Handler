# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Lemonldap-NG-Handler.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 9;
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
            status              => 1
        }
    ),
    'New Object'
);

ok( $statusPipe->isa('IO::Pipe::End'), 'In pipe' );

ok( $statusOut->isa('IO::Pipe::End'), 'Out pipe' );

ok( print( $statusPipe "uid => / OK\nuid => / OK\nuid => /no REJECT\n" ),
    'New requests' );

ok( print( $statusPipe "STATUS\n" ), 'Status request' );

ok( &read, 'Status result' );

ok( close($statusOut) );

ok( close($statusPipe) );

sub read {
    my $ok = 0;
    #open LOG, '>/tmp/log';
    while (<$statusOut>) {
        #print LOG $_;
        $ok++ if (/^OK\s+:\s*2\s*\(2\.00\s*\/\s*mn\)$/);
        $ok++ if (/^REJECT\s+:\s*1\s*\(1\.00\s*\/\s*mn\)$/);
        $ok++ if (/^OK\s+:\s*[\d\.]+\s*\/\s*mn$/);
        $ok++ if (/^REJECT\s+:\s*[\d\.]+\s*\/\s*mn$/);
        if (/^END$/) {
            $ok++;
            last;
        }
    }
    #print LOG "$ok\n";
    #close LOG;
    return ( $ok == 5 );
}
