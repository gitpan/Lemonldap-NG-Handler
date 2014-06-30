
package Lemonldap::NG::Handler::Main::Logger;

use Lemonldap::NG::Handler::Main qw( :apache );

## @rmethod void lmLog(string mess, string level)
# Wrapper for Apache log system
# @param $mess message to log
# @param $level string (debug, info, warning or error)
sub lmLog {
    my ( $class, $mess, $level ) = splice @_;
    die("Level is required") unless ($level);
    my $call;
    my @tmp = caller();
    ( my $module = $tmp[0] ) =~ s/.+:://g;
    $module .= "($tmp[2]): ";
    unless ( $level eq 'debug' ) {
        $call = "$tmp[1] $tmp[2]:";
    }
    if ( MP() == 2 ) {
        Apache2::ServerRec->log->debug($call) if ($call);
        Apache2::ServerRec->log->$level( $module . $mess );
    }
    elsif ( MP() == 1 ) {
        Apache->server->log->debug($call) if ($call);
        Apache->server->log->$level( $module . $mess );
    }
    else {
        print STDERR "[$level] $module $mess\n";
    }
}

1;
