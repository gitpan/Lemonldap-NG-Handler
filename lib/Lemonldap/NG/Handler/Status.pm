## @file
# Status process mechanism

package Lemonldap::NG::Handler::Status;

use strict;
use POSIX;
use Data::Dumper;
#inherits Cache::Cache

our $VERSION  = "0.21";

our $status   = {};
our $activity = [];
our $start    = int( time / 60 );
use constant MN_COUNT => 5;

## @fn private hashRef portalTab()
# @return Constant hash used to convert error codes into string.
sub portalTab {
    return {
        -2 => 'PORTAL_REDIRECT',
        -1 => 'PORTAL_ALREADY_AUTHENTICATED',
        0  => 'PORTAL_OK',
        1  => 'PORTAL_SESSIONEXPIRED',
        2  => 'PORTAL_FORMEMPTY',
        3  => 'PORTAL_WRONGMANAGERACCOUNT',
        4  => 'PORTAL_USERNOTFOUND',
        5  => 'PORTAL_BADCREDENTIALS',
        6  => 'PORTAL_LDAPCONNECTFAILED',
        7  => 'PORTAL_LDAPERROR',
        8  => 'PORTAL_APACHESESSIONERROR',
        9  => 'PORTAL_FIRSTACCESS',
        10 => 'PORTAL_BADCERTIFICATE',
        11 => 'PORTAL_LA_FAILED',
        12 => 'PORTAL_LA_ARTFAILED',
        13 => 'PORTAL_LA_DEFEDFAILED',
        14 => 'PORTAL_LA_QUERYEMPTY',
        15 => 'PORTAL_LA_SOAPFAILED',
        16 => 'PORTAL_LA_SLOFAILED',
        17 => 'PORTAL_LA_SSOFAILED',
        18 => 'PORTAL_LA_SSOINITFAILED',
        19 => 'PORTAL_LA_SESSIONERROR',
        20 => 'PORTAL_LA_SEPFAILED',
        21 => 'PORTAL_PP_ACCOUNT_LOCKED',
        22 => 'PORTAL_PP_PASSWORD_EXPIRED',
    };
}

eval {
    POSIX::setgid( ( getgrnam( $ENV{APACHE_RUN_GROUP} ) )[2] );
    POSIX::setuid( ( getpwnam( $ENV{APACHE_RUN_USER} ) )[2] );
};

## @rfn void run(string localStorage, hashRef localStorageOptions)
# Main.
# Reads requests from STDIN to :
# - update counts
# - display results
sub run {
    my ( $localStorage, $localStorageOptions ) = ( shift, shift );
    my $refLocalStorage;
    eval
"use $localStorage; \$refLocalStorage = new $localStorage(\$localStorageOptions);";
    die($@) if ($@);
    $| = 1;
    my ( $lastMn, $mn, $count );
    while (<STDIN>) {
        $mn = int( time / 60 ) - $start + 1;

        # Cleaning activity array
        if ( $mn > $lastMn ) {
            for ( my $i = 0 ; $i < $mn - $lastMn ; $i++ ) {
                unshift @$activity, {};
                delete $activity->[ MN_COUNT + 1 ];
            }
        }
        $lastMn = $mn;

        # Activity collect
        if (/^(\S+)\s+=>\s+(\S+)\s+(OK|REJECT|REDIRECT|LOGOUT|\-?\d+)$/) {
            my ( $user, $uri, $code ) = ( $1, $2, $3 );

            # Portal error translation
            $code = portalTab->{$code} || $code if ( $code =~ /^\-?\d+$/ );

            # Per user activity
            $status->{user}->{$user}->{$code}++;

            # Per uri activity
            $uri =~ s/^(.*?)\?.*$/$1/;
            $status->{uri}->{$uri}->{$code}++;
            $count->{uri}->{$uri}++;

            # Per vhost activity
            my ($vhost) = ( $uri =~ /^([^\/]+)/ );
            $status->{vhost}->{$vhost}->{$code}++;
            $count->{vhost}->{$vhost}++;

            # Last 5 minutes activity
            $activity->[0]->{$code}++;
        }

        # Status requests

        # $args contains parameters passed to url status page (a=1 for example
        # if request is http://test.example.com/status?a=1). To be used
        # later...
        elsif (/^STATUS(?:\s+(\S+))?$/) {
            my $tmp  = $1;
            my $args = {};
            %$args = split( /[=&]/, $tmp ) if ($tmp);
            &head;

            #print Dumper($args),&end;next;
            my ( $c, $m, $u );
            while ( my ( $user, $v ) = each( %{ $status->{user} } ) ) {
                $u++ unless ( $user =~ /^\d+\.\d+\.\d+\.\d+$/ );

                # Total requests
                foreach ( keys %$v ) {
                    $c->{$_} += $v->{$_};
                }
            }
            for ( my $i = 1 ; $i < @$activity ; $i++ ) {
                $m->{$_} += $activity->[$i]->{$_}
                  foreach ( keys %{ $activity->[$i] } );
            }
            foreach ( keys %$m ) {
                $m->{$_} = sprintf( "%.2f", $m->{$_} / MN_COUNT );
                $m->{$_} = int( $m->{$_} ) if ( $m->{$_} > 99 );
            }
            if ( $args->{'dump'} ) {
                print "<div id=\"dump\"><pre>\n";
                print Dumper( $status, $activity, $count );
                print "</pre></div>\n";
            }

            # Total requests
            print "<h2>Total</h2>\n<div id=\"total\"><pre>\n";
            print sprintf( "%-30s : \%6d (%.02f / mn)\n",
                $_, $c->{$_}, $c->{$_} / $mn )
              foreach ( sort keys %$c );
            print "\n</pre></div>\n";

            # Average
            print "<h2>Average for last " . MN_COUNT
              . " minutes</h2>\n<div id=\"average\"><pre>\n";
            print sprintf( "%-30s : %6s / mn\n", $_, $m->{$_} )
              foreach ( sort keys %$m );
            print "\n</pre></div>\n";

            # Users connected
            print "<div id=\"users\"><p>\nTotal users : $u\n</p></div>\n";

            # Local cache
            my @t =
              $refLocalStorage->get_keys( $localStorageOptions->{namespace} );
            print "<div id=\"cache\"><p>\nLocal Cache : " . @t
              . " objects\n</p></div>\n";

            # Top uri
            if ( $args->{top} ) {
                print "<hr/>\n";
                $args->{categories} ||= 'REJECT,PORTAL_FIRSTACCESS,LOGOUT,OK';

                # Vhost activity
                print
                  "<h2>Virtual Host activity</h2>\n<div id=\"vhost\"><pre>\n";
                foreach (
                    sort { $count->{vhost}->{$b} <=> $count->{vhost}->{$a} }
                    keys %{ $count->{vhost} }
                  )
                {
                    print sprintf( "%-40s : %6d\n", $_, $count->{vhost}->{$_} );
                }
                print "\n</pre></div>\n";

                # General
                print "<h2>Top used URI</h2>\n<div id=\"uri\"><pre>\n";
                my $i = 0;
                foreach (
                    sort { $count->{uri}->{$b} <=> $count->{uri}->{$a} }
                    keys %{ $count->{uri} }
                  )
                {
                    last if ( $i == $args->{top} );
                    last unless ( $count->{uri}->{$_} );
                    $i++;
                    print sprintf( "%-80s : %6d\n", $_, $count->{uri}->{$_} );
                }
                print "\n</pre></div>\n";

                # Top by category
                print
"<table border=\"1\" width=\"100%\"><tr><th>Code</th><th>Top</ht></tr>\n";
                foreach my $cat ( split /,/, $args->{categories} ) {
                    print
"<tr><td><pre>$cat</pre></td><td nowrap>\n<div id=\"$cat\">\n";
                    topByCat( $cat, $args->{top} );
                    print "</div>\n</td></tr>";
                }
                print "</table>\n";
            }
            print "<div id=\"up\"><p>\nServer up for : "
              . &timeUp($mn)
              . "\n</p></div>\n";
            &end;
        }
    }
}

## @rfn private string timeUp(int d)
# Return the time since the status process was launched (last Apache reload).
# @param $d Number of minutes since start
# @return Date in format "day hour minute"
sub timeUp {
    my $d  = shift;
    my $mn = $d % 60;
    $d = ( $d - $mn ) / 60;
    my $h = $d % 24;
    $d = ( $d - $h ) / 24;
    return "$d\d $h\h $mn\mn";
}

## @rfn private void topByCat(string cat,int max)
# Display the "top 10" for a category (OK, REDIRECT,...).
# @param $cat Category to display
# @param $max Number of lines to display
sub topByCat {
    my ( $cat, $max ) = @_;
    my $i = 0;
    print "<pre>\n";
    foreach (
        sort { $status->{uri}->{$b}->{$cat} <=> $status->{uri}->{$a}->{$cat} }
        keys %{ $status->{uri} }
      )
    {
        last if ( $i == $max );
        last unless ( $status->{uri}->{$_}->{$cat} );
        $i++;
        print sprintf( "%-80s : %6d\n", $_, $status->{uri}->{$_}->{$cat} );
    }
    print "</pre>\n";
}

## @rfn private void head()
# Display head of HTML status responses.
sub head {
    print <<"EOF";
<!DOCTYPE html
    PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
         "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en-US" xml:lang="en-US">
<head>
<title>Lemonldap::NG Status</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf8" />
</head>
<body>
<h1>Lemonldap::NG Status</h1>
EOF
}

## @rfn private void end()
# Display end of HTML status responses.
sub end {
    print <<"EOF";
<hr/>
<script type="text/javascript" language="Javascript">
  //<!--
  var a = document.location.href;
  a=a.replace(/\\?.*\$/,'');
  document.write('<a href="'+a+'?top=10&categories=REJECT,PORTAL_FIRSTACCESS,LOGOUT,OK">Top 10</a>');
  //-->
</script>
</body>
</html>
END
EOF
}
1;
__END__

=head1 NAME

Lemonldap::NG::Handler::Status - Perl extension to add a mod_status like system for L<Lemonldap::NG::Handler>

=head1 SYNOPSIS

=head2 Create your Apache module

Create your own package (example using a central configuration database):

  package My::Package;
  use Lemonldap::NG::Handler::SharedConf;
  @ISA = qw(Lemonldap::NG::Handler::SharedConf);
  
  __PACKAGE__->init ( {
    # Activate status feature
    status              => 1,
    # Local storage used for sessions and configuration
    localStorage        => "Cache::DBFile",
    localStorageOptions => {...},
    # How to get my configuration
    configStorage       => {
        type                => "DBI",
        dbiChain            => "DBI:mysql:database=lemondb;host=$hostname",
        dbiUser             => "lemonldap",
        dbiPassword          => "password",
    }
    # ... See Lemonldap::N::Handler
  } );

=head2 Configure Apache

Call your package in /apache-dir/conf/httpd.conf:

  # Load your package
  PerlRequire /My/File
  # Normal Protection
  PerlHeaderParserHandler My::Package
  
  # Status page
  <Location /status>
    Order deny,allow
    Allow from 10.1.1.0/24
    Deny from all
    PerlHeaderParserHandler My::Package->status
  </Location>

=head1 DESCRIPTION

Lemonldap::NG::Handler::Status adds a mod_status like feature to display
Lemonldap::NG::Handler activity on a protected server. It can so be used by
L<mrtg> or directly browsed by your browser.

=head1 SEE ALSO

L<Lemonldap::NG::Handler>, L<Lemonldap::NG::Portal>, L<Lemonldap::NG::Manager>,
L<http://wiki.lemonldap.objectweb.org/xwiki/bin/view/NG/Presentation>

=head1 AUTHOR

Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2008 by Xavier Guimard

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut
