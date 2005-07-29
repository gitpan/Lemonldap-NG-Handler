package Lemonldap::NG::Handler::Vhost;

use Lemonldap::NG::Handler qw(:locationRules :headers);
use strict;
use MIME::Base64;

our $VERSION = '0.05';

sub locationRulesInit {
    my ( $class, $args ) = @_;
    foreach my $vhost ( keys %{ $args->{locationRules} } ) {
        $locationCount->{$vhost} = 0;
        foreach ( keys %{ $args->{locationRules}->{$vhost} } ) {
            if ( $_ eq 'default' ) {
                $defaultCondition->{$vhost} =
                  $class->conditionSub(
                    $args->{locationRules}->{$vhost}->{$_} );
            }
            else {
                $locationCondition->{$vhost}->[ $locationCount->{$vhost} ] =
                  $class->conditionSub(
                    $args->{locationRules}->{$vhost}->{$_} );
                $locationRegexp->{$vhost}->[ $locationCount->{$vhost} ] =
                  qr/$_/;
                $locationCount->{$vhost}++;
            }
        }

        # Default police
        $defaultCondition->{$vhost} = $class->conditionSub('accept')
          unless ( $defaultCondition->{$vhost} );
    }
}

sub forgeHeadersInit {
    my ( $class, $args ) = @_;
    Apache->server->log->debug( __PACKAGE__ . ": forgeHeadersInit" );

    # Creation of the subroutine who will generate headers
    foreach my $vhost ( keys %{ $args->{exportedHeaders} } ) {
        my %tmp = %{ $args->{exportedHeaders}->{$vhost} };
        foreach ( keys %tmp ) {
            $tmp{$_} =~ s/\$(\w+)/\$datas->{$1}/g;
            $tmp{$_} =~
              s/\$datas->\{ip\}/\$apacheRequest->connection->remote_ip/g;
        }

        my $sub;
        foreach ( keys %tmp ) {
            $sub .= "\$apacheRequest->header_in('$_' => " . $tmp{$_} . ");";
        }
        $sub = "\$forgeHeaders->{'$vhost'} = sub {$sub};";
        eval "$sub";
        Apache->server->log->error(
            __PACKAGE__ . ": Unable to forge headers: $@ $sub" )
          if ($@);
    }
}

sub sendHeaders {
    my $class = shift;
    my $vhost;
    $vhost = $apacheRequest->hostname;
    if ( defined( $forgeHeaders->{$vhost} ) ) {
        &{ $forgeHeaders->{$vhost} };
    }
    else {
        $apacheRequest->header_in( 'Auth-User' => '$uid' );
    }
}

sub grant {
    my ( $class, $uri ) = @_;
    my $vhost = $apacheRequest->hostname;
    for ( my $i = 0 ; $i < $locationCount->{$vhost} ; $i++ ) {
        if ( $uri =~ $locationRegexp->{$vhost}->[$i] ) {
            return &{ $locationCondition->{$vhost}->[$i] }($datas);
        }
    }
    unless ( $defaultCondition->{$vhost} ) {
        Apache->server->log->warn(
            "User rejected because VirtualHost $vhost has no configuration");
    }
    return &{ $defaultCondition->{$vhost} };
}

1;

__END__

=head1 NAME

Lemonldap::NG::Handler::Vhost - Perl extension for building a Lemonldap compatible
handler able to manage Apache virtual hosts.

=head1 SYNOPSIS

Create your own package:

  package My::Package;
  use Lemonldap::NG::Handler::Vhost;
  
  # IMPORTANT ORDER
  our @ISA = qw (Lemonldap::NG::Handler::Vhost Lemonldap::NG::Handler);
  
  __PACKAGE__->init ( { locationRules => {
             'vhost1.dc.com' => {
	         'default' => '$ou =~ /brh/'
	     },
	     'vhost2.dc.com' => {
	         '^/pj/.*$'       => q($qualif="opj"),
		 '^/rh/.*$'       => q($ou=~/brh/),
		 '^/rh_or_opj.*$' => q($qualif="opj or $ou=~/brh/),
                 default          => 'accept',
	     },
	     # Put here others Lemonldap::NG::Handler options
	   }
	 );

Other example, using L<Lemonldap::NG::Handler::SharedConf>

  package My::Package;
  use Lemonldap::NG::Handler::SharedConf;
  use Lemonldap::NG::Handler::Vhost;
  
  # IMPORTANT ORDER
  # our @ISA = qw (Lemonldap::NG::Handler::Vhost Lemonldap::NG::Handler::SharedConf);
  
  __PACKAGE__->init ... # as using Lemonldap::NG::Handler::SharedConf alone

Change configuration

  __PACKAGE__->setConf ( {
               locationRules => {
                 'vhost1.dc.com' => {
	           'default' => '$ou =~ /brh/'
                 },
	         'vhost2.dc.com' => {
	           '^/pj/.*$'       => q($qualif="opj"),
		   '^/rh/.*$'       => q($ou=~/brh/),
		   '^/rh_or_opj.*$' => q($qualif="opj or $ou=~/brh/),
                   default          => 'accept',
	         },
	       },
	       exportedHeaders => {
	         'vhost1.dc.com' => {
	          'Authorization'=>'"Basic ".MIME::Base64::encode_base64($uid)',
		  'User-Auth'    => '$uid',
		 },
		 'vhost2.dc.com' => {
		   'User-Auth'   => '$uid',
		 },
               }
	       # Put here others Lemonldap::NG::Handler::SharedConf options
	     }
	   );

Call your package in <apache-directory>/conf/httpd.conf

  PerlRequire MyFile
  PerlInitHandler My::Package

=head1 DESCRIPTION

Lemonldap is a simple Web-SSO based on Apache::Session modules. It simplifies
the build of a protected area with a few changes in the application (they just

This library provides a way to protect Apache virtual hosts with Lemonldap.

=head2 INITIALISATION PARAMETERS

Lemonldap::NG::Handler::Vhost splits the locationRules parameter into a hash
reference which contains anonymous hash references as used by
L<Lemonldap::NG::Handler>.

=head1 SEE ALSO

L<Lemonldap::NG::Handler(3)>

=head1 AUTHOR

Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Xavier Guimard

This library is free software; you can redistribute it and/or modify it under
same terms as Perl itself, either Perl version 5.8.4 or, at your option, any
later version of Perl 5 you may have available.

=cut
