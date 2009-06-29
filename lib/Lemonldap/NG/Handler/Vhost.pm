## @file
# Virtual host support mechanism

## @class
# This class adds virtual host support for Lemonldap::NG handlers.
package Lemonldap::NG::Handler::Vhost;

use Lemonldap::NG::Handler::Simple qw(:locationRules :headers); #inherits
use strict;
use MIME::Base64;

our $VERSION = '0.55';

## @cmethod void locationRulesInit(hashRef args)
# Compile rules.
# Rules are stored in $args->{locationRules}->{&lt;virtualhost&gt;} that contains
# regexp=>test expressions where :
# - regexp is used to test URIs
# - test contains an expression used to grant the user
#
# This function creates 2 hashRef containing :
# - one list of the compiled regular expressions for each virtual host
# - one list of the compiled functions (compiled with conditionSub()) for each
# virtual host
# @param $args reference to the configuration hash
sub locationRulesInit {
    my ( $class, $args ) = @_;
    foreach my $vhost ( keys %{ $args->{locationRules} } ) {
        $locationCount->{$vhost} = 0;
        foreach ( sort keys %{ $args->{locationRules}->{$vhost} } ) {
            if ( $_ eq 'default' ) {
                $defaultCondition->{$vhost} =
                  $class->conditionSub(
                    $args->{locationRules}->{$vhost}->{$_} );
            }
            else {
                $locationCondition->{$vhost}->[ $locationCount->{$vhost} ] =
                  $class->conditionSub( $args->{locationRules}->{$vhost}->{$_} );
                $locationRegexp->{$vhost}->[ $locationCount->{$vhost} ] = qr/$_/;
                $locationCount->{$vhost}++;
            }
        }

        # Default police
        $defaultCondition->{$vhost} = $class->conditionSub('accept')
          unless ( $defaultCondition->{$vhost} );
    }
    1;
}

## @cmethod void forgeHeadersInit(hashRef args)
# Create the &$forgeHeaders->{&lt;virtualhost&gt;} subroutines used to insert
# headers into the HTTP request.
# @param $args reference to the configuration hash
sub forgeHeadersInit {
    my ( $class, $args ) = @_;

    # Creation of the subroutine who will generate headers
    foreach my $vhost ( keys %{ $args->{exportedHeaders} } ) {
        my %tmp = %{ $args->{exportedHeaders}->{$vhost} };
        foreach ( keys %tmp ) {
            $tmp{$_} =~ s/\$(\w+)/\$datas->{$1}/g;
            $tmp{$_} = $class->regRemoteIp( $tmp{$_} );
        }

        my $sub;
        foreach ( keys %tmp ) {
            $sub .=
              "lmSetHeaderIn(\$apacheRequest,'$_' => join('',split(/[\\r\\n]+/,"
              . $tmp{$_} . ")));";
        }

        #$sub = "\$forgeHeaders->{'$vhost'} = sub {$sub};";
        #eval "$sub";
        $forgeHeaders->{$vhost} = $class->safe->reval("sub {$sub}");
        $class->lmLog( "$class: Unable to forge headers: $@: sub {$sub}",
            'error' )
          if ($@);
    }
    1;
}

## @cmethod void sendHeaders()
# Launch function compiled by forgeHeadersInit() for the current virtual host
sub sendHeaders {
    my $class = shift;
    my $vhost;
    $vhost = $apacheRequest->hostname;
    if ( defined( $forgeHeaders->{$vhost} ) ) {
        &{ $forgeHeaders->{$vhost} };
    }
    else {
        lmSetHeaderIn( $apacheRequest, 'Auth-User' => $datas->{uid} );
    }
}

## @cmethod boolean grant()
# Grant or refuse client using compiled regexp and functions
# @return True if the user is granted to access to the current URL
sub grant {
    my ( $class, $uri ) = @_;
    my $vhost = $apacheRequest->hostname;
    for ( my $i = 0 ; $i < $locationCount->{$vhost} ; $i++ ) {
        if ( $uri =~ $locationRegexp->{$vhost}->[$i] ) {
            return &{ $locationCondition->{$vhost}->[$i] }($datas);
        }
    }
    unless ( $defaultCondition->{$vhost} ) {
        $class->lmLog(
            "User rejected because VirtualHost \"$vhost\" has no configuration",
            'warn'
        );
        return 0;
    }
    return &{ $defaultCondition->{$vhost} }($datas);
}

1;

__END__

=head1 NAME

Lemonldap::NG::Handler::Vhost - Perl extension for building a Lemonldap::NG
compatible handler able to manage Apache virtual hosts.

=head1 SYNOPSIS

Create your own package:

  package My::Package;
  use Lemonldap::NG::Handler::Vhost;
  
  # IMPORTANT ORDER
  our @ISA = qw (Lemonldap::NG::Handler::Vhost Lemonldap::NG::Handler::Simple);
  
  __PACKAGE__->init ( { locationRules => {
             'vhost1.dc.com' => {
                 'default' => '$ou =~ /brh/'
             },
             'vhost2.dc.com' => {
                 '^/pj/.*$'       => '$qualif="opj"',
                 '^/rh/.*$'       => '$ou=~/brh/',
                 '^/rh_or_opj.*$' => '$qualif="opj" or $ou=~/brh/',
                 default          => 'accept',
             },
             # Put here others Lemonldap::NG::Handler::Simple options
           }
         );

Call your package in <apache-directory>/conf/httpd.conf

  PerlRequire MyFile
  PerlHeaderParserHandler My::Package

=head1 DESCRIPTION

This library provides a way to protect Apache virtual hosts with Lemonldap::NG.

=head2 INITIALISATION PARAMETERS

Lemonldap::NG::Handler::Vhost splits the locationRules parameter into a hash
reference which contains anonymous hash references as used by
L<Lemonldap::NG::Handler::Simple>.

=head1 SEE ALSO

L<Lemonldap::NG::Handler(3)>,
http://wiki.lemonldap.objectweb.org/xwiki/bin/view/NG/Presentation

=head1 AUTHOR

Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=head1 BUG REPORT

Use OW2 system to report bug or ask for features:
L<http://forge.objectweb.org/tracker/?group_id=274>

=head1 DOWNLOAD

Lemonldap::NG is available at
L<http://forge.objectweb.org/project/showfiles.php?group_id=274>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Xavier Guimard E<lt>x.guimard@free.frE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.

=cut
