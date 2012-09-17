##@file
# Auth-basic authentication with Lemonldap::NG rights management

##@class
# Auth-basic authentication with Lemonldap::NG rights management
package Lemonldap::NG::Handler::AuthBasic;

use strict;

use Lemonldap::NG::Handler::SharedConf qw(:all);
use Digest::MD5 qw(md5_base64);
use MIME::Base64;
use SOAP::Lite;    # link protected portalRequest

use base qw(Lemonldap::NG::Handler::SharedConf);
use utf8;
no utf8;

our $VERSION = '1.2.2';

# We need just this constant, that's why Portal is 'required' but not 'used'
*PE_OK = *Lemonldap::NG::Portal::SharedConf::PE_OK;

# Apache constants
BEGIN {
    if ( MP() == 2 ) {
        *AUTH_REQUIRED = \&Apache2::Const::AUTH_REQUIRED;
        require Apache2::Access;
    }
    elsif ( MP() == 0 ) {
        eval 'sub AUTH_REQUIRED {1}';
    }
}

## @rmethod int run(Apache2::RequestRec apacheRequest)
# overload run subroutine to implement Auth-Basic mechanism.
# @param $apacheRequest current request
# @return Apache constant
sub run ($$) {
    my $class;
    ( $class, $apacheRequest ) = splice @_;
    if ( time() - $lastReload > $reloadTime ) {
        unless ( my $tmp = $class->testConf(1) == OK ) {
            $class->lmLog( "$class: No configuration found", 'error' );
            return $tmp;
        }
    }
    return DECLINED unless ( $apacheRequest->is_initial_req );
    my $uri = $apacheRequest->uri
      . ( $apacheRequest->args ? "?" . $apacheRequest->args : "" );

    # AUTHENTICATION
    # I - recover the WWW-Authentication header
    my ( $id, $user, $pass );
    unless ( $user = lmHeaderIn( $apacheRequest, 'Authorization' ) ) {
        lmSetErrHeaderOut( $apacheRequest,
            'WWW-Authenticate' => 'Basic realm="LemonLDAP::NG"' );
        return AUTH_REQUIRED;
    }
    $user =~ s/^Basic\s*//;

    # DEBUG
    $id = md5_base64($user);

    # II - recover the user datas
    #  2.1 search if the user was the same as previous (very efficient in
    #      persistent connection).
    unless ( $id eq $datas->{_session_id} ) {

        # 2.2 search in the local cache if exists
        unless ( $refLocalStorage and $datas = $refLocalStorage->get($id) ) {

            # 2.3 Authentication by Lemonldap::NG::Portal using SOAP request
            my $soap =
              SOAP::Lite->proxy( $class->portal() )
              ->uri('urn:Lemonldap::NG::Common::CGI::SOAPService');
            $user = decode_base64($user);
            ( $user, $pass ) = ( $user =~ /^(.*?):(.*)$/ );
            $class->lmLog( "AuthBasic authentication for user: $user",
                'debug' );
            my $r = $soap->getCookies( $user, $pass );
            my $cv;

            # Catch SOAP errors
            if ( $r->fault ) {
                return $class->abort( "SOAP request to the portal failed: "
                      . $r->fault->{faultstring} );
            }
            else {
                my $res = $r->result();

                # If authentication failed, display error
                if ( $res->{errorCode} ) {
                    $class->lmLog(
                        "Authentication failed for $user: "
                          . $soap->error( $res->{errorCode}, 'en' )->result(),
                        'notice'
                    );
                    lmSetErrHeaderOut( $apacheRequest,
                        'WWW-Authenticate' => 'Basic realm="LemonLDAP::NG"' );
                    return AUTH_REQUIRED;
                }
                $cv = $res->{cookies}->{$cookieName};
            }

            # Now, normal work to find session
            my %h;
            eval { tie %h, $globalStorage, $cv, $globalStorageOptions; };
            if ($@) {

                # The cookie isn't yet available
                $class->lmLog( "The cookie $cv isn't yet available: $@",
                    'info' );
                $class->updateStatus( $apacheRequest->connection->remote_ip,
                    $apacheRequest->uri, 'EXPIRED' );
                return $class->goToPortal($uri);
            }
            $datas->{$_} = $h{$_} foreach ( keys %h );

            # Store now the user in the local storage
            if ($refLocalStorage) {
                $refLocalStorage->set( $id, $datas, "20 minutes" );
            }
            untie %h;
        }
    }

    # ACCOUNTING
    # 1 - Inform Apache
    $class->lmSetApacheUser( $apacheRequest, $datas->{$whatToTrace} );

    # AUTHORIZATION
    return $class->forbidden($uri) unless ( $class->grant($uri) );
    $class->updateStatus( $datas->{$whatToTrace}, $apacheRequest->uri, 'OK' );
    $class->logGranted( $uri, $datas );

    # ACCOUNTING
    # 2 - Inform remote application
    $class->sendHeaders;

    # SECURITY
    # Hide Lemonldap::NG cookie
    $class->hideCookie;

    # Hide user password
    $class->lmSetHeaderIn( $apacheRequest, Authorization => '' );
    OK;
}

1;

__END__

=head1 NAME

=encoding utf8

Lemonldap::NG::Handler::AuthBasic - Perl extension to be able to authenticate
users by basic web system but to use Lemonldap::NG to control authorizations.

=head1 SYNOPSIS

Create your own package:

  package My::Package;
  use Lemonldap::NG::Handler::AuthBasic;
  
  # IMPORTANT ORDER
  our @ISA = qw (Lemonldap::NG::Handler::AuthBasic);
  
  __PACKAGE__->init ( {
    # Local storage used for sessions and configuration
    localStorage        => "Cache::DBFile",
    localStorageOptions => {...},
    # How to get my configuration
    configStorage       => {
        type                => "DBI",
        dbiChain            => "DBI:mysql:database=lemondb;host=$hostname",
        dbiUser             => "lemonldap",
        dbiPassword         => "password",
    }
    # Uncomment this to activate status module
    # status                => 1,
  } );

Call your package in <apache-directory>/conf/httpd.conf

  PerlRequire MyFile
  PerlHeaderParserHandler My::Package

=head1 DESCRIPTION

This library provides a way to use Lemonldap::NG to manage authorizations
without using Lemonldap::NG for authentications. This can be used in conjunction
with a normal Lemonldap::NG installation but to manage non-browser clients.

=head1 SEE ALSO

L<Lemonldap::NG::Handler(3)>,
L<http://lemonldap-ng.org/>

=head1 AUTHOR

Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=head1 BUG REPORT

Use OW2 system to report bug or ask for features:
L<http://jira.ow2.org>

=head1 DOWNLOAD

Lemonldap::NG is available at
L<http://forge.objectweb.org/project/showfiles.php?group_id=274>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2008, 2010 by Xavier Guimard E<lt>x.guimard@free.frE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
