##@file
# Auth-basic authentication with Lemonldap::NG rights management

##@class
# Auth-basic authentication with Lemonldap::NG rights management

# This specific handler is intended to be called directly by Apache

package Lemonldap::NG::Handler::Specific::AuthBasic;

use strict;

use Lemonldap::NG::Handler::SharedConf qw(:all);
use Digest::MD5 qw(md5_base64);
use MIME::Base64;
use HTTP::Headers;
use SOAP::Lite;    # link protected portalRequest
use Lemonldap::NG::Handler::Main::Headers;
use Lemonldap::NG::Handler::Main::Logger;
use Lemonldap::NG::Common::Session;

use base qw(Lemonldap::NG::Handler::SharedConf);
use utf8;
no utf8;

our $VERSION = '1.4.1';

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
            Lemonldap::NG::Handler::Main::Logger->lmLog(
                "$class: No configuration found", 'error' );
            return $tmp;
        }
    }
    return DECLINED unless ( $apacheRequest->is_initial_req );
    my $uri = $apacheRequest->uri
      . ( $apacheRequest->args ? "?" . $apacheRequest->args : "" );

    # AUTHENTICATION
    # I - recover the WWW-Authentication header
    my ( $id, $user, $pass );
    unless (
        $user = Lemonldap::NG::Handler::Main::Headers->lmHeaderIn(
            $apacheRequest, 'Authorization'
        )
      )
    {
        Lemonldap::NG::Handler::Main::Headers->lmSetErrHeaderOut(
            $apacheRequest,
            'WWW-Authenticate' => 'Basic realm="LemonLDAP::NG"' );
        return AUTH_REQUIRED;
    }
    $user =~ s/^Basic\s*//;

    # ID for local cache
    $id = md5_base64($user);

    # II - recover the user datas
    #  2.1 search if the user was the same as previous (very efficient in
    #      persistent connection).
    unless ( $id eq $datas->{_cache_id} ) {

        # 2.2 search in the local cache if exists
        my $session_id;
        unless ($tsv->{refLocalStorage}
            and $session_id = $tsv->{refLocalStorage}->get($id) )
        {

            # 2.3 Authentication by Lemonldap::NG::Portal using SOAP request

            # Add client IP as X-Forwarded-For IP in SOAP request
            my $xheader =
              Lemonldap::NG::Handler::Main::Headers->lmHeaderIn( $apacheRequest,
                'X-Forwarded-For' );
            $xheader .= ", " if ($xheader);
            $xheader .= $class->ip();
            my $soapHeaders =
              HTTP::Headers->new( "X-Forwarded-For" => $xheader );

            my $soap =
              SOAP::Lite->proxy( $class->portal(),
                default_headers => $soapHeaders )
              ->uri('urn:Lemonldap::NG::Common::CGI::SOAPService');
            $user = decode_base64($user);
            ( $user, $pass ) = ( $user =~ /^(.*?):(.*)$/ );
            Lemonldap::NG::Handler::Main::Logger->lmLog(
                "AuthBasic authentication for user: $user", 'debug' );
            my $r = $soap->getCookies( $user, $pass );

            # Catch SOAP errors
            if ( $r->fault ) {
                return $class->abort( "SOAP request to the portal failed: "
                      . $r->fault->{faultstring} );
            }
            else {
                my $res = $r->result();

                # If authentication failed, display error
                if ( $res->{errorCode} ) {
                    Lemonldap::NG::Handler::Main::Logger->lmLog(
                        "Authentication failed for $user: "
                          . $soap->error( $res->{errorCode}, 'en' )->result(),
                        'notice'
                    );
                    Lemonldap::NG::Handler::Main::Headers->lmSetErrHeaderOut(
                        $apacheRequest,
                        'WWW-Authenticate' => 'Basic realm="LemonLDAP::NG"' );
                    return AUTH_REQUIRED;
                }
                $session_id = $res->{cookies}->{ $tsv->{cookieName} };
            }
        }

        # Get the session
        my $apacheSession = Lemonldap::NG::Common::Session->new(
            {
                storageModule        => $tsv->{globalStorage},
                storageModuleOptions => $tsv->{globalStorageOptions},
                cacheModule          => $tsv->{localSessionStorage},
                cacheModuleOptions   => $tsv->{localSessionStorageOptions},
                id                   => $session_id,
                kind                 => "SSO",
            }
        );

        if ( $apacheSession->error ) {
            Lemonldap::NG::Handler::Main::Logger->lmLog(
                "The cookie $session_id isn't yet available", 'info' );
            Lemonldap::NG::Handler::Main::Logger->lmLog( $apacheSession->error,
                'info' );
            $class->updateStatus( $class->ip(), $apacheRequest->uri,
                'EXPIRED' );
            return $class->goToPortal($uri);
        }

        $datas->{$_} = $apacheSession->data->{$_}
          foreach ( keys %{ $apacheSession->data } );
        $datas->{_cache_id} = $id;

        # Store now the user in the local storage
        if ( $tsv->{refLocalStorage} ) {
            $tsv->{refLocalStorage}
              ->set( $id, $datas->{_session_id}, "20 minutes" );
        }
    }

    # ACCOUNTING
    # 1 - Inform Apache
    $class->lmSetApacheUser( $apacheRequest, $datas->{ $tsv->{whatToTrace} } );

    # AUTHORIZATION
    return $class->forbidden($uri) unless ( $class->grant($uri) );
    $class->updateStatus( $datas->{ $tsv->{whatToTrace} },
        $apacheRequest->uri, 'OK' );
    $class->logGranted( $uri, $datas );

    # SECURITY
    # Hide Lemonldap::NG cookie
    $class->hideCookie;

    # Hide user password
    Lemonldap::NG::Handler::Main::Headers->lmUnsetHeaderIn( $apacheRequest,
        "Authorization" );

    # ACCOUNTING
    # 2 - Inform remote application
    Lemonldap::NG::Handler::Main::Headers->sendHeaders( $apacheRequest,
        $tsv->{forgeHeaders} );

    OK;
}

__PACKAGE__->init( {} );

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

=over

=item Clement Oudot, E<lt>clem.oudot@gmail.comE<gt>

=item François-Xavier Deltombe, E<lt>fxdeltombe@gmail.com.E<gt>

=item Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=back

=head1 BUG REPORT

Use OW2 system to report bug or ask for features:
L<http://jira.ow2.org>

=head1 DOWNLOAD

Lemonldap::NG is available at
L<http://forge.objectweb.org/project/showfiles.php?group_id=274>

=head1 COPYRIGHT AND LICENSE

=over

=item Copyright (C) 2008, 2009, 2010 by Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=item Copyright (C) 2012, 2013 by François-Xavier Deltombe, E<lt>fxdeltombe@gmail.com.E<gt>

=item Copyright (C) 2010, 2011, 2012 by Clement Oudot, E<lt>clem.oudot@gmail.comE<gt>

=back

This library is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see L<http://www.gnu.org/licenses/>.

=cut
