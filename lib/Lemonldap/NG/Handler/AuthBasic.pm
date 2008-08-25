package Lemonldap::NG::Handler::AuthBasic;

use strict;

use Lemonldap::NG::Handler::SharedConf qw(:all);
use Lemonldap::NG::Portal::SharedConf;
use Digest::MD5 qw(md5_base64);
use MIME::Base64;

our @ISA = qw(Lemonldap::NG::Handler::SharedConf);

our $VERSION = '0.01';

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

# overload of run subroutine
sub run ($$) {
    my $class;
    ( $class, $apacheRequest ) = @_;
    if ( time() - $lastReload > $reloadTime ) {
        unless ( $class->localConfUpdate($apacheRequest) == OK ) {
            $class->lmLog( "$class: No configuration found", 'error' );
            return SERVER_ERROR;
        }
    }
    return DECLINED unless ( $apacheRequest->is_initial_req );
    my $uri = $apacheRequest->uri . ( $apacheRequest->args ? "?" . $apacheRequest->args : "" );

    # AUTHENTICATION
    # I - recover the WWW-Authentication header
    my ( $id, $user, $pass );
    unless ( $user = lmHeaderIn( $apacheRequest, 'Authorization' ) ) {
        lmSetErrHeaderOut ( $apacheRequest, 'WWW-Authenticate' => 'Basic realm="Lemonldap::NG"' );
        return AUTH_REQUIRED;
    }
    $user =~ s/^Basic\s*//;
    # DEBUG
    $class->lmLog("debug : $user",'notice');
    $id = md5_base64($user);

    # II - recover the user datas
    #  2.1 search if the user was the same as previous (very efficient in
    #      persistent connection).
    unless ( $id eq $datas->{_session_id} ) {

        # 2.2 search in the local cache if exists
        unless ( $refLocalStorage and $datas = $refLocalStorage->get($id) ) {

            # 2.3 Authentication by Lemonldap::NG::Portal
            my $portal = Lemonldap::NG::Portal::SharedConf->new ( {
                configStorage => $Lemonldap::NG::Conf::configStorage,
                controlUrlOrigin => sub {PE_OK},
                controlExistingSession => sub {PE_OK},
                extractFormInfo => sub {PE_OK},
                store => sub {PE_OK},
                buildCookie => sub {PE_OK},
                autoRedirect => sub {PE_OK},
            } );
            ($portal->{user},$portal->{password}) = split /:/,decode_base64($user);
            unless ( $portal->process() ) {
                $class->lmLog( "Fail to authenticate user $user", 'notice' );
                lmSetErrHeaderOut ( $apacheRequest, 'WWW-Authenticate' => 'Basic realm="Lemonldap::NG"' );
                return AUTH_REQUIRED;
            }
            $datas->{$_} = $portal->{sessionInfo}->{$_} foreach ( keys %{ $portal->{sessionInfo} } );
            $datas->{_session_id} = $id;

            # Store now the user in the local storage
            if ($refLocalStorage) {
                $refLocalStorage->set( $id, $datas, "20 minutes" );
            }
        }
    }

    # ACCOUNTING
    # 1 - Inform Apache
    lmSetApacheUser( $apacheRequest, $datas->{$whatToTrace} );

    # AUTHORIZATION
    return $class->forbidden($uri) unless ( $class->grant($uri) );
    $class->lmLog(
        "User "
          . $datas->{$whatToTrace}
          . " was authorizated to access to $uri",
        'debug'
    );

    # ACCOUNTING
    # 2 - Inform remote application
    $class->sendHeaders;

    # SECURITY
    # Hide Lemonldap::NG cookie
    $class->hideCookie;
    OK;
}

1;

__END__

=head1 NAME

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

Copyright (C) 2008 by Xavier Guimard E<lt>x.guimard@free.frE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.

=cut
