## @file
# Lemonldap::NG special handler

## @class
# Lemonldap::NG special handler
package Lemonldap::NG::Handler::UpdateCookie;

use strict;
use Lemonldap::NG::Handler::SharedConf qw(:all);
use base qw(Lemonldap::NG::Handler::SharedConf);

our $VERSION = '1.2.2_01';

## @rmethod int run(Apache2::RequestRec apacheRequest)
# Main method used to control access.
# Calls :
# - fetchId()
# - fetchUTime()
# - SUPER::run()
# @param $apacheRequest Current request
# @return Apache2::Const value (OK, FORBIDDEN, REDIRECT or SERVER_ERROR)
sub run {
    my $class = shift;
    $apacheRequest = $_[0];

    # I - Recover the main cookie.
    #     If not present, then call parent.
    my $id;
    if ( $id = $class->SUPER::fetchId ) {

        # II - Found update cookie.
        #      If found, remove session from local cache when utime is recent.
        my $utime;
        if ( $utime = $class->fetchUTime ) {
            my $clear = 0;
            if ( $id eq $datas->{_session_id} and $datas->{_utime} lt $utime ) {
                $datas->{_session_id} = 0;
                $clear = 1;
            }
            elsif ( $refLocalStorage
                and my $ldatas = $refLocalStorage->get($id) )
            {
                if ( $ldatas->{_utime} lt $utime ) {
                    $clear = 1;
                }
            }
            if ($clear) {
                $class->lmLog( "$class: remove $id from local cache", 'debug' );
                $refLocalStorage->remove($id);
            }
        }

    }

    # III - Call parent process.
    $class->SUPER::run(@_);
}

## @rmethod protected $ fetchUTime()
# Get user cookies and search for Lemonldap::NG update cookie.
# @return Value of the cookie if found, 0 else
sub fetchUTime {
    my $t = lmHeaderIn( $apacheRequest, 'Cookie' );
    my $c = $cookieName . 'update';
    return ( $t =~ /$c=([^,; ]+)/o ) ? $1 : 0;
}

1;
__END__

=head1 NAME

=encoding utf8

Lemonldap::NG::Handler::UpdateCookie - Perl extension to manage update
cookie sent by client, to reload session in local cache.

=head1 SYNOPSIS

  package My::Package;
  use Lemonldap::NG::Handler::UpdateCookie;
  @ISA = qw(Lemonldap::NG::Handler::SharedConf);

  __PACKAGE__->init ( {
    # See Lemonldap::NG::Handler for more
    # Local storage used for sessions and configuration
  } );

=head1 DESCRIPTION

Lemonldap::NG::Handler::UpdateCookie is a special Lemonldap::NG:: handler that
allow a session to be removed from local cache of the current handler, if a
update cookie is sent by the user.

The update cookie should be name "lemonldapupdate" and only contains a simple
timestamp.

=head2 EXPORT

See L<Lemonldap::NG::Handler>

=head1 SEE ALSO

L<Lemonldap::NG::Handler>

=head1 AUTHOR

Thomas Chemineau, E<lt>thomas.chemineau@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Thomas Chemineau

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
