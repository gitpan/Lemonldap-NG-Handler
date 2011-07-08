##@file
# Secure Token

##@class
# Secure Token
#
# Create a secure token used to resolve user identity by a protected application
package Lemonldap::NG::Handler::SecureToken;

use strict;
use Lemonldap::NG::Handler::SharedConf qw(:all);
use base qw(Lemonldap::NG::Handler::SharedConf);
use Cache::Memcached;
use Apache::Session::Generate::MD5;

our $VERSION = '1.1.0';

# Shared variables
our (
    $secureTokenMemcachedServers, $secureTokenExpiration,
    $secureTokenAttribute,        $secureTokenUrls,
    $secureTokenHeader,           $datas,
    $secureTokenMemcachedConnection
);

BEGIN {
    eval {
        require threads::shared;
        threads::share($secureTokenMemcachedConnection);
    };
}

## @imethod protected void defaultValuesInit(hashRef args)
# Overload defaultValuesInit
# @param $args reference to the configuration hash
sub defaultValuesInit {
    my ( $class, $args ) = splice @_;

    # Catch Secure Token parameters
    $secureTokenMemcachedServers =
         $args->{'secureTokenMemcachedServers'}
      || $secureTokenMemcachedServers
      || ['127.0.0.1:11211'];
    $secureTokenExpiration =
         $args->{'secureTokenExpiration'}
      || $secureTokenExpiration
      || '60';
    $secureTokenAttribute =
         $args->{'secureTokenAttribute'}
      || $secureTokenAttribute
      || 'uid';
    $secureTokenUrls = $args->{'secureTokenUrls'} || $secureTokenUrls || ['.*'];
    $secureTokenHeader =
         $args->{'secureTokenHeader'}
      || $secureTokenHeader
      || 'Auth-Token';

    # Force some parameters to be array references
    foreach (qw/secureTokenMemcachedServers secureTokenUrls/) {
        no strict 'refs';
        unless ( ref ${$_} eq "ARRAY" ) {
            $class->lmLog( "Transform $_ value into an array reference",
                'debug' );
            my @array = split( /\s+/, ${$_} );
            ${$_} = \@array;
        }
    }

    # Display found values in debug mode
    $class->lmLog( "secureTokenMemcachedServers: @$secureTokenMemcachedServers",
        'debug' );
    $class->lmLog( "secureTokenExpiration: $secureTokenExpiration", 'debug' );
    $class->lmLog( "secureTokenAttribute: $secureTokenAttribute",   'debug' );
    $class->lmLog( "secureTokenUrls: @$secureTokenUrls",            'debug' );
    $class->lmLog( "secureTokenHeader: $secureTokenHeader",         'debug' );

    # Delete Secure Token parameters
    delete $args->{'secureTokenMemcachedServers'};
    delete $args->{'secureTokenExpiration'};
    delete $args->{'secureTokenAttribute'};
    delete $args->{'secureTokenUrls'};
    delete $args->{'secureTokenHeader'};

    # Call main subroutine
    return $class->SUPER::defaultValuesInit($args);
}

## @rmethod Apache2::Const run(Apache2::RequestRec r)
# Overload main run method
# @param r Current request
# @return Apache2::Const value (OK, FORBIDDEN, REDIRECT or SERVER_ERROR)
sub run {
    my $class = shift;
    my $r     = $_[0];
    my $ret   = $class->SUPER::run(@_);

    # Continue only if user is authorized
    return $ret unless ( $ret == OK );

    # Get current URI
    my $args = $r->args;
    my $uri = $r->uri . ( $args ? "?$args" : "" );

    # Return if we are not on a secure token URL
    my $checkurl = 0;
    foreach (@$secureTokenUrls) {
        if ( $uri =~ m#$_# ) {
            $checkurl = 1;
            $class->lmLog( "URL $uri detected as an Secure Token URL (rule $_)",
                'debug' );
            last;
        }
    }
    return OK unless ($checkurl);

    # Memcached connection
    unless ($secureTokenMemcachedConnection) {
        $secureTokenMemcachedConnection = $class->_createMemcachedConnection();
    }

    # Value to store
    my $value = $datas->{$secureTokenAttribute};

    # Set token
    my $key = $class->_setToken($value);

    # Header location
    lmSetHeaderIn( $r, $secureTokenHeader => $key );

    # Remove token
    eval 'use Apache2::Filter' unless ( $INC{"Apache2/Filter.pm"} );

    $r->add_output_filter(
        sub {
            my $f = shift;
            while ( $f->read( my $buffer, 1024 ) ) {
                $f->print($buffer);
            }
            if ( $f->seen_eos ) {
                $class->_deleteToken($key);
            }
            return OK;
        }
    );

    # Return OK
    return OK;
}

## @method private Cache::Memcached _createMemcachedConnection
# Create Memcached connexion
# @return Cache::Memcached object
sub _createMemcachedConnection {
    my ($class) = splice @_;

    # Open memcached connexion
    my $memd = new Cache::Memcached {
        'servers' => $secureTokenMemcachedServers,
        'debug'   => 0,
    };

    return $memd;
}

## @method private string _setToken(string value)
# Set token value
# @param value Value
# @return Token key
sub _setToken {
    my ( $class, $value ) = splice @_;

    my $key = Apache::Session::Generate::MD5::generate();

    my $res =
      $secureTokenMemcachedConnection->set( $key, $value,
        $secureTokenExpiration );

    unless ($res) {
        $class->lmLog( "Unable to store secure token $key", 'error' );
        return;
    }

    $class->lmLog( "Set $value in token $key", 'info' );

    return $key;
}

## @method private boolean _deleteToken(string key)
# Delete token
# @param key Key
# @return result
sub _deleteToken {
    my ( $class, $key ) = splice @_;

    my $res = $secureTokenMemcachedConnection->delete($key);

    unless ($res) {
        $class->lmLog( "Unable to delete secure token $key", 'error' );
    }
    else {
        $class->lmLog( "Token $key deleted", 'info' );
    }

    return $res;
}

1;

__END__

=head1 NAME

=encoding utf8

Lemonldap::NG::Handler::SecureToken - Perl extension to generate a secure token

=head1 SYNOPSIS

package My::SecureToken;
use Lemonldap::NG::Handler::SecureToken;
@ISA = qw(Lemonldap::NG::Handler::SecureToken);

__PACKAGE__->init ( {

# See Lemonldap::NG::Handler for more

		} );
1;

=head1 DESCRIPTION

Edit your vhost configuration like this:

<VirtualHost *>
ServerName secure.example.com

# Load Secure Token Handler
PerlRequire __HANDLERDIR__/MyHandlerSecureToken.pm
PerlHeaderParserHandler My::SecureToken

</VirtualHost>

=head2 EXPORT

See L<Lemonldap::NG::Handler>

=head1 SEE ALSO

L<Lemonldap::NG::Handler>

=head1 AUTHOR

Clement Oudot, E<lt>coudot@linagora.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Clement Oudot

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
   at your option, any later version of Perl 5 you may have available.

   =cut

