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

our $VERSION = '1.1.2';

# Shared variables
our (
    $secureTokenMemcachedServers,    $secureTokenExpiration,
    $secureTokenAttribute,           $secureTokenUrls,
    $secureTokenHeader,              $datas,
    $secureTokenMemcachedConnection, $secureTokenAllowOnError,
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
    $args->{'secureTokenAllowOnError'} = 1
      unless defined $args->{'secureTokenAllowOnError'};
    $secureTokenAllowOnError =
      defined $secureTokenAllowOnError
      ? $secureTokenAllowOnError
      : $args->{'secureTokenAllowOnError'};

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
    $class->lmLog( "secureTokenAllowOnError: $secureTokenAllowOnError",
        'debug' );

    # Delete Secure Token parameters
    delete $args->{'secureTokenMemcachedServers'};
    delete $args->{'secureTokenExpiration'};
    delete $args->{'secureTokenAttribute'};
    delete $args->{'secureTokenUrls'};
    delete $args->{'secureTokenHeader'};
    delete $args->{'secureTokenAllowOnError'};

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

    # Test Memcached connection
    unless ( $class->_isAlive() ) {
        $secureTokenMemcachedConnection = $class->_createMemcachedConnection();
    }

    # Exit if no connection
    return $class->_returnError() unless $class->_isAlive();

    # Value to store
    my $value = $datas->{$secureTokenAttribute};

    # Set token
    my $key = $class->_setToken($value);
    return $class->_returnError() unless $key;

    # Header location
    $class->lmSetHeaderIn( $r, $secureTokenHeader => $key );

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

    $class->lmLog( "Memcached connection created", 'debug' );

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

## @method private boolean _isAlive()
# Run a STATS command to see if Memcached connection is alive
# @param connection Cache::Memcached object
# @return result
sub _isAlive {
    my ($class) = splice @_;

    return 0 unless defined $secureTokenMemcachedConnection;

    my $stats = $secureTokenMemcachedConnection->stats();

    if ( $stats and defined $stats->{'total'} ) {
        my $total_c = $stats->{'total'}->{'connection_structures'};
        my $total_i = $stats->{'total'}->{'total_items'};

        $class->lmLog(
"Memcached connection is alive ($total_c connections / $total_i items)",
            'debug'
        );

        return 1;
    }

    $class->lmLog( "Memcached connection is not alive", 'error' );

    return 0;
}

## @method private int _returnError()
# Give hand back to Apache
# @return Apache2::Const value
sub _returnError {
    my ($class) = splice @_;

    if ($secureTokenAllowOnError) {
        $class->lmLog( "Allow request without secure token", 'debug' );
        return OK;
    }

    # Redirect or Forbidden?
    if ($useRedirectOnError) {
        $class->lmLog( "Use redirect for error", 'debug' );
        return $class->goToPortal( '/', 'lmError=500' );
    }

    else {
        $class->lmLog( "Return error", 'debug' );
        return SERVER_ERROR;
    }
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

