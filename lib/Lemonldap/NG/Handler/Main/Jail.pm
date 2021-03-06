package Lemonldap::NG::Handler::Main::Jail;

use strict;

use Safe;
use Lemonldap::NG::Common::Safelib;    #link protected safe Safe object
use constant SAFEWRAP => ( Safe->can("wrap_code_ref") ? 1 : 0 );
use Mouse;
use Lemonldap::NG::Handler::Main::Logger;

has customFunctions => ( is => 'rw', isa => 'Maybe[Str]' );

has useSafeJail => ( is => 'rw', isa => 'Maybe[Int]' );

has safe => ( is => 'rw' );

our $VERSION = '1.3.1';

# for accessing $datas and $apacheRequest
use Lemonldap::NG::Handler::Main ':jailSharedVars';

## @imethod protected build_safe()
# Build and return the security jail used to compile rules and headers.
# @return Safe object
sub build_safe {
    my $self = shift;

    return $self->safe if ( $self->safe );

    $self->useSafeJail(1) unless defined $self->useSafeJail;

    my @t =
      $self->customFunctions ? split( /\s+/, $self->customFunctions ) : ();
    foreach (@t) {
        Lemonldap::NG::Handler::Main::Logger->lmLog( "Custom function : $_",
            'debug' );
        my $sub = $_;
        unless (/::/) {
            $sub = "$self\::$_";
        }
        else {
            s/^.*:://;
        }
        next if ( $self->can($_) );
        eval "sub $_ {
            my \$uri = \$Lemonldap::NG::Handler::Main::apacheRequest->unparsed_uri();
            Apache2::URI::unescape_url(\$uri);
            return $sub(\$uri, \@_)
            }";
        Lemonldap::NG::Handler::Main::Logger->lmLog( $@, 'error' ) if ($@);
    }

    if ( $self->useSafeJail ) {
        $self->safe( Safe->new );
        $self->safe->share_from( 'main', ['%ENV'] );
    }
    else {
        $self->safe($self);
    }

    # Share objects with Safe jail
    $self->safe->share_from( 'Lemonldap::NG::Common::Safelib',
        $Lemonldap::NG::Common::Safelib::functions );

    $self->safe->share_from( 'Lemonldap::NG::Handler::Main',
        [ '$datas', '$apacheRequest', '&ip', '&portal' ] );
    $self->safe->share(@t);
    $self->safe->share_from( 'MIME::Base64', ['&encode_base64'] );

    return $self->safe;
}

## @method reval
# Fake reval method if useSafeJail is off
sub reval {
    my ( $self, $e ) = splice @_;
    return eval $e;
}

## @method wrap_code_ref
# Fake wrap_code_ref method if useSafeJail is off
sub wrap_code_ref {
    my ( $self, $e ) = splice @_;
    return $e;
}

## @method share
# Fake share method if useSafeJail is off
sub share {
    my ( $self, @vars ) = splice @_;
    $self->share_from( scalar(caller), \@vars );
}

## @method share_from
# Fake share_from method if useSafeJail is off
sub share_from {
    my ( $self, $pkg, $vars ) = splice @_;

    no strict 'refs';
    foreach my $arg (@$vars) {
        my ( $var, $type );
        $type = $1 if ( $var = $arg ) =~ s/^(\W)//;
        for ( 1 .. 2 ) {    # assign twice to avoid any 'used once' warnings
            *{$var} =
                ( !$type ) ? \&{ $pkg . "::$var" }
              : ( $type eq '&' ) ? \&{ $pkg . "::$var" }
              : ( $type eq '$' ) ? \${ $pkg . "::$var" }
              : ( $type eq '@' ) ? \@{ $pkg . "::$var" }
              : ( $type eq '%' ) ? \%{ $pkg . "::$var" }
              : ( $type eq '*' ) ? *{ $pkg . "::$var" }
              :                    undef;
        }
    }
}

## @imethod protected jail_reval()
# Build and return restricted eval command with SAFEWRAP, if activated
# @return evaluation of $reval or $reval2
sub jail_reval {
    my ( $self, $reval ) = splice @_;

    # if nothing is returned by reval, add the return statement to
    # the "no safe wrap" reval
    my $nosw_reval = $reval;
    if ( $reval !~ /^sub\{return\(.*\}$/ ) {
        $nosw_reval =~ s/^sub{(.*)}$/sub{return($1)}/;
    }

    return (
        SAFEWRAP
        ? $self->safe->wrap_code_ref( $self->safe->reval($reval) )
        : $self->safe->reval($nosw_reval)
    );

}

1;
