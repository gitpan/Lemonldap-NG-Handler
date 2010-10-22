##@file
# Sympa autologin

##@class
# Sympa autologin
#
# Build Sympa cookie and send it to Sympa
package Lemonldap::NG::Handler::SympaAutoLogin;

use strict;
use Lemonldap::NG::Handler::SharedConf qw(:all);
use base qw(Lemonldap::NG::Handler::SharedConf);
use Digest::MD5;

our $VERSION = '0.991';

# Shared variables
our ( $sympaSecret, $sympaMailKey );

## @imethod protected void defaultValuesInit(hashRef args)
# Overload defaultValuesInit
# @param $args reference to the configuration hash
sub defaultValuesInit {
    my ( $class, $args ) = splice @_;

    # Sympa secret should be in configuration
    $sympaSecret = $args->{'sympaSecret'} || $sympaSecret;

    # If not, try to read it from /etc/lemonldap-ng/sympa.secret
    if ( !$sympaSecret and -r '/etc/lemonldap-ng/sympa.secret' ) {
        open S, '/etc/lemonldap-ng/sympa.secret'
          or die("Unable to open /etc/lemonldap-ng/sympa.secret");
        $sympaSecret = join( '', <S> );
        close S;
        $sympaSecret =~ s/[\r\n]//g;
    }

    # Sympa mail key
    $sympaMailKey = $args->{'sympaMailKey'} || $sympaMailKey || "mail";

    # Display found values in debug mode
    $class->lmLog( "sympaSecret: $sympaSecret",   'debug' );
    $class->lmLog( "sympaMailKey: $sympaMailKey", 'debug' );

    # Delete Sympa parameters
    delete $args->{'sympaSecret'};
    delete $args->{'sympaMailKey'};

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

    # Fail if no sympaSecret
    return $class->abort("No Sympa secret configured")
      unless ($sympaSecret);

    # Mail value
    my $mail = $datas->{$sympaMailKey};

    # Building Sympa cookie
    my $tmp = new Digest::MD5;
    $tmp->reset;
    $tmp->add( $mail . $sympaSecret );
    my $str = "sympauser=$mail:" . substr( unpack( "H*", $tmp->digest ), -8 );

    # Get cookie header, removing Sympa cookie if exists (avoid security
    # problems) and set the new value
    $tmp = lmHeaderIn( $r, 'Cookie' );
    $tmp =~ s/\bsympauser=[^,;]*[,;]?//;
    $tmp .= $tmp ? ";$str" : $str;
    lmSetHeaderIn( $r, 'Cookie' => $tmp );

    # Return SUPER::run() result
    return $ret;
}

1;

__END__

=head1 NAME

=encoding utf8

Lemonldap::NG::Handler::SympaAutoLogin - Perl extension to generate Sympa cookie
for users authenticated by LemonLDAP::NG

=head1 SYNOPSIS

  package My::Sympa;
  use Lemonldap::NG::Handler::SympaAutoLogin;
  @ISA = qw(Lemonldap::NG::Handler::SympaAutoLogin);

  __PACKAGE__->init ( {

    # Sympa parameters
    sympaSecret => 'XXXX',
    sympaMailKey => 'mail',

    # See Lemonldap::NG::Handler for more
  } );
  1;

=head1 DESCRIPTION

Lemonldap::NG::Handler::SympaAutoLogin is a special Lemonldap::NG handler that
generates Sympa cookie for authenticated users. Use it instead of classic
Lemonldap::NG::Handler to protect your Sympa web server. You have to set the
configuration key containing user email (parameter sympaMailKey) and to
store Sympa secret (cookie parameter on Sympa configuration file) in the 
corresponding configuration parameter (sympaSecret)

Edit you Sympa vhost configuration like this:

<VirtualHost *>
        ServerName sympa.example.com

        # Load Sympa Handler
        PerlRequire __HANDLERDIR__/MyHandlerSympa.pm
        PerlHeaderParserHandler My::Sympa

</VirtualHost>

=head2 EXPORT

See L<Lemonldap::NG::Handler>

=head1 SEE ALSO

L<Lemonldap::NG::Handler>

=head1 AUTHOR

Xavier Guimard, E<lt>x.guimard@free.frE<gt>
Clement Oudot,  E<lt>clement@oodo.netE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Xavier Guimard

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
