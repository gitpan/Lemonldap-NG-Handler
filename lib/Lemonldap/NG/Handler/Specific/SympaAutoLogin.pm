##@file
# Sympa autologin

##@class
# Sympa autologin
#
# Build Sympa cookie and send it to Sympa

# This specific handler is intended to be called directly by Apache

package Lemonldap::NG::Handler::Specific::SympaAutoLogin;

use strict;
use Lemonldap::NG::Handler::SharedConf qw(:all);
use base qw(Lemonldap::NG::Handler::SharedConf);
use Digest::MD5;
use Lemonldap::NG::Handler::Main::Headers;
use Lemonldap::NG::Handler::Main::Logger;

our $VERSION = '1.1.2';

# Shared variables
our ( $sympaSecret, $sympaMailKey );

## @imethod protected void globalInit(hashRef args)
# Overload globalInit to launch this class defaultValuesInit
# @param $args reference to the configuration hash
sub globalInit {
    my $class = shift;
    __PACKAGE__->defaultValuesInit(@_);
    $class->SUPER::globalInit(@_);
}

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
    Lemonldap::NG::Handler::Main::Logger->lmLog( "sympaSecret: $sympaSecret",
        'debug' );
    Lemonldap::NG::Handler::Main::Logger->lmLog( "sympaMailKey: $sympaMailKey",
        'debug' );

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
    $tmp = Lemonldap::NG::Handler::Main::Headers->lmHeaderIn( $r, 'Cookie' );
    $tmp =~ s/\bsympauser=[^,;]*[,;]?//;
    $tmp .= $tmp ? ";$str" : $str;
    Lemonldap::NG::Handler::Main::Headers->lmSetHeaderIn( $r,
        'Cookie' => $tmp );

    # Return SUPER::run() result
    return $ret;
}

__PACKAGE__->init( {} );

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

=over

=item Clement Oudot, E<lt>clem.oudot@gmail.comE<gt>

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

=item Copyright (C) 2009, 2010 by Xavier Guimard, E<lt>x.guimard@free.frE<gt>

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
