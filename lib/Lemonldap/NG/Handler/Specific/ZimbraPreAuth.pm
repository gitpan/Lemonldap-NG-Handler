##@file
# Zimbra preauthentication

##@class
# Zimbra preauthentication
#
# It will build Zimbra preauth URL

# This specific handler is intended to be called directly by Apache

package Lemonldap::NG::Handler::Specific::ZimbraPreAuth;

use strict;
use Lemonldap::NG::Handler::SharedConf qw(:all);
use base qw(Lemonldap::NG::Handler::SharedConf);
use Digest::HMAC_SHA1 qw(hmac_sha1 hmac_sha1_hex);
use Lemonldap::NG::Handler::Main::Headers;
use Lemonldap::NG::Handler::Main::Logger;

our $VERSION = '1.0.0';

# Shared variables
our ( $zimbraPreAuthKey, $zimbraAccountKey, $zimbraBy, $zimbraUrl,
    $zimbraSsoUrl, $timeout );

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

    # Catch Zimbra parameters
    $zimbraPreAuthKey = $args->{'zimbraPreAuthKey'} || $zimbraPreAuthKey;
    $zimbraAccountKey =
         $args->{'zimbraAccountKey'}
      || $zimbraAccountKey
      || 'uid';
    $zimbraBy  = $args->{'zimbraBy'}  || $zimbraBy  || 'id';
    $zimbraUrl = $args->{'zimbraUrl'} || $zimbraUrl || '/service/preauth';
    $zimbraSsoUrl = $args->{'zimbraSsoUrl'} || $zimbraSsoUrl || '^/zimbrasso$';
    $timeout      = $args->{'timeout'}      || $timeout      || '0';

    # Display found values in debug mode
    Lemonldap::NG::Handler::Main::Logger->lmLog(
        "zimbraPreAuthKey: $zimbraPreAuthKey", 'debug' );
    Lemonldap::NG::Handler::Main::Logger->lmLog(
        "zimbraAccountKey: $zimbraAccountKey", 'debug' );
    Lemonldap::NG::Handler::Main::Logger->lmLog( "zimbraBy: $zimbraBy",
        'debug' );
    Lemonldap::NG::Handler::Main::Logger->lmLog( "zimbraUrl: $zimbraUrl",
        'debug' );
    Lemonldap::NG::Handler::Main::Logger->lmLog( "zimbraSsoUrl: $zimbraSsoUrl",
        'debug' );
    Lemonldap::NG::Handler::Main::Logger->lmLog( "timeout: $timeout", 'debug' );

    # Delete Zimbra parameters
    delete $args->{'zimbraPreAuthKey'};
    delete $args->{'zimbraAccountKey'};
    delete $args->{'zimbraBy'};
    delete $args->{'zimbraUrl'};
    delete $args->{'zimbraSsoUrl'};
    delete $args->{'timeout'};

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

    # Return if we are not on a Zimbra SSO URI
    return OK unless ( $uri =~ $zimbraSsoUrl );

    # Check mandatory parameters
    return $class->abort("No Zimbra preauth key configured")
      unless ($zimbraPreAuthKey);

    # Build URL
    my $zimbra_url = $class->_buildZimbraPreAuthUrl(
        $zimbraPreAuthKey,           $zimbraUrl,
        $datas->{$zimbraAccountKey}, $zimbraBy
    );

    # Header location
    Lemonldap::NG::Handler::Main::Headers->lmSetHeaderOut( $r,
        'Location' => $zimbra_url );

    # Return REDIRECT
    return REDIRECT;
}

## @method private string _buildZimbraPreAuthUrl(string key, string url, string account, string by)
# Build Zimbra PreAuth URL
# @param key PreAuthKey
# @param url URL
# @param account User account
# @param by Account type
# @return Zimbra PreAuth URL
sub _buildZimbraPreAuthUrl {
    my ( $class, $key, $url, $account, $by ) = splice @_;

    # Expiration time is calculated with _utime and timeout
    my $expires = $timeout ? ( $datas->{_utime} + $timeout ) * 1000 : $timeout;

    # Timestamp
    my $timestamp = time() * 1000;

    # Compute preauth value
    my $computed_value =
      hmac_sha1_hex( "$account|$by|$expires|$timestamp", $key );

    Lemonldap::NG::Handler::Main::Logger->lmLog(
        "Compute value $account|$by|$expires|$timestamp into $computed_value",
        'debug' );

    # Build PreAuth URL
    my $zimbra_url =
"$url?account=$account&by=$by&timestamp=$timestamp&expires=$expires&preauth=$computed_value";

    Lemonldap::NG::Handler::Main::Logger->lmLog(
        "Build Zimbra URL: $zimbra_url", 'debug' );

    return $zimbra_url;
}

__PACKAGE__->init( {} );

1;

__END__

=head1 NAME

=encoding utf8

Lemonldap::NG::Handler::ZimbraPreAuth - Perl extension to generate Zimbra preauth URL
for users authenticated by Lemonldap::NG

=head1 SYNOPSIS

  package My::Zimbra;
  use Lemonldap::NG::Handler::ZimbraPreAuth;
  @ISA = qw(Lemonldap::NG::Handler::ZimbraPreAuth);

  __PACKAGE__->init ( {

    # Zimbra parameters
    zimbraPreAuthKey => 'XXXX',
    zimbraAccountKey => 'uid',
    zimbraBy         => 'id',
    zimbraUrl        => '/service/preauth',
    zimbraSsoUrl     => '^/zimbrasso$',

    # Common parameters
    timeout          => '72000',

    # See Lemonldap::NG::Handler for more

  } );
  1;

=head1 DESCRIPTION

Edit you Zimbra vhost configuration like this:

<VirtualHost *>
	ServerName zimbra.example.com

	# Load Zimbra Handler
	PerlRequire __HANDLERDIR__/MyHandlerZimbra.pm
		PerlHeaderParserHandler My::Zimbra

</VirtualHost>

=head2 EXPORT

See L<Lemonldap::NG::Handler>

=head1 SEE ALSO

L<http://wiki.zimbra.com/wiki/Preauth>
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

=item Copyright (C) 2010 by Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=item Copyright (C) 2010, 2012 by Clement Oudot, E<lt>clem.oudot@gmail.comE<gt>

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
