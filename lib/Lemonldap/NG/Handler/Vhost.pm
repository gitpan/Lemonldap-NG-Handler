## @file
# Virtual host support mechanism

## @class
# This class adds virtual host support for Lemonldap::NG handlers.
package Lemonldap::NG::Handler::Vhost;

use strict;
use AutoLoader 'AUTOLOAD';

use Lemonldap::NG::Handler::Simple qw(:locationRules :headers :post :apache)
  ;    #inherits
use MIME::Base64;
use constant SAFEWRAP => ( Safe->can("wrap_code_ref") ? 1 : 0 );

our $VERSION = '1.2.3';

## @imethod protected void defaultValuesInit(hashRef args)
# Set default values for non-customized variables
# @param $args reference to the configuration hash
sub defaultValuesInit {
    my ( $class, $args ) = splice @_;
    foreach my $t (qw(https port maintenance)) {

        # Skip Handler initialization (values not defined)
        next unless defined $args->{$t};

        # Record default value in key '_'
        $args->{$t} = { _ => $args->{$t} } unless ( ref( $args->{$t} ) );

        # Override with vhost options
        if ( defined $args->{vhostOptions} ) {
            my $n = 'vhost' . ucfirst($t);
            foreach my $k ( keys %{ $args->{vhostOptions} } ) {
                my $v = $args->{vhostOptions}->{$k}->{$n};
                $class->lmLog( "Options $t for vhost $k: $v", 'debug' );
                $args->{$t}->{$k} = $v
                  if ( $v >= 0 );    # Keep default value if $v is negative
            }
        }
    }
    $class->Lemonldap::NG::Handler::Simple::defaultValuesInit($args);
}

## @imethod void locationRulesInit(hashRef args)
# Compile rules.
# Rules are stored in $args->{locationRules}->{&lt;virtualhost&gt;} that contains
# regexp=>test expressions where :
# - regexp is used to test URIs
# - test contains an expression used to grant the user
#
# This function creates 2 hashRef containing :
# - one list of the compiled regular expressions for each virtual host
# - one list of the compiled functions (compiled with conditionSub()) for each
# virtual host
# @param $args reference to the configuration hash
sub locationRulesInit {
    my ( $class, $args ) = splice @_;
    foreach my $vhost ( keys %{ $args->{locationRules} } ) {
        $locationCount->{$vhost} = 0;
        foreach ( sort keys %{ $args->{locationRules}->{$vhost} } ) {
            if ( $_ eq 'default' ) {
                ( $defaultCondition->{$vhost}, $defaultProtection->{$vhost} ) =
                  $class->conditionSub(
                    $args->{locationRules}->{$vhost}->{$_} );
            }
            else {
                (
                    $locationCondition->{$vhost}->[ $locationCount->{$vhost} ],
                    $locationProtection->{$vhost}->[ $locationCount->{$vhost} ]
                  )
                  = $class->conditionSub(
                    $args->{locationRules}->{$vhost}->{$_} );
                $locationRegexp->{$vhost}->[ $locationCount->{$vhost} ] =
                  qr/$_/;
                $locationCount->{$vhost}++;
            }
        }

        # Default police
        ( $defaultCondition->{$vhost}, $defaultProtection->{$vhost} ) =
          $class->conditionSub('accept')
          unless ( $defaultCondition->{$vhost} );
    }
    1;
}

## @imethod void forgeHeadersInit(hashRef args)
# Create the &$forgeHeaders->{&lt;virtualhost&gt;} subroutines used to insert
# headers into the HTTP request.
# @param $args reference to the configuration hash
sub forgeHeadersInit {
    my ( $class, $args ) = splice @_;

    # Creation of the subroutine who will generate headers
    foreach my $vhost ( keys %{ $args->{exportedHeaders} } ) {
        my %tmp = %{ $args->{exportedHeaders}->{$vhost} };
        foreach ( keys %tmp ) {
            $tmp{$_} =~ s/\$(\w+)/\$datas->{$1}/g;
            $tmp{$_} = $class->regRemoteIp( $tmp{$_} );
        }

        my $sub;
        foreach ( keys %tmp ) {
            $sub .= "'$_' => join('',split(/[\\r\\n]+/,$tmp{$_})),";
        }

        $forgeHeaders->{$vhost} = (
            SAFEWRAP
            ? $class->safe->wrap_code_ref( $class->safe->reval("sub {$sub}") )
            : $class->safe->reval("sub {return($sub)}")
        );
        $class->lmLog( "$class: Unable to forge headers: $@: sub {$sub}",
            'error' )
          if ($@);
    }
    1;
}

## @imethod void headerListInit(hashRef args)
# Lists the exported HTTP headers into $headerList
# @param $args reference to the configuration hash
sub headerListInit {
    my ( $class, $args ) = splice @_;

    foreach my $vhost ( keys %{ $args->{exportedHeaders} } ) {
        my @tmp = keys %{ $args->{exportedHeaders}->{$vhost} };
        $headerList->{$vhost} = \@tmp;
    }
    1;
}

## @rmethod void sendHeaders()
# Launch function compiled by forgeHeadersInit() for the current virtual host
sub sendHeaders {
    my $class = shift;
    my $vhost = $apacheRequest->hostname;
    if ( defined( $forgeHeaders->{$vhost} ) ) {
        $class->lmSetHeaderIn( $apacheRequest, &{ $forgeHeaders->{$vhost} } );
    }
}

## @rmethod void cleanHeaders()
# Unset HTTP headers for the current virtual host, when sendHeaders is skipped
sub cleanHeaders {
    my $class = shift;
    my $vhost = $apacheRequest->hostname;
    if ( defined( $forgeHeaders->{$vhost} ) ) {
        $class->lmUnsetHeaderIn( $apacheRequest, @{ $headerList->{$vhost} } );
    }
}

## @rmethod protected int isUnprotected()
# @return 0 if URI is protected,
# UNPROTECT if it is unprotected by "unprotect",
# SKIP if is is unprotected by "skip"
sub isUnprotected {
    my ( $class, $uri ) = splice @_;
    my $vhost = $apacheRequest->hostname;
    for ( my $i = 0 ; $i < $locationCount->{$vhost} ; $i++ ) {
        if ( $uri =~ $locationRegexp->{$vhost}->[$i] ) {
            return $locationProtection->{$vhost}->[$i];
        }
    }
    return $defaultProtection->{$vhost};
}

## @rmethod boolean grant()
# Grant or refuse client using compiled regexp and functions
# @return True if the user is granted to access to the current URL
sub grant {
    my ( $class, $uri ) = splice @_;
    my $vhost = $apacheRequest->hostname;
    for ( my $i = 0 ; $i < $locationCount->{$vhost} ; $i++ ) {
        if ( $uri =~ $locationRegexp->{$vhost}->[$i] ) {
            return &{ $locationCondition->{$vhost}->[$i] }($datas);
        }
    }
    unless ( $defaultCondition->{$vhost} ) {
        $class->lmLog(
            "User rejected because VirtualHost \"$vhost\" has no configuration",
            'warn'
        );
        return 0;
    }
    return &{ $defaultCondition->{$vhost} }($datas);
}

## @rmethod protected $ fetchId()
# Get user cookies and search for Lemonldap::NG cookie.
# @return Value of the cookie if found, 0 else
sub fetchId {
    my $t                 = lmHeaderIn( $apacheRequest, 'Cookie' );
    my $vhost             = $apacheRequest->hostname;
    my $lookForHttpCookie = $securedCookie =~ /^(2|3)$/
      && !( defined( $https->{$vhost} ) ? $https->{$vhost} : $https->{_} );
    my $value =
      $lookForHttpCookie
      ? ( $t =~ /${cookieName}http=([^,; ]+)/o ? $1 : 0 )
      : ( $t =~ /$cookieName=([^,; ]+)/o ? $1 : 0 );

    $value = $cipher->decryptHex( $value, "http" )
      if ( $value && $lookForHttpCookie && $securedCookie == 3 );
    return $value;
}

## @cmethod private string _buildUrl(string s)
# Transform /<s> into http(s?)://<host>:<port>/s
# @param $s path
# @return URL
sub _buildUrl {
    my ( $class, $s ) = splice @_;
    my $vhost = $apacheRequest->hostname;
    my $portString =
         $port->{$vhost}
      || $port->{_}
      || $apacheRequest->get_server_port();
    my $_https =
      ( defined( $https->{$vhost} ) ? $https->{$vhost} : $https->{_} );
    $portString =
        ( $_https  && $portString == 443 ) ? ''
      : ( !$_https && $portString == 80 )  ? ''
      :                                      ':' . $portString;
    my $url = "http"
      . ( $_https ? "s" : "" ) . "://"
      . $apacheRequest->get_server_name()
      . $portString
      . $s;
    $class->lmLog( "Build URL $url", 'debug' );
    return $url;
}

## @imethod protected void postUrlInit()
# Prepare methods to post form attributes
sub postUrlInit {
    my ( $class, $args ) = splice @_;

    # Do nothing if no POST configured
    return unless ( $args->{post} );

    # Load required modules
    eval 'use Apache2::Filter;use URI';

    # Prepare transform sub
    $transform = {};

    # Browse all vhost
    foreach my $vhost ( keys %{ $args->{post} } ) {

        # Browse all POST URI
        while ( my ( $url, $d ) = each( %{ $args->{post}->{$vhost} } ) ) {

            # Where to POST
            $d->{postUrl} ||= $url;

            # Register POST form for POST URL
            $transform->{$vhost}->{$url} =
              sub { $class->buildPostForm( $d->{postUrl} ) }
              if ( $url ne $d->{postUrl} );

            # Get datas to POST
            my $expr = $d->{expr};
            my %postdata;

            # Manage old and new configuration format
            # OLD: expr => 'param1 => value1, param2 => value2',
            # NEW : expr => { param1 => value1, param2 => value2 },
            if ( ref $expr eq 'HASH' ) {
                %postdata = %$expr;
            }
            else {
                %postdata = split /(?:\s*=>\s*|\s*,\s*)/, $expr;
            }

            # Build string for URI::query_form
            my $tmp;
            foreach ( keys %postdata ) {
                $postdata{$_} =~ s/\$(\w+)/\$datas->{$1}/g;
                $postdata{$_} = "'$postdata{$_}'"
                  if ( $postdata{$_} =~ /^\w+$/ );
                $tmp .= "'$_'=>$postdata{$_},";
            }

            $class->lmLog( "Compiling POST request for $url (vhost $vhost)",
                'debug' );
            $transform->{$vhost}->{ $d->{postUrl} } = sub {
                return $class->buildPostForm( $d->{postUrl} )
                  if ( $apacheRequest->method ne 'POST' );
                $apacheRequest->add_input_filter(
                    sub {
                        $class->postFilter( $tmp, @_ );
                    }
                );
                OK;
              }
        }

    }

}

## @rmethod protected transformUri(string uri)
# Transform URI to replay POST forms
# @param uri URI to catch
# @return Apache2::Const
sub transformUri {
    my ( $class, $uri ) = splice @_;
    my $vhost = $apacheRequest->hostname;

    if ( defined( $transform->{$vhost}->{$uri} ) ) {
        return &{ $transform->{$vhost}->{$uri} };
    }

    OK;
}

## @rmethod protected boolean checkMaintenanceMode
# Check if we are in maintenance mode
# @return true if maintenance mode
sub checkMaintenanceMode {
    my ($class) = splice @_;
    my $vhost = $apacheRequest->hostname;
    my $_maintenance =
      ( defined $maintenance->{$vhost} )
      ? $maintenance->{$vhost}
      : $maintenance->{_};

    if ($_maintenance) {
        $class->lmLog( "Maintenance mode activated", 'debug' );
        return 1;
    }

    return 0;
}

1;

__END__

=head1 NAME

=encoding utf8

Lemonldap::NG::Handler::Vhost - Perl extension for building a Lemonldap::NG
compatible handler able to manage Apache virtual hosts.

=head1 SYNOPSIS

Create your own package:

  package My::Package;
  use Lemonldap::NG::Handler::Vhost;
  
  # IMPORTANT ORDER
  our @ISA = qw (Lemonldap::NG::Handler::Vhost Lemonldap::NG::Handler::Simple);
  
  __PACKAGE__->init ( { locationRules => {
             'vhost1.dc.com' => {
                 'default' => '$ou =~ /brh/'
             },
             'vhost2.dc.com' => {
                 '^/pj/.*$'       => '$qualif="opj"',
                 '^/rh/.*$'       => '$ou=~/brh/',
                 '^/rh_or_opj.*$' => '$qualif="opj" or $ou=~/brh/',
                 default          => 'accept',
             },
             # Put here others Lemonldap::NG::Handler::Simple options
           }
         );

Call your package in <apache-directory>/conf/httpd.conf

  PerlRequire MyFile
  PerlHeaderParserHandler My::Package

=head1 DESCRIPTION

This library provides a way to protect Apache virtual hosts with Lemonldap::NG.

=head2 INITIALISATION PARAMETERS

Lemonldap::NG::Handler::Vhost splits the locationRules parameter into a hash
reference which contains anonymous hash references as used by
L<Lemonldap::NG::Handler::Simple>.

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

=item Copyright (C) 2006, 2007, 2008, 2009, 2010 by Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=item Copyright (C) 2012 by François-Xavier Deltombe, E<lt>fxdeltombe@gmail.com.E<gt>

=item Copyright (C) 2006, 2010, 2011, 2012, 2013 by Clement Oudot, E<lt>clem.oudot@gmail.comE<gt>

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
