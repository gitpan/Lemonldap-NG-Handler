## @file
# Virtual host support mechanism

## @class
# This class adds virtual host support for Lemonldap::NG handlers.
package Lemonldap::NG::Handler::Vhost;

use Lemonldap::NG::Handler::Simple qw(:locationRules :headers :post :apache)
  ;    #inherits
use strict;
use MIME::Base64;
use constant SAFEWRAP => ( Safe->can("wrap_code_ref") ? 1 : 0 );

our $VERSION = '0.992';

## @imethod protected void defaultValuesInit(hashRef args)
# Set default values for non-customized variables
# @param $args reference to the configuration hash
sub defaultValuesInit {
    my ( $class, $args ) = splice @_;
    foreach my $t (qw(https port)) {

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
            $sub .=
              "lmSetHeaderIn(\$apacheRequest,'$_' => join('',split(/[\\r\\n]+/,"
              . $tmp{$_} . ")));";
        }

        $forgeHeaders->{$vhost} = (
            SAFEWRAP
            ? $class->safe->wrap_code_ref( $class->safe->reval("sub {$sub}") )
            : $class->safe->reval("sub {$sub}")
        );
        $class->lmLog( "$class: Unable to forge headers: $@: sub {$sub}",
            'error' )
          if ($@);
    }
    1;
}

## @rmethod void sendHeaders()
# Launch function compiled by forgeHeadersInit() for the current virtual host
sub sendHeaders {
    my $class = shift;
    my $vhost;
    $vhost = $apacheRequest->hostname;
    if ( defined( $forgeHeaders->{$vhost} ) ) {
        &{ $forgeHeaders->{$vhost} };
    }
    else {
        lmSetHeaderIn( $apacheRequest, 'Auth-User' => $datas->{uid} );
    }
}

## @rmethod protected boolean isProtected()
# @return True if URI isn't protected (rule "unprotect")
sub isProtected {
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
            $transform->{$vhost}->{ $d->{postUrl} } =
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

            # Build subroutine
            my $sub = "sub{
            my \$f = shift;
            my \$l;
            unless(\$f->ctx){
            \$f->ctx(1);
            my \$u=URI->new('http:');
            \$u->query_form({$tmp});
            my \$s=\$u->query();
            \$l = \$f->r->headers_in->{'Content-Length'};
            \$f->r->headers_in->set( 'Content-Length' => length(\$s) );
            \$f->r->headers_in->set( 'Content-Type' => 'application/x-www-form-urlencoded' );
            \$f->print(\$s);
            while ( \$f->read( my \$b, \$l ) ) {}
            \$f->seen_eos(1);
            }
            return OK;
        }"
              ;
            $sub = (
                SAFEWRAP
                ? $class->safe->wrap_code_ref( $class->safe->reval($sub) )
                : $class->safe->reval($sub)
            );
            $class->lmLog( "Compiling POST request for $url (vhost $vhost)",
                'debug' );
            $transform->{$vhost}->{$url} = sub {
                return $class->buildPostForm($url)
                  if ( $apacheRequest->method ne 'POST' );
                $apacheRequest->add_input_filter($sub);
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

Copyright (C) 2005, 2010 by Xavier Guimard E<lt>x.guimard@free.frE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.

=cut
