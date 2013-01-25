## @file
# Auto-protected CGI machanism

## @class
# Base class for auto-protected CGI
package Lemonldap::NG::Handler::CGI;

use strict;

use Lemonldap::NG::Common::CGI;
use CGI::Cookie;
use MIME::Base64;

use base qw(Lemonldap::NG::Common::CGI);

use Lemonldap::NG::Handler::SharedConf qw(:all);

#link Lemonldap::NG::Handler::_CGI protected _handler

our $VERSION = '1.2.2_01';

## @cmethod Lemonldap::NG::Handler::CGI new(hashRef args)
# Constructor.
# @param $args hash passed to Lemonldap::NG::Handler::_CGI object
# @return new object
sub new {
    my $class = shift;
    my $self = $class->SUPER::new() or $class->abort("Unable to build CGI");
    $Lemonldap::NG::Handler::_CGI::_cgi = $self;
    unless ($Lemonldap::NG::Handler::_CGI::cookieName) {
        Lemonldap::NG::Handler::_CGI->init(@_);
        Lemonldap::NG::Handler::_CGI->initLocalStorage(@_);
    }
    unless ( eval { Lemonldap::NG::Handler::_CGI->testConf() } == OK ) {
        if ( $_[0]->{noAbort} ) {
            $self->{_noConf} = $@;
        }
        else {
            $class->abort( "Unable to get configuration", $@ );
        }
    }

    # Arguments
    my @args = splice @_;
    if ( ref( $args[0] ) ) {
        %$self = ( %$self, %{ $args[0] } );
    }
    else {
        %$self = ( %$self, @args );
    }

    # Protection
    if ( $self->{protection} and $self->{protection} ne 'none' ) {
        $self->authenticate();

        # ACCOUNTING
        if ( $self->{protection} =~ /^manager$/i ) {
            $self->authorize()
              or $self->abort( 'Forbidden',
                "You don't have rights to access this page" );
        }
        elsif ( $self->{protection} =~ /rule\s*:\s*(.*)\s*$/i ) {
            my $rule = $1;
            $rule =~ s/\$date/&POSIX::strftime("%Y%m%d%H%M%S",localtime())/e;
            $rule =~ s/\$(\w+)/\$datas->{$1}/g;
            $rule = 0 if ( $rule eq 'deny' );
            my $r;
            unless ( $rule eq 'accept'
                or Lemonldap::NG::Handler::_CGI->safe->reval($rule) )
            {
                $self->abort( 'Forbidden',
                    "You don't have rights to access this page" );
            }
        }
        elsif ( $self->{protection} !~ /^authenticate$/i ) {
            $self->abort(
                'Bad configuration',
                "The rule <code>" . $self->{protection} . "</code> is not known"
            );
        }
    }
    return $self;
}

## @method boolean authenticate()
# Checks if user session is valid.
# Checks Lemonldap::NG cookie and search session in sessions database.
# If nothing is found, redirects the user to the Lemonldap::NG portal.
# @return boolean : true if authentication is good. Exit before else
sub authenticate {
    my $self = shift;
    $self->abort(
        "Can't authenticate because configuration has not been loaded",
        $self->{_noConf} )
      if ( $self->{_noConf} );
    my %cookies = fetch CGI::Cookie;
    my $id;
    unless ( $cookies{$cookieName} and $id = $cookies{$cookieName}->value ) {
        return $self->goToPortal();
    }
    unless ( $datas and $id eq $datas->{_session_id} ) {
        unless ( $refLocalStorage and $datas = $refLocalStorage->get($id) ) {
            my %h;
            eval { tie %h, $globalStorage, $id, $globalStorageOptions; };
            if ($@) {
                return $self->goToPortal();
            }
            $datas->{$_} = $h{$_} foreach ( keys %h );
            if ($refLocalStorage) {
                $refLocalStorage->set( $id, $datas, "10 minutes" );
            }
        }
    }

    # Accounting : set user in apache logs
    $self->setApacheUser( $datas->{$whatToTrace} );
    $ENV{REMOTE_USER} = $datas->{$whatToTrace};

    return 1;
}

## @method boolean authorize()
# Checks if user is authorized to access to the current request.
# Call Lemonldap::NG::Handler::_CGI::grant() function.
# @return boolean : true if user is granted
sub authorize {
    my $self = shift;
    return Lemonldap::NG::Handler::_CGI->grant( $ENV{REQUEST_URI} );
}

## @method int testUri(string uri)
# Checks if user is authorized to access to $uri.
# Call Lemonldap::NG::Handler::_CGI::grant() function.
# @param $uri URI or URL to test
# @return int : 1 if user is granted, -1 if virtual host has no configuration,
# 0 if user isn't granted
sub testUri {
    my $self = shift;
    $self->abort( "Can't test URI because configuration has not been loaded",
        $self->{_noConf} )
      if ( $self->{_noConf} );
    my $uri = shift;
    my $host =
      ( $uri =~ s#^(?:https?://)?([^/]*)/#/# ) ? $1 : $ENV{SERVER_NAME};
    return -1 unless ( Lemonldap::NG::Handler::_CGI->vhostAvailable($host) );
    return Lemonldap::NG::Handler::_CGI->grant( $uri, $host );
}

## @method hashRef user()
# @return hash of user datas
sub user {
    return $datas;
}

## @method boolean group(string group)
# @param $group name of the Lemonldap::NG group to test
# @return boolean : true if user is in this group
sub group {
    my ( $self, $group ) = splice @_;
    return ( $datas->{groups} =~ /\b$group\b/ );
}

## @method void goToPortal()
# Redirects the user to the portal and exit.
sub goToPortal {
    my $self = shift;
    my $tmp = encode_base64( $self->_uri, '' );
    print CGI::redirect(
        -uri => Lemonldap::NG::Handler::_CGI->portal() . "?url=$tmp" );
    exit;
}

## @fn private string _uri()
# Builds current URL including "http://" and server name.
# @return URL_string
sub _uri {
    my $vhost = $ENV{SERVER_NAME};
    my $portString =
         $port->{$vhost}
      || $port->{_}
      || $ENV{SERVER_PORT};
    my $_https =
      ( defined( $https->{$vhost} ) ? $https->{$vhost} : $https->{_} );
    $portString =
        ( $_https  && $portString == 443 ) ? ''
      : ( !$_https && $portString == 80 )  ? ''
      :                                      ':' . $portString;
    my $url = "http"
      . ( $_https ? "s" : "" ) . "://"
      . $vhost
      . $portString
      . $ENV{REQUEST_URI};
    return $url;
}

## @class
# Private class used by Lemonldap::NG::Handler::CGI for his internal handler.
package Lemonldap::NG::Handler::_CGI;

use strict;
use Lemonldap::NG::Handler::SharedConf qw(:locationRules :localStorage :traces);

use base qw(Lemonldap::NG::Handler::SharedConf);

our $_cgi;

## @method boolean childInit()
# Since this is not a real Apache handler, childs have not to be initialized.
# @return true
sub childInit { 1 }

## @method boolean purgeCache()
# Since this is not a real Apache handler, it must not purge the cache at starting.
# @return true
sub purgeCache { 1 }

## @method void lmLog(string message,string level)
# Replace lmLog by "print STDERR $message".
# @param $message Message to log
# @param $level error level (debug, info, warning or error)
sub lmLog {
    my $class = shift;
    $_cgi->lmLog(@_);
}

## @method boolean vhostAvailable(string vhost)
# Checks if $vhost has been declared in configuration
# @param $vhost Virtual Host to test
# @return boolean : true if $vhost is available
sub vhostAvailable {
    my ( $self, $vhost ) = splice @_;
    return defined( $defaultCondition->{$vhost} );
}

## @method boolean grant(string uri, string vhost)
# Return true if user is granted to access.
# @param $uri URI string
# @param $vhost Optional virtual host (default current virtual host)
sub grant {
    my ( $self, $uri, $vhost ) = splice @_;
    $vhost ||= $ENV{SERVER_NAME};
    $apacheRequest = Lemonldap::NG::Apache::Request->new(
        {
            uri      => $uri,
            hostname => $vhost,
            args     => '',
        }
    );
    for ( my $i = 0 ; $i < $locationCount->{$vhost} ; $i++ ) {
        if ( $uri =~ $locationRegexp->{$vhost}->[$i] ) {
            return &{ $locationCondition->{$vhost}->[$i] }($datas);
        }
    }
    unless ( $defaultCondition->{$vhost} ) {
        $self->lmLog(
            "User rejected because VirtualHost \"$vhost\" has no configuration",
            'warn'
        );
        return 0;
    }
    return &{ $defaultCondition->{$vhost} }($datas);
}

package Lemonldap::NG::Apache::Request;

sub new {
    my $class = shift;
    my $self  = shift;
    return bless $self, $class;
}

sub hostname {
    return $_[0]->{hostname};
}

sub uri {
    return $_[0]->{uri};
}

sub args {
    return $_[0]->{args};
}

1;
__END__

=head1 NAME

=encoding utf8

Lemonldap::NG::Handler::CGI - Perl extension for using Lemonldap::NG
authentication in Perl CGI without using Lemonldap::NG::Handler

=head1 SYNOPSIS

  use Lemonldap::NG::Handler::CGI;
  my $cgi = Lemonldap::NG::Handler::CGI->new ( {
      # Local storage used for sessions and configuration
      localStorage        => "Cache::FileCache",
      localStorageOptions => {...},
      # How to get my configuration
      configStorage       => {
          type                => "DBI",
          dbiChain            => "DBI:mysql:database=lemondb;host=$hostname",
          dbiUser             => "lemonldap",
          dbiPassword          => "password",
      },
      https               => 0,
      # Optional
      protection    => 'rule: $uid eq "admin"',
      # Or to use rules from manager
      protection    => 'manager',
      # Or just to authenticate without managing authorization
      protection    => 'authenticate',
    }
  );
  
  # Lemonldap::NG cookie validation (done if you set "protection")
  $cgi->authenticate();
  
  # Optional Lemonldap::NG authorization (done if you set "protection")
  $cgi->authorize();
  
  # See CGI(3) for more about writing HTML pages
  print $cgi->header;
  print $cgi->start_html;
  
  # Since authentication phase, you can use user attributes and macros
  my $name = $cgi->user->{cn};
  
  # Instead of using "$cgi->user->{groups} =~ /\badmin\b/", you can use
  if( $cgi->group('admin') ) {
    # special html code for admins
  }
  else {
    # another HTML code
  }

=head1 DESCRIPTION

Lemonldap::NG::Handler provides the protection part of Lemonldap::NG web-SSO
system. It can be used with any system used with Apache (PHP or JSP pages for
example). If you need to protect only few Perl CGI, you can use this library
instead.

Warning, this module must not be used in a Lemonldap::NG::Handler protected
area because it hides Lemonldap::NG cookies. 

=head1 SEE ALSO

L<http://lemonldap-ng.org/>
L<CGI>, L<Lemonldap::NG::Handler>, L<Lemonldap::NG::Manager>,
L<Lemonldap::NG::Portal>

=head1 AUTHOR

Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=head1 BUG REPORT

Use OW2 system to report bug or ask for features:
L<http://jira.ow2.org>

=head1 DOWNLOAD

Lemonldap::NG is available at
L<http://forge.objectweb.org/project/showfiles.php?group_id=274>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2007, 2010 by Xavier Guimard

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
