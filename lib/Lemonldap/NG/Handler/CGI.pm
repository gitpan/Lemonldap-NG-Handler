package Lemonldap::NG::Handler::CGI;

use strict;

use CGI;
use CGI::Cookie;
use MIME::Base64;

our @ISA = qw(CGI);

use Lemonldap::NG::Handler::SharedConf qw(:all);

our $VERSION = '0.1';

sub new {
    my $class = shift;
    my $self  = $class->SUPER::new();
    $self->{_handler} = bless {}, 'Lemonldap::NG::Handler::_CGI';
    $self->_handler->init(@_);
    $self->_handler->initLocalStorage();
    die "Unable to get configuration"
      unless $self->_handler->localConfUpdate() == OK;
    return $self;
}

sub authenticate {
    my $self    = shift;
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
    return 1;
}

sub authorize {
    my $self = shift;
    return $self->_handler->grant( $ENV{REQUEST_URI} );
}

sub testUri {
    my $self = shift;
    my $uri  = shift;
    my $host = ( $uri =~ s#^(?:https?://)?([^/]*)/#/# ) ? $1 : $ENV{SERVER_NAME};
    return -1 unless ( $self->_handler->vhostAvailable($host) );
    return $self->_handler->grant( $uri, $host );
}

sub user {
    return $datas;
}

sub group {
    my ( $self, $group ) = @_;
    return ( $datas->{groups} =~ /\b$group\b/ );
}

sub goToPortal {
    my $self = shift;
    my $tmp  = encode_base64( $self->_uri );
    $tmp =~ s/[\r\n]//sg;
    print CGI::redirect( -uri => "$portal?url=$tmp" );
    exit;
}

sub _uri {
    return 'http'
      . ( $https ? 's' : '' ) . '://'
      . $ENV{SERVER_NAME}
      . $ENV{REQUEST_URI};
}

sub _handler {
    return shift->{_handler};
}

package Lemonldap::NG::Handler::_CGI;

use Lemonldap::NG::Handler::SharedConf qw(:locationRules);

our @ISA = qw(Lemonldap::NG::Handler::SharedConf);

sub lmLog {
    my ( $self, $mess, $level ) = @_;
    $mess =~ s/^.*HASH[^:]*:/__PACKAGE__/e;
    print STDERR "$mess\n" unless ( $level eq 'debug' );
}

sub vhostAvailable {
    my ( $self, $vhost ) = @_;
    return defined( $defaultCondition->{$vhost} );
}

sub grant {
    my ( $self, $uri, $vhost ) = @_;
    $vhost ||= $ENV{SERVER_NAME};
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

1;
__END__

=head1 NAME

Lemonldap::NG::Handler::CGI - Perl extension for using Lemonldap::NG
authentication in Perl CGI without using Lemonldap::NG::Handler

=head1 SYNOPSIS

  use Lemonldap::NG::Handler::CGI;
  my $cgi = Lemonldap::NG::Handler::CGI->new ( {
      # Local storage used for sessions and configuration
      localStorage        => "Cache::DBFile",
      localStorageOptions => {...},
      # How to get my configuration
      configStorage       => {
          type                => "DBI",
          dbiChain            => "DBI:mysql:database=lemondb;host=$hostname",
          dbiUser             => "lemonldap",
          dbiPassword          => "password",
      },
      https               => 0,
    }
  );
  
  # Lemonldap::NG cookie validation
  $cgi->authenticate();
  
  # Optionnal Lemonldap::NG authorization
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

L<http://wiki.lemonldap.objectweb.org/xwiki/bin/view/NG/Presentation>,
L<CGI>, L<Lemonldap::NG::Handler>, L<Lemonldap::NG::Manager>,
L<Lemonldap::NG::Portal>

=head1 AUTHOR

Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=head1 BUG REPORT

Use OW2 system to report bug or ask for features:
L<http://forge.objectweb.org/tracker/?group_id=274>

=head1 DOWNLOAD

Lemonldap::NG is available at
L<http://forge.objectweb.org/project/showfiles.php?group_id=274>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2007 by Xavier Guimard

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut
