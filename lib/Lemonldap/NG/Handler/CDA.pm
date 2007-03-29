package Lemonldap::NG::Handler::CDA;

use strict;

use Lemonldap::NG::Handler::SharedConf qw(:all);

our $VERSION = '0.01';

our @ISA = qw(Lemonldap::NG::Handler::SharedConf);

*EXPORT_TAGS = *Lemonldap::NG::Handler::SharedConf::EXPORT_TAGS;
*EXPORT_OK   = *Lemonldap::NG::Handler::SharedConf::EXPORT_OK;

sub run ($$) {
    my $class;
    ( $class, $apacheRequest ) = @_;
    my $args = $apacheRequest->args;
    if ( $args =~ s/\??($cookieName=\w+)$//oi ) {
        my $str = $1;
        $class->lmLog(
            "Found a CDA id. Redirecting  "
              . $apacheRequest->connection->remote_ip
              . " to myself with new cookie",
            'debug'
        );
        $apacheRequest->args($args);
        my $host = $apacheRequest->get_server_name();
        lmSetErrHeaderOut( $apacheRequest,
                'Location' => "http"
              . ( $https ? 's' : '' )
              . "://$host"
              . $apacheRequest->uri
              . ( $apacheRequest->args ? "?" . $apacheRequest->args : "" ) );
        $host =~ s/^[^\.]+\.(.*\..*$)/$1/;
        lmSetErrHeaderOut( $apacheRequest,
            'Set-Cookie' => "$str; domain=$host; path=/"
              . ( $cookieSecured ? "; secure" : "" ) );
        return REDIRECT;
    }
    else {
        return $class->SUPER::run($apacheRequest);
    }
}

1;
__END__

=head1 NAME

Lemonldap::NG::Handler::CDA - Module to use Lemonldap::NG::Handler
mechanisms with Cross-Domain-Authentication.

=head1 SYNOPSIS

New usage:

  package My::Package;
  use Lemonldap::NG::Handler::CDA;
  @ISA = qw(Lemonldap::NG::Handler::CDA);
  __PACKAGE__->init ( {
    localStorage        => "Cache::FileCache",
    localStorageOptions => {
        'namespace' => 'MyNamespace',
        'default_expires_in' => 600,
      },
    reloadTime          => 1200, # Default: 600
    configStorage       => {
       type                => "DBI"
       dbiChain            => "DBI:mysql:database=$database;host=$hostname;port=$port",
       dbiUser             => "lemonldap",
       dbiPassword         => "password",
    },
  } );

Call your package in /apache-dir/conf/httpd.conf :

  PerlRequire MyFile
  # TOTAL PROTECTION
  PerlHeaderParserHandler My::Package
  # OR SELECTED AREA
  <Location /protected-area>
    PerlHeaderParserHandler My::Package
  </Location>

The configuration is loaded only at Apache start. Create an URI to force
configuration reload, so you don't need to restart Apache at each change :

  # /apache-dir/conf/httpd.conf
  <Location /location/that/I/ve/choosed>
    Order deny,allow
    Deny from all
    Allow from my.manager.com
    PerlHeaderParserHandler My::Package->refresh
  </Location>

=head1 DESCRIPTION

This library inherit from L<Lemonldap::NG::Handler::SharedConf> and add the
capability to control users that are authenticated with a
L<Lemonldap::NG::portal::CDA> CGI in another domain.

=head2 EXPORT

Same as L<Lemonldap::NG::Handler::SharedConf>.

=head1 SEE ALSO

L<Lemonldap::NG::Manager>, L<Lemonldap::NG::Handler>,
L<Lemonldap::NG::Handler::SharedConf>,
http://wiki.lemonldap.objectweb.org/xwiki/bin/view/NG/Presentation

=head1 AUTHOR

Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2007 by Xavier Guimard E<lt>x.guimard@free.frE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.

=cut

