package Lemonldap::NG::Handler::Proxy;

use strict;

use Lemonldap::NG::Handler::Simple qw(:apache :headers);
use LWP::UserAgent;

our $VERSION = '0.3';

##########################################
# COMPATIBILITY WITH APACHE AND APACHE 2 #
##########################################

BEGIN {
    if ( MP() == 2 ) {
        Apache2::compat->import();
    }
    *handler = ( MP() == 2 ) ? \&handler_mp2 : \&handler_mp1;
}

sub handler_mp1 ($$) { &run(@_) }

sub handler_mp2 : method {
    &run(@_);
}

########
# MAIN #
########

# Shared variables
our $r;
our $base;
our $headers_set;
our $UA = new LWP::UserAgent;
our $class;

# IMPORTANT: LWP does not have to execute any redirection itself. This has to
# be done by the client itself, else cookies and other information may
# disappear.
$UA->requests_redirectable( [] );

sub run($$) {
    ( $class, $r ) = @_;
    my $url = $r->uri;
    $url .= "?" . $r->args if ( $r->args );
    return DECLINED unless ( $base = $r->dir_config('LmProxyPass') );
    my $request = new HTTP::Request( $r->method, $base . $url );

    # Scan Apache request headers to generate LWP request headers
    $r->headers_in->do(
        sub {
            $_[1] =~ s/lemon=[^;]*;?// if ( $_[0] =~ /Cookie/i );
            return 1 if ( $_[1] =~ /^$/ );
            $request->header(@_) unless ( $_[0] =~ /^(Host|Referer)$/i );
            $class->lmLog(
                "$class: header pushed to the server: " . $_[0] . ": " . $_[1],
                'debug'
            );
            1;
        }
    );
    $base =~ s/https?:\/\/([^\/]+).*$/$1/;
    $request->header( Host => $base );

    # copy POST data, if any
    if ( $r->method eq "POST" ) {
        my $len = $r->header_in('Content-Length');
        my $buf;
        $r->read( $buf, $len );
        $request->content($buf);
    }
    $headers_set = 0;

    # For performance, we use a callback. See LWP::UserAgent for more
    my $response = $UA->request( $request, \&cb_content );
    if ( $response->code != 200 ) {
        $class->headers($response) unless ($headers_set);
        $r->print( $response->content );
    }
    return OK;
}

sub cb_content {
    my $chunk = shift;
    unless ($headers_set) {
        $class->headers(shift);
        $headers_set = 1;
    }
    $r->print($chunk);
}

sub headers {
    $class = shift;
    my $response = shift;
    my $tmp      = $response->header('Content-Type');
    $r->content_type($tmp) if ($tmp);

    # Modif demandée par mail
    #$r->content_type( $response->header('Content-Type') );
    $r->status( $response->code );
    $r->status_line( join ' ', $response->code, $response->message );

    # Scan LWP response headers to generate Apache response headers
    my ( $location_old, $location_new ) = split /[;,]+/,
      $r->dir_config('LmLocationToReplace');
    $response->scan(
        sub {

            # Replace Location headers
            $_[1] =~ s#$location_old#$location_new#
              if ( $location_old and $location_new and $_[0] =~ /Location/i );
            lmSetErrHeaderOut( $r, @_ );
            $class->lmLog(
                "$class: header pushed to the client: " . $_[0] . ": " . $_[1],
                'debug'
            );
            1;
        }
    );
    $r->send_http_header;
    $headers_set = 1;
}

1;

__END__

=head1 NAME

Lemonldap::NG::Handler::Proxy - Perl extension to add a reverse-proxy to a
Lemonldap::NG handler.

=head1 SYNOPSIS

apache/conf/httpd.conf:
  # Global reverse proxy
  PerlModule Lemonldap::NG::Handler::Proxy
  SetHandler perl-script
  PerlHandler Lemonldap::NG::Handler::Proxy
  PerlSetVar LmProxyPass http://real-server.com/
  PerlSetVar LmLocationToReplace http://real-server/,https://lemon.server/

  # Or just on a Location
  PerlModule Lemonldap::NG::Handler::Proxy
  <Location /reverse-area>
    SetHandler perl-script
    PerlHandler Lemonldap::NG::Handler::Proxy
    PerlSetVar LmProxyPass https://real-server.com/
    PerlSetVar LmLocationToReplace http://real-server/,https://lemon.server/
  </Location>

=head1 DESCRIPTION

This library adds a reverse-proxy functionnality to Apache. It is useful to
manage redirections if the remote host use it without the good domain.

=head2 PARAMETERS

=over

=item * B<LmProxyPass (required)>: Real server to push request to

=item * B<LmLocationToReplace> (optional): substitution to do to avoid bad
redirections. See synopsys for usage.

=head2 EXPORT

None by default.

=head1 SEE ALSO

Lemonldap::NG::Handler(3), LWP::UserAgent

=head1 AUTHOR

Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Xavier Guimard E<lt>x.guimard@free.frE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.

=cut
