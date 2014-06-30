package Lemonldap::NG::Handler::Main::Headers;

use strict;

use Lemonldap::NG::Handler::Main qw( :apache );    # for importing MP function
use Lemonldap::NG::Handler::Main::Logger;

our $VERSION = '1.3.1';

BEGIN {

    if ( MP() == 2 ) {
        require Apache2::Log;
        require Apache2::RequestUtil;
        Apache2::RequestUtil->import();
        require Apache2::RequestRec;
        Apache2::RequestRec->import();
        require Apache2::ServerUtil;
        Apache2::ServerUtil->import();
        require Apache2::Connection;
        Apache2::Connection->import();
        require Apache2::RequestIO;
        Apache2::RequestIO->import();
        require APR::Table;
        APR::Table->import();
        require Apache2::URI;
        Apache2::URI->import();
        require Apache2::Const;
        Apache2::Const->import( '-compile', qw(:common :log) );
    }
    elsif ( MP() == 1 ) {
        require Apache;
        require Apache::Log;
        require Apache::Constants;
        Apache::Constants->import(':common');
        Apache::Constants->import(':response');
    }

}

## @rmethod void lmSetHeaderIn(Apache2::RequestRec r, hash headers)
# Set HTTP headers in the HTTP request.
# @param $r Current request
# @param %headers Hash of header names and values
sub lmSetHeaderIn {
    my ( $self, $r, %headers ) = splice @_;
    while ( my ( $h, $v ) = each %headers ) {
        if ( MP() == 2 ) {
            $r->headers_in->set( $h => $v );
        }
        elsif ( MP() == 1 ) {
            $r->header_in( $h => $v );
        }
        Lemonldap::NG::Handler::Main::Logger->lmLog(
            "Send header $h with value $v", 'debug' );
    }
}

## @rmethod void lmUnsetHeaderIn(Apache2::RequestRec r, array headers)
# Unset HTTP headers in the HTTP request.
# @param $r Current request
# @param @headers Name of the headers
sub lmUnsetHeaderIn {
    my ( $self, $r, @headers ) = splice @_;
    foreach my $h (@headers) {
        if ( MP() == 2 ) {
            $r->headers_in->unset($h);
        }
        elsif ( MP() == 1 ) {
            $r->header_in( $h => "" )
              if ( $r->header_in($h) );
        }
        Lemonldap::NG::Handler::Main::Logger->lmLog( "Unset header $h",
            'debug' );
    }
}

## @rfn string lmHeaderIn(Apache2::RequestRec r, string h)
# Return an HTTP header value from the HTTP request.
# @param $r Current request
# @param $h Name of the header
# @return Value of the header
sub lmHeaderIn {
    my ( $self, $r, $h ) = splice @_;
    use Data::Dumper;
    if ( MP() == 2 ) {
        return $r->headers_in->{$h};
    }
    elsif ( MP() == 1 ) {
        return $r->header_in($h);
    }
}

## @rfn void lmSetErrHeaderOut(Apache2::RequestRec r, string h, string v)
# Set an HTTP header in the HTTP response in error context
# @param $r Current request
# @param $h Name of the header
# @param $v Value of the header
sub lmSetErrHeaderOut {
    my ( $self, $r, $h, $v ) = splice @_;
    if ( MP() == 2 ) {
        return $r->err_headers_out->set( $h => $v );
    }
    elsif ( MP() == 1 ) {
        return $r->err_header_out( $h => $v );
    }
}

## @rfn void lmSetHeaderOut(Apache2::RequestRec r, string h, string v)
# Set an HTTP header in the HTTP response in normal context
# @param $r Current request
# @param $h Name of the header
# @param $v Value of the header
sub lmSetHeaderOut {
    my ( $self, $r, $h, $v ) = splice @_;
    if ( MP() == 2 ) {
        return $r->headers_out->set( $h => $v );
    }
    elsif ( MP() == 1 ) {
        return $r->header_out( $h => $v );
    }
}

## @rfn string lmHeaderOut(Apache2::RequestRec r, string h)
# Return an HTTP header value from the HTTP response.
# @param $r Current request
# @param $h Name of the header
# @return Value of the header
sub lmHeaderOut {
    my ( $self, $r, $h, $v ) = splice @_;
    if ( MP() == 2 ) {
        return $r->headers_out->{$h};
    }
    elsif ( MP() == 1 ) {
        return $r->header_out($h);
    }
}

## @rmethod void sendHeaders()
# Launch function compiled by forgeHeadersInit() for the current virtual host
sub sendHeaders {
    my ( $self, $apacheRequest, $forgeHeaders ) = splice @_;
    my $vhost = $apacheRequest->hostname;
    if ( defined( $forgeHeaders->{$vhost} ) ) {
        lmSetHeaderIn( $self, $apacheRequest, &{ $forgeHeaders->{$vhost} } );
    }
}

## @rmethod void cleanHeaders()
# Unset HTTP headers for the current virtual host, when sendHeaders is skipped
sub cleanHeaders {
    my ( $self, $apacheRequest, $forgeHeaders, $headerList ) = splice @_;
    my $vhost = $apacheRequest->hostname;
    if ( defined( $forgeHeaders->{$vhost} ) ) {
        lmUnsetHeaderIn( $self, $apacheRequest, @{ $headerList->{$vhost} } );
    }
}

1;
