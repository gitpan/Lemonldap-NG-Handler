package Lemonldap::NG::Handler::Simple;

use strict;

use MIME::Base64;
use Exporter 'import';
use Safe;
require POSIX;

our $VERSION = '0.81';

our %EXPORT_TAGS = (
    localStorage =>
      [ qw( $localStorage $localStorageOptions $refLocalStorage ) ],
    globalStorage => [ qw( $globalStorage $globalStorageOptions ) ],
    locationRules => [
        qw(
          $locationCondition $defaultCondition $locationCount
          $locationRegexp $apacheRequest $datas $safe $portal
          )
    ],
    import  => [ qw( import @EXPORT_OK @EXPORT %EXPORT_TAGS ) ],
    headers => [
        qw(
          $forgeHeaders
          lmHeaderIn
          lmSetHeaderIn
          lmHeaderOut
          lmSetHeaderOut
          lmSetErrHeaderOut
          $cookieName
          $cookieSecured
          $https
          )
    ],
    traces => [ qw( $whatToTrace ) ],
    apache =>
      [ qw( MP OK REDIRECT FORBIDDEN DONE DECLINED SERVER_ERROR ) ],
);

our @EXPORT_OK = ();
push( @EXPORT_OK, @{ $EXPORT_TAGS{$_} } )
  foreach (
    qw( localStorage globalStorage locationRules import headers traces apache )
  );
$EXPORT_TAGS{all} = \@EXPORT_OK;

our @EXPORT = ();

# Shared variables
our (
    $locationRegexp,      $locationCondition,    $defaultCondition,
    $forgeHeaders,        $apacheRequest,        $locationCount,
    $cookieName,          $portal,               $datas,
    $globalStorage,       $globalStorageOptions, $localStorage,
    $localStorageOptions, $whatToTrace,          $https,
    $refLocalStorage,     $safe,                 $cookieSecured,
);

##########################################
# COMPATIBILITY WITH APACHE AND APACHE 2 #
##########################################

BEGIN {
    if ( exists $ENV{MOD_PERL} ) {
        if ( $ENV{MOD_PERL_API_VERSION} and $ENV{MOD_PERL_API_VERSION} >= 2 ) {
            *MP = sub { 2 };
        }
        else {
            *MP = sub { 1 };
        }
    }
    else {
        *MP = sub { 0 };
    }
    if ( MP() == 2 ) {
        require Apache2::RequestRec;
        Apache2::RequestRec->import();

        #require Apache2::RequestIO;
        require Apache2::Log;
        require Apache2::Const;

        #Apache2::Const->import('-compile', 'FORBIDDEN');
        Apache2::Const->import( '-compile', qw(:common :log) );
        *FORBIDDEN    = \&Apache2::Const::FORBIDDEN;
        *REDIRECT     = \&Apache2::Const::REDIRECT;
        *OK           = \&Apache2::Const::OK;
        *DECLINED     = \&Apache2::Const::DECLINED;
        *DONE         = \&Apache2::Const::DONE;
        *SERVER_ERROR = \&Apache2::Const::SERVER_ERROR;
        require Apache2::compat;
        Apache2::compat->import();
        eval {
            require threads::shared;
            threads::shared::share($locationRegexp);
            threads::shared::share($locationCondition);
            threads::shared::share($defaultCondition);
            threads::shared::share($forgeHeaders);
            threads::shared::share($locationCount);
            threads::shared::share($cookieName);
            threads::shared::share($portal);
            threads::shared::share($globalStorage);
            threads::shared::share($globalStorageOptions);
            threads::shared::share($localStorage);
            threads::shared::share($localStorageOptions);
            threads::shared::share($whatToTrace);
            threads::shared::share($https);
            threads::shared::share($refLocalStorage);
        };
    }
    elsif ( MP() == 1 ) {
        require Apache;
        require Apache::Log;
        require Apache::Constants;
        Apache::Constants->import(':common');
        Apache::Constants->import(':response');
    }
    else {    # For Test or CGI
        eval '
            sub OK {0}
            sub FORBIDDEN {1}
            sub REDIRECT {2}
            sub DECLINED {1}
            sub DONE {4}
            sub SERVER_ERROR {5}
        ';
    }
    *handler = ( MP() == 2 ) ? \&handler_mp2 : \&handler_mp1;
}

sub handler_mp1 ($$) { shift->run(@_) }

sub handler_mp2 : method {
    shift->run(@_);
}

sub lmLog {
    my ( $class, $mess, $level ) = @_;
    if ( MP() == 2 ) {
        Apache2::ServerRec->log->$level($mess);
    }
    elsif ( MP() == 1 ) {
        Apache->server->log->$level($mess);
    }
    else {
        print STDERR "$mess\n";
    }
}

sub regRemoteIp {
    my ( $class, $str ) = @_;
    $str =~ s/\$datas->\{ip\}/\$apacheRequest->connection->remote_ip/g;
    return $str;
}

sub lmSetHeaderIn {
    my ( $r, $h, $v ) = @_;
    if ( MP() == 2 ) {
        return $r->headers_in->set( $h => $v );
    }
    elsif ( MP() == 1 ) {
        return $r->header_in( $h => $v );
    }
}

sub lmHeaderIn {
    my ( $r, $h, $v ) = @_;
    if ( MP() == 2 ) {
        return $r->headers_in->{$h};
    }
    elsif ( MP() == 1 ) {
        return $r->header_in($h);
    }
}

sub lmSetErrHeaderOut {
    my ( $r, $h, $v ) = @_;
    if ( MP() == 2 ) {
        return $r->err_headers_out->set( $h => $v );
    }
    elsif ( MP() == 1 ) {
        return $r->err_header_out( $h => $v );
    }
}

sub lmSetHeaderOut {
    my ( $r, $h, $v ) = @_;
    if ( MP() == 2 ) {
        return $r->headers_out->set( $h => $v );
    }
    elsif ( MP() == 1 ) {
        return $r->header_out( $h => $v );
    }
}

sub lmHeaderOut {
    my ( $r, $h, $v ) = @_;
    if ( MP() == 2 ) {
        return $r->headers_out->{$h};
    }
    elsif ( MP() == 1 ) {
        return $r->header_out($h);
    }
}

##############################
# Initialization subroutines #
##############################

# Security jail
$safe = new Safe;
$safe->share( '&encode_base64', '$datas', '&lmSetHeaderIn', '$apacheRequest' );

# init() : by default, it calls localInit and globalInit, but with
#          a shared configuration, init() is overloaded to call only
#          localInit; globalInit is called later when the configuration
#          is loaded.
sub init($$) {
    my $class = shift;
    $class->localInit(@_);
    $class->globalInit(@_);
}

# Local storage initialization
sub localInit($$) {
    my ( $class, $args ) = @_;
    if ( $localStorage = $args->{localStorage} ) {
        $localStorageOptions = $args->{localStorageOptions};
        $localStorageOptions->{namespace}          ||= "lemonldap";
        $localStorageOptions->{default_expires_in} ||= 600;

        eval "use $localStorage;";
        die("Unable to load $localStorage: $@") if ($@);

        # At each Apache (re)start, we've to clear the cache to avoid living
        # with old datas
        eval '$refLocalStorage = new '
          . $localStorage
          . '($localStorageOptions);';
        if ( defined $refLocalStorage ) {
            $refLocalStorage->clear();
        }
        else {
            $class->lmLog( "Unable to clear local cache: $@", 'error' );
        }
    }

    # We don't initialise local storage in the "init" subroutine because it can
    # be used at the starting of Apache and so with the "root" privileges. Local
    # Storage is also initialized just after Apache's fork and privilege lost.

    # Local storage is cleaned after giving the content of the page to increase
    # performances.
    no strict;
    if ( MP() == 2 ) {
        Apache->push_handlers(
            PerlChildInitHandler => sub { return $class->initLocalStorage( $_[1], $_[0] ); }
        );
        Apache->push_handlers(
            PerlCleanupHandler => sub { return $class->cleanLocalStorage(@_); }
        );
    }
    elsif ( MP() == 1 ) {
        Apache->push_handlers(
            PerlChildInitHandler => sub { return $class->initLocalStorage(@_); }
        );
        Apache->push_handlers(
            PerlCleanupHandler => sub { return $class->cleanLocalStorage(@_); }
        );
    }
    1;
}

# Global initialization process :
sub globalInit {
    my $class = shift;
    $class->locationRulesInit(@_);
    $class->defaultValuesInit(@_);
    $class->portalInit(@_);
    $class->globalStorageInit(@_);
    $class->forgeHeadersInit(@_);
}

# locationRulesInit : used to pre-compile rules :
#   - rules are stored in a hash containing regexp=>test expressions where :
#       - regexp is used to test URIs
#       - test contains an expression used to grant the user

# TODO: split locationRules into 2 arrays
sub locationRulesInit {
    my ( $class, $args ) = @_;
    $locationCount = 0;

    # Pre compilation : both regexp and conditions
    foreach ( keys %{ $args->{locationRules} } ) {
        if ( $_ eq 'default' ) {
            $defaultCondition =
              $class->conditionSub( $args->{locationRules}->{$_} );
        }
        else {
            $locationCondition->[$locationCount] =
              $class->conditionSub( $args->{locationRules}->{$_} );
            $locationRegexp->[$locationCount] = qr/$_/;
            $locationCount++;
        }
    }

    # Default police: all authenticated users are accepted
    $defaultCondition = $class->conditionSub('accept')
      unless ($defaultCondition);
    1;
}

# conditionSub returns a pre-compiled subroutine used to grant users (used by
# locationRulesInit().
sub conditionSub {
    my ( $class, $cond ) = @_;
    return sub { 1 }
      if ( $cond =~ /^accept$/i );
    return sub { 0 }
      if ( $cond =~ /^deny$/i );
    $cond =~ s/\$date/&POSIX::strftime("%Y%m%d%H%M%S",localtime())/e;
    $cond =~ s/\$(\w+)/\$datas->{$1}/g;
    my $sub;
    $sub = $safe->reval("sub {return ( $cond )}");
    return $sub;
}

# defaultValuesInit : set default values for non-customized variables
sub defaultValuesInit {
    my ( $class, $args ) = @_;

    # Other values
    $cookieName  = $args->{cookieName}  || 'lemonldap';
    $cookieSecured = $args->{cookieSecured}  || 0;
    $whatToTrace = $args->{whatToTrace} || '$uid';
    $whatToTrace =~ s/\$//g;
    $https = $args->{https} unless defined($https);
    $https = 1 unless defined($https);
    1;
}

# portalInit : verify that portal variable exists
sub portalInit {
    my ( $class, $args ) = @_;
    $portal = $args->{portal} or die("portal parameter required");
}

# globalStorageInit : initialize the Apache::Session::* package used to
# share user's variables
sub globalStorageInit {
    my ( $class, $args ) = @_;
    $globalStorage = $args->{globalStorage} or die "globalStorage required";
    eval "use $globalStorage;";
    die($@) if ($@);
    $globalStorageOptions = $args->{globalStorageOptions};
}

# forgeHeadersInit : create the &$forgeHeaders subroutine used to insert
# headers into the HTTP request (which are used for accounting by the
# application)
sub forgeHeadersInit {
    my ( $class, $args ) = @_;

    # Creation of the subroutine who will generate headers
    my %tmp;
    if ( $args->{exportedHeaders} ) {
        %tmp = %{ $args->{exportedHeaders} };
    }
    else {
        %tmp = ( 'User-Auth' => '$uid' );
    }
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

    #$sub = "\$forgeHeaders = sub {$sub};";
    #eval "$sub";
    $forgeHeaders = $safe->reval("sub {$sub};");
    $class->lmLog( "$class: Unable to forge headers: $@: sub {$sub}", 'error' )
      if ($@);
    1;
}

################
# MAIN PROCESS #
################

# grant : grant or refuse client
sub grant {
    my ( $class, $uri ) = @_;
    for ( my $i = 0 ; $i < $locationCount ; $i++ ) {
        return &{ $locationCondition->[$i] }($datas)
          if ( $uri =~ $locationRegexp->[$i] );
    }
    return &$defaultCondition;
}

# forbidden : used to reject non authorizated requests
sub forbidden {
    my $class = shift;

    # We use Apache::Log here
    $class->lmLog(
        'The user "' . $datas->{$whatToTrace} . '" was reject when he tried to access to ' . shift,
        'notice'
    );
    return FORBIDDEN;
}

# hideCookie : hide Lemonldap cookie to the protected application
sub hideCookie {
    my $class = shift;
    $class->lmLog( "$class: removing cookie", 'debug' );
    my $tmp = lmHeaderIn( $apacheRequest, 'Cookie' );
    $tmp =~ s/$cookieName[^;]*;?//o;
    lmSetHeaderIn( $apacheRequest, 'Cookie' => $tmp );
}

# Redirect non-authenticated users to the portal
sub goToPortal() {
    my ( $class, $url, $arg ) = @_;
    my $urlc_init =
      encode_base64( "http"
          . ( $https ? "s" : "" ) . "://"
          . $apacheRequest->get_server_name()
          . $url );
    $urlc_init =~ s/[\n\s]//g;
    $class->lmLog(
        "Redirect "
          . $apacheRequest->connection->remote_ip
          . " to portal (url was $url)",
        'debug'
    );
    $apacheRequest->headers_out->set(
        'Location' => "$portal?url=$urlc_init" . ( $arg ? "&$arg" : "" )
    );
    return REDIRECT;
}

# Fetch $id
sub fetchId() {
    my $t = lmHeaderIn( $apacheRequest, 'Cookie' );
    return ($t =~ /$cookieName=([^; ]+);?/o ) ? $1: 0;
}

# MAIN SUBROUTINE called by Apache (using PerlHeaderParserHandler option)
sub run ($$) {
    my $class;
    ( $class, $apacheRequest ) = @_;

    return DECLINED unless ( $apacheRequest->is_initial_req );
    my $uri = $apacheRequest->uri . ( $apacheRequest->args ? "?" . $apacheRequest->args : "" );

    # AUTHENTICATION
    # I - recover the cookie
    my $id;
    unless ( $id = $class->fetchId ) {
        $class->lmLog( "$class: No cookie found", 'info' );
        return $class->goToPortal($uri);
    }

    # II - recover the user datas
    #  2.1 search if the user was the same as previous (very efficient in
    #      persistent connection).
    unless ( $id eq $datas->{_session_id} ) {

        # 2.2 search in the local cache if exists
        unless ( $refLocalStorage and $datas = $refLocalStorage->get($id) ) {

            # 2.3 search in the central cache
            my %h;
            eval { tie %h, $globalStorage, $id, $globalStorageOptions; };
            if ($@) {

                # The cookie isn't yet available
                $class->lmLog( "The cookie $id isn't yet available: $@",
                    'info' );
                return $class->goToPortal($uri);
            }
            $datas->{$_} = $h{$_} foreach ( keys %h );

            # Store now the user in the local storage
            if ($refLocalStorage) {
                $refLocalStorage->set( $id, $datas, "10 minutes" );
            }
            untie %h;
        }
    }

    # ACCOUNTING
    # 1 - Inform Apache
    $apacheRequest->connection->user( $datas->{$whatToTrace} );

    # AUTHORIZATION
    return $class->forbidden($uri) unless ( $class->grant($uri) );
    $class->lmLog(
        "User "
          . $datas->{$whatToTrace}
          . " was authorizated to access to $uri",
        'debug'
    );

    # ACCOUNTING
    # 2 - Inform remote application
    $class->sendHeaders;

    # SECURITY
    # Hide Lemonldap cookie
    $class->hideCookie;
    OK;
}

sub sendHeaders {
    &$forgeHeaders;
}

sub initLocalStorage {
    my ( $class, $r ) = @_;
    if ( $localStorage and not $refLocalStorage ) {
        eval '$refLocalStorage = new '
          . $localStorage
          . '($localStorageOptions);';
    }
    $class->lmLog( "Local cache initialization failed: $@", 'error' )
      unless ( defined $refLocalStorage );
    return DECLINED;
}

sub cleanLocalStorage {
    $refLocalStorage->purge() if ($refLocalStorage);
    return DECLINED;
}

sub unprotect {
    OK;
}

sub logout ($$) {
    my $class;
    ($class, $apacheRequest ) = @_;
    if( my $id = $class->fetchId ) {
        # Delete Apache thread datas
        if ( $id eq $datas->{_session_id} ) {
            $datas = {};
        }
        # Delete Apache local cache
        if( $refLocalStorage and $refLocalStorage->get($id) ) {
            $refLocalStorage->remove($id);
        }
    }
    return $class->goToPortal( '/', 'logout=1' );
}

1;
__END__

=head1 NAME

Lemonldap::NG::Handler::Simple - Perl base extension for building Lemonldap::NG
compatible handler.

=head1 SYNOPSIS

Create your own package:

  package My::Package;
  use Lemonldap::NG::Handler::Simple;

  our @ISA = qw(Lemonldap::NG::Handler::Simple);

  __PACKAGE__->init ({
         locationRules        => {
               default          => '$ou =~ /brh/'
         },
         globalStorage        => 'Apache::Session::MySQL',
         globalStorageOptions => {
               DataSource       => 'dbi:mysql:database=dbname;host=127.0.0.1',
               UserName         => 'db_user',
               Password         => 'db_password',
               TableName        => 'sessions',
               LockDataSource   => 'dbi:mysql:database=dbname;host=127.0.0.1',
               LockUserName     => 'db_user',
               LockPassword     => 'db_password',
           },
         localStorage         => 'Cache::DBFile',
         localStorageOptions  => {},
         portal               => 'https://portal/',
       });

More complete example

  package My::Package;
  use Lemonldap::NG::Handler::Simple;

  our @ISA = qw(Lemonldap::NG::Handler::Simple);

  __PACKAGE__->init ( { locationRules => {
             '^/pj/.*$'       => q($qualif="opj"),
             '^/rh/.*$'       => q($ou=~/brh/),
             '^/rh_or_opj.*$' => q($qualif="opj or $ou=~/brh/),
             default => 'accept', # means that all authenticated users are greanted
           },
           globalStorage        => 'Apache::Session::MySQL',
           globalStorageOptions => {
               DataSource       => 'dbi:mysql:database=dbname;host=127.0.0.1',
               UserName         => 'db_user',
               Password         => 'db_password',
               TableName        => 'sessions',
               LockDataSource   => 'dbi:mysql:database=dbname;host=127.0.0.1',
               LockUserName     => 'db_user',
               LockPassword     => 'db_password',
           },
           localStorage         => 'Cache::DBFile',
           localStorageOptions  => {},
           cookieName           => 'lemon',
           portal               => 'https://portal/',
           whatToTrace          => '$uid',
           exportedHeaders      => {
               'Auth-User'      => '$uid',
               'Unit'           => '$ou',
           https                => 1,
         }
       );

Call your package in <apache-directory>/conf/httpd.conf

  PerlRequire MyFile
  # TOTAL PROTECTION
  PerlHeaderParserHandler My::Package
  # OR SELECTED AREA
  <Location /protected-area>
    PerlHeaderParserHandler My::Package
  </Location>
  
You can also unprotect an URI

  <Files "*.gif">
    PerlHeaderParserHandler My::Package->unprotect
  </Files>

=head1 DESCRIPTION

Lemonldap::NG::Handler::Simple is designed to be overloaded. See
L<Lemonldap::NG::Handler> for more.

=head2 INITIALISATION PARAMETERS

This section presents the C<init> method parameters.

=over

=item B<locationRules> (required)

Reference to a hash that contains "url-regexp => perl-expression" entries to
manage authorizations.

=over

=item * "url-regexp" can be a perl regexp or the keyword 'default' which
corresponds to the default police (accept by default).

=item * "perl-expression" can be a perl condition or the keyword "accept" or the
keyword "deny". All the variables announced by $<name of the variable> are
replaced by the values resulting from the global session store.

=back

=item B<globalStorage> E<amp> B<globalStorageOptions> (required)

Name and parameters of the Apache::Session::* module used by the portal to
store user's datas. See L<Lemonldap::NG::Portal(3)> for more explanations.

=item B<localStorage> E<amp> B<localStorageOptions>

Name and parameters of the optional but recommanded Cache::* module used to
share user's datas between Apache processes. There is no need to set expires
options since L<Lemonldap::NG::Handler::Simple> call the Cache::*::purge
method itself.

=item B<cookieName> (default: lemon)

Name of the cookie used by the Lemonldap infrastructure.

=item B<portal> (required)

Url of the portal used to authenticate users.

=item B<whatToTrace> (default: uid)

Stored user variable to use in Apache logs.

=item B<exportedHeaders>

Reference to a hash that contains "Name => value" entries. Those headers are
calculated for each user by replacing the variables announced by "$" by their
values resulting from the global session store.

=item B<https> (default: 1)

Indicates if the protected server is protected by SSL. It is used to build
redirections, so you have to set it to avoid bad redirections after
authentication.

=back

=head2 EXPORT

None by default. You can import the following tags for inheritance:

=over

=item * B<:localStorage> : variables used to manage local storage

=item * B<:globalStorage> : variables used to manage global storage

=item * B<:locationRules> : variables used to manage area protection

=item * B<:import> : import function inherited from L<Exporter> and related
variables

=item * B<:headers> : functions and variables used to manage custom HTTP
headers exported to the applications

=item * B<apache> : functions and variables used to dialog with mod_perl.
This is done to be compatible both with Apache 1 and 2.

=back

=head1 SEE ALSO

L<Lemonldap::NG::Handler>, L<Lemonldap::NG::Portal>,
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

Copyright (C) 2005-2007 by Xavier Guimard E<lt>x.guimard@free.frE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.

=cut
