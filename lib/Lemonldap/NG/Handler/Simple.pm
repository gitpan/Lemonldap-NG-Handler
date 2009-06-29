## @file
# Base file for Lemonldap::NG handlers

## @class
# Base class for Lemonldap::NG handlers.
# All methods in handler are class methods: in ModPerl environment, handlers
# are always launched without object created.
#
# The main method is run() who is called by Apache for each requests (using
# handler() wrapper).
#
# The main initialization subroutine is init() who launch localInit() and
# globalInit().
package Lemonldap::NG::Handler::Simple;

use strict;

use MIME::Base64;
use Exporter 'import';
use Safe;
use Lemonldap::NG::Common::Safelib;    #link protected safe Safe object
require Data::Dumper;
require POSIX;

#inherits Cache::Cache
#inherits Apache::Session
#link Lemonldap::NG::Common::Apache::Session::SOAP protected globalStorage

our $VERSION = '0.91';

our %EXPORT_TAGS;

our @EXPORT_OK;

our @EXPORT;

# Shared variables
our (
    $locationRegexp,       $locationCondition, $defaultCondition,
    $forgeHeaders,         $apacheRequest,     $locationCount,
    $cookieName,           $datas,             $globalStorage,
    $globalStorageOptions, $localStorage,      $localStorageOptions,
    $whatToTrace,          $https,             $refLocalStorage,
    $safe,                 $port,              $statusPipe,
    $statusOut,            $customFunctions,   $transform,
    $cda,
);

##########################################
# COMPATIBILITY WITH APACHE AND APACHE 2 #
##########################################

BEGIN {
    %EXPORT_TAGS = (
        localStorage =>
          [qw( $localStorage $localStorageOptions $refLocalStorage )],
        globalStorage => [qw( $globalStorage $globalStorageOptions )],
        locationRules => [
            qw(
              $locationCondition $defaultCondition $locationCount
              $locationRegexp $apacheRequest $datas $safe safe $customFunctions
              )
        ],
        import  => [qw( import @EXPORT_OK @EXPORT %EXPORT_TAGS )],
        headers => [
            qw(
              $forgeHeaders lmHeaderIn lmSetHeaderIn lmHeaderOut
              lmSetHeaderOut lmSetErrHeaderOut $cookieName $https $port
              )
        ],
        traces => [qw( $whatToTrace $statusPipe $statusOut )],
        apache => [qw( MP OK REDIRECT FORBIDDEN DONE DECLINED SERVER_ERROR )],
        post   => [qw($transform)],
        cda    => ['$cda'],
    );
    push( @EXPORT_OK, @{ $EXPORT_TAGS{$_} } ) foreach ( keys %EXPORT_TAGS );
    $EXPORT_TAGS{all} = \@EXPORT_OK;
    if ( exists $ENV{MOD_PERL} ) {
        if ( $ENV{MOD_PERL_API_VERSION} and $ENV{MOD_PERL_API_VERSION} >= 2 ) {
            eval 'use constant MP => 2;';
        }
        else {
            eval 'use constant MP => 1;';
        }
    }
    else {
        eval 'use constant MP => 0;';
    }
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
        require Apache2::Const;
        Apache2::Const->import( '-compile', qw(:common :log) );
        eval '
        use constant FORBIDDEN    => Apache2::Const::FORBIDDEN;
        use constant REDIRECT     => Apache2::Const::REDIRECT;
        use constant OK           => Apache2::Const::OK;
        use constant DECLINED     => Apache2::Const::DECLINED;
        use constant DONE         => Apache2::Const::DONE;
        use constant SERVER_ERROR => Apache2::Const::SERVER_ERROR;
        ';
        eval {
            require threads::shared;
            threads::shared::share($locationRegexp);
            threads::shared::share($locationCondition);
            threads::shared::share($defaultCondition);
            threads::shared::share($forgeHeaders);
            threads::shared::share($locationCount);
            threads::shared::share($cookieName);
            threads::shared::share($globalStorage);
            threads::shared::share($globalStorageOptions);
            threads::shared::share($localStorage);
            threads::shared::share($localStorageOptions);
            threads::shared::share($whatToTrace);
            threads::shared::share($https);
            threads::shared::share($port);
            threads::shared::share($refLocalStorage);
            threads::shared::share($statusPipe);
            threads::shared::share($statusOut);
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
        use constant FORBIDDEN    => 1;
        use constant REDIRECT     => 1;
        use constant OK           => 1;
        use constant DECLINED     => 1;
        use constant DONE         => 1;
        use constant SERVER_ERROR => 1;
        ';
    }
    *handler = ( MP() == 2 ) ? \&handler_mp2 : \&handler_mp1;
    *logout  = ( MP() == 2 ) ? \&logout_mp2  : \&logout_mp1;
}

## @rmethod protected int handler_mp1()
# Launch run() when used under mod_perl version 1
# @return Apache constant
sub handler_mp1 ($$) { shift->run(@_); }

## @rmethod protected int handler_mp2()
# Launch run() when used under mod_perl version 2
# @return Apache constant
sub handler_mp2 : method {
    shift->run(@_);
}

## @rmethod protected int logout_mp1()
# Launch unlog() when used under mod_perl version 1
# @return Apache constant
sub logout_mp1 ($$) { shift->unlog(@_); }

## @rmethod protected int logout_mp2()
# Launch unlog() when used under mod_perl version 2
# @return Apache constant
sub logout_mp2 : method {
    shift->unlog(@_);
}

## @rmethod void lmLog(string mess, string level)
# Wrapper for Apache log system
# @param $mess message to log
# @param $level string (debug, info, warning or error)
sub lmLog {
    my ( $class, $mess, $level ) = @_;
    die "Level is required" unless ($level);
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

## @rmethod protected void lmSetApacheUser(Apache2::RequestRec r,string s)
# Inform Apache for the data to use as user for logs
# @param $r current request
# @param $s string to use
sub lmSetApacheUser {
    my ( $class, $r, $s ) = @_;
    return unless ($s);
    if ( MP() == 2 ) {
        $r->user($s);
    }
    else {
        $r->connection->user($s);
    }
}

## @ifn protected string protected regRemoteIp(string str)
# Replaces $ip by the client IP address in the string
# @param $str string
# @return string
sub regRemoteIp {
    my ( $class, $str ) = @_;
    if ( MP() == 2 ) {
        $str =~ s/\$datas->\{ip\}/\$apacheRequest->connection->remote_ip/g;
    }
    else {
        $str =~ s/\$datas->\{ip\}/\$apacheRequest->remote_ip/g;
    }
    return $str;
}

## @rfn void lmSetHeaderIn(Apache2::RequestRec r, string h, string v)
# Set an HTTP header in the HTTP request.
# @param $r Current request
# @param $h Name of the header
# @param $v Value of the header
sub lmSetHeaderIn {
    my ( $r, $h, $v ) = @_;
    if ( MP() == 2 ) {
        return $r->headers_in->set( $h => $v );
    }
    elsif ( MP() == 1 ) {
        return $r->header_in( $h => $v );
    }
}

## @rfn string lmHeaderIn(Apache2::RequestRec r, string h)
# Return an HTTP header value from the HTTP request.
# @param $r Current request
# @param $h Name of the header
# @return Value of the header
sub lmHeaderIn {
    my ( $r, $h ) = @_;
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
    my ( $r, $h, $v ) = @_;
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
    my ( $r, $h, $v ) = @_;
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
    my ( $r, $h, $v ) = @_;
    if ( MP() == 2 ) {
        return $r->headers_out->{$h};
    }
    elsif ( MP() == 1 ) {
        return $r->header_out($h);
    }
}

# Status daemon creation

## @ifn protected void statusProcess()
# Launch the status processus.
sub statusProcess {
    require IO::Pipe;
    $statusPipe = IO::Pipe->new;
    $statusOut  = IO::Pipe->new;
    if ( my $pid = fork() ) {
        $statusPipe->writer();
        $statusOut->reader();
        $statusPipe->autoflush(1);
    }
    else {
        $statusPipe->reader();
        $statusOut->writer();
        my $fdin  = $statusPipe->fileno;
        my $fdout = $statusOut->fileno;
        open STDIN,  "<&$fdin";
        open STDOUT, ">&$fdout";
        my @tmp = ();
        push @tmp, "-I$_" foreach (@INC);
        exec 'perl', '-MLemonldap::NG::Handler::Status',
          @tmp,
          '-e',
          '&Lemonldap::NG::Handler::Status::run('
          . $localStorage . ','
          . Data::Dumper->new( [$localStorageOptions] )->Terse(1)->Dump . ');';
    }
}

##############################
# Initialization subroutines #
##############################

## @imethod protected Safe safe()
# Build and return the security jail used to compile rules and headers.
# @return Safe object
sub safe {
    my $class = shift;
    return $safe if ($safe);
    $safe = new Safe;
    my @t = $customFunctions ? split( /\s+/, $customFunctions ) : ();
    foreach (@t) {
        $class->lmLog( "Custom function : $_", 'debug' );
        my $sub = $_;
        unless (/::/) {
            $sub = "$class\::$_";
        }
        else {
            s/^.*:://;
        }
        next if ( $class->can($_) );
        eval "sub $_ {
            return $sub(\$apacheRequest->uri
                . ( \$apacheRequest->args ? '?' . \$apacheRequest->args : '' )
                , \@_)
            }";
        $class->lmLog( $@, 'error' ) if ($@);
    }
    $safe->share_from( 'main', ['%ENV'] );
    $safe->share_from( 'Lemonldap::NG::Common::Safelib',
        $Lemonldap::NG::Common::Safelib::functions );
    $safe->share( '&encode_base64', '$datas', '&lmSetHeaderIn',
        '$apacheRequest', '&portal', @t );
    return $safe;
}

## @imethod void init(hashRef args)
# Calls localInit() and globalInit().
# @param $args reference to the initialization hash
sub init($$) {
    my $class = shift;
    $class->localInit(@_);
    $class->globalInit(@_);
}

## @imethod void localInit(hashRef args)
# Call purgeCache() to purge the local cache, launch the status process
# (statusProcess()) in wanted and launch childInit().
# @param $args reference to the initialization hash
sub localInit($$) {
    my ( $class, $args ) = @_;
    if ( $localStorage = $args->{localStorage} ) {
        $localStorageOptions = $args->{localStorageOptions};
        $localStorageOptions->{namespace}          ||= "lemonldap";
        $localStorageOptions->{default_expires_in} ||= 600;
        $class->purgeCache();
    }
    if ( $args->{status} ) {
        statusProcess();
    }
    $class->childInit();
}

## @imethod protected boolean childInit()
# Indicates to Apache that it has to launch:
# - initLocalStorage() for each child process (after fork and uid change)
# - cleanLocalStorage() after each requests
# @return True
sub childInit {
    my $class = shift;

    # We don't initialise local storage in the "init" subroutine because it can
    # be used at the starting of Apache and so with the "root" privileges. Local
    # Storage is also initialized just after Apache's fork and privilege lost.

    # Local storage is cleaned after giving the content of the page to increase
    # performances.
    no strict;
    if ( MP() == 2 ) {
        Apache2::ServerUtil->server->push_handlers( PerlChildInitHandler =>
              sub { return $class->initLocalStorage( $_[1], $_[0] ); } );
    }
    elsif ( MP() == 1 ) {
        Apache->push_handlers(
            PerlChildInitHandler => sub { return $class->initLocalStorage(@_); }
        );
    }
    1;
}

## @imethod protected void purgeCache()
# Purge the local cache.
# Launched at Apache startup.
sub purgeCache {
    my $class = shift;
    eval "use $localStorage;";
    die("Unable to load $localStorage: $@") if ($@);

    # At each Apache (re)start, we've to clear the cache to avoid living
    # with old datas
    eval '$refLocalStorage = new ' . $localStorage . '($localStorageOptions);';
    if ( defined $refLocalStorage ) {
        $refLocalStorage->clear();
    }
    else {
        $class->lmLog( "Unable to clear local cache: $@", 'error' );
    }
}

## @imethod void globalInit(hashRef args)
# Global initialization process. Launch :
# - locationRulesInit()
# - defaultValuesInit()
# - portalInit()
# - globalStorageInit()
# - forgeHeadersInit()
# @param $args reference to the configuration hash
sub globalInit {
    my $class = shift;
    $class->portalInit(@_);
    $class->locationRulesInit(@_);
    $class->defaultValuesInit(@_);
    $class->globalStorageInit(@_);
    $class->forgeHeadersInit(@_);
    $class->postUrlInit(@_);
}

## @imethod protected void locationRulesInit(hashRef args)
# Compile rules.
# Rules are stored in $args->{locationRules} that contains regexp=>test
# expressions where :
# - regexp is used to test URIs
# - test contains an expression used to grant the user
#
# This function creates 2 arrays containing :
# - the list of the compiled regular expressions
# - the list of the compiled functions (compiled with conditionSub())
# @param $args reference to the configuration hash
sub locationRulesInit {
    my ( $class, $args ) = @_;
    $locationCount = 0;

    # Pre compilation : both regexp and conditions
    foreach ( sort keys %{ $args->{locationRules} } ) {
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

## @imethod protected codeRef conditionSub(string cond)
# Returns a compiled function used to grant users (used by
# locationRulesInit().
# @param $cond The boolean expression to use
sub conditionSub {
    my ( $class, $cond ) = @_;
    return sub { 1 }
      if ( $cond =~ /^accept$/i );
    return sub { 0 }
      if ( $cond =~ /^deny$/i );
    if ( $cond =~ /^logout(?:_sso)?(?:\s+(.*))?$/i ) {
        my $url = $1;
        return $url
          ? sub { $datas->{_logout} = $url;     return 0 }
          : sub { $datas->{_logout} = portal(); return 0 };
    }
    if ( MP() == 2 ) {
        if ( $cond =~ /^logout_app(?:\s+(.*))?$/i ) {
            my $u = $1 || 'portal()';
            eval 'use Apache2::Filter' unless ( $INC{"Apache2/Filter.pm"} );
            return sub {
                $apacheRequest->add_output_filter(
                    sub {
                        return $class->redirectFilter( $u, @_ );
                    }
                );
                1;
            };
        }
        elsif ( $cond =~ /^logout_app_sso(?:\s+(.*))?$/i ) {
            eval 'use Apache2::Filter' unless ( $INC{"Apache2/Filter.pm"} );
            my $u = $1 || 'portal()';
            return sub {
                $class->localUnlog;
                $apacheRequest->add_output_filter(
                    sub {
                        return $class->redirectFilter(
                            $class->portal() . "?url="
                              . $class->encodeUrl($u)
                              . "&logout=1",
                            @_
                        );
                    }
                );
                1;
            };
        }
    }
    $cond =~ s/\$date/&POSIX::strftime("%Y%m%d%H%M%S",localtime())/e;
    $cond =~ s/\$(\w+)/\$datas->{$1}/g;
    $cond =~ s/\$datas->{vhost}/\$apacheRequest->hostname/g;
    my $sub = $class->safe->reval("sub {return ( $cond )}");
    return $sub;
}

## @imethod protected void defaultValuesInit(hashRef args)
# Set default values for non-customized variables
# @param $args reference to the configuration hash
sub defaultValuesInit {
    my ( $class, $args ) = @_;

    # Other values
    $cookieName  = $args->{cookieName}  || $cookieName  || 'lemonldap';
    $whatToTrace = $args->{whatToTrace} || $whatToTrace || 'uid';
    $whatToTrace =~ s/\$//g;
    $https = $args->{https} unless defined($https);
    $https = 1 unless defined($https);
    $args->{securedCookie} = 1 unless defined( $args->{securedCookie} );
    $cookieName .= 'http' if ( $args->{securedCookie} == 2 and $https == 0 );
    $port            = $args->{port} || 0 unless defined($port);
    $customFunctions = $args->{customFunctions};
    $cda             = $args->{cda} || 0 unless defined($cda);
    1;
}

## @imethod protected void portalInit(hashRef args)
# Verify that portal variable exists. Die unless
# @param $args reference to the configuration hash
sub portalInit {
    my ( $class, $args ) = @_;
    die("portal parameter required") unless ( $args->{portal} );
    if ( $args->{portal} =~ /[\$\(&\|"']/ ) {
        my $portal = $class->conditionSub( $args->{portal} );
        eval "sub portal {return &\$portal}";
    }
    else {
        eval "sub portal {return '$args->{portal}'}";
    }
    die("Unable to read portal parameter ($@)") if ($@);
    1;
}

## @imethod protected void globalStorageInit(hashRef args)
# Initialize the Apache::Session::* module choosed to share user's variables.
# @param $args reference to the configuration hash
sub globalStorageInit {
    my ( $class, $args ) = @_;
    $globalStorage = $args->{globalStorage} or die "globalStorage required";
    eval "use $globalStorage;";
    die($@) if ($@);
    $globalStorageOptions = $args->{globalStorageOptions};
}

## @imethod protected void forgeHeadersInit(hashRef args)
# Create the &$forgeHeaders subroutine used to insert
# headers into the HTTP request.
# @param $args reference to the configuration hash
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
    $forgeHeaders = $class->safe->reval("sub {$sub};");
    $class->lmLog( "$class: Unable to forge headers: $@: sub {$sub}", 'error' )
      if ($@);
    1;
}

## @imethod protected int initLocalStorage()
# Prepare local cache (if not done before by Lemonldap::NG::Common::Conf)
# @return Apache2::Const::DECLINED
sub initLocalStorage {
    my ( $class, $r ) = @_;
    if ( $localStorage and not $refLocalStorage ) {
        eval
"use $localStorage;\$refLocalStorage = new $localStorage(\$localStorageOptions);";
        $class->lmLog( "Local cache initialization failed: $@", 'error' )
          unless ( defined $refLocalStorage );
    }
    return DECLINED;
}

## @imethod protected void postUrlInit()
# Prepare methods to post form attributes
sub postUrlInit {
    my ( $class, $args ) = @_;
    return unless ( $args->{post} );
    eval 'use Apache2::Filter;use URI';
    $transform = {};
    while ( my ( $url, $d ) = each( %{ $args->{post} } ) ) {
        $d->{postUrl} ||= $url;
        $transform->{ $d->{postUrl} } =
          sub { $class->buildPostForm( $d->{postUrl} ) }
          if ( $url ne $d->{postUrl} );

        my $expr = $d->{expr};
        $expr =~ s/\$(\w+)/\$datas->{$1}/g;
        my %h = split /(?:\s*=>\s*|\s*,\s*)/, $expr;
        my $tmp;
        foreach ( keys %h ) {
            $h{$_} = "'$h{$_}'" if ( $h{$_} =~ /^\w+$/ );
            $tmp .= "'$_'=>$h{$_},";
        }
        my $sub = $class->safe->reval(
            "sub{
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
        );
        $class->lmLog( "Compiling POST request for $url", 'debug' );
        $transform->{$url} = sub {
            return $class->buildPostForm($url)
              if ( $apacheRequest->method ne 'POST' );
            $apacheRequest->add_input_filter($sub);
            OK;
          }
    }
}

sub buildPostForm {
    my $class = shift;
    my $url   = shift;
    my $count = shift || 1000;
    $apacheRequest->handler("perl-script");
    $apacheRequest->set_handlers(
        'PerlResponseHandler' => sub {
            my $r = shift;
            $r->content_type('text/html; charset=UTF-8');
            $r->print(
qq{<html><body onload="document.getElementById('f').submit()"><form id="f" method="post" action="$url"><input type=hidden name="a" value="}
                  . sprintf( "%0" . $count . "d", 1 )
                  . qq{"/><input type="submit" value="Ok"/></form></body></html>}
            );
            OK;
        }
    );
    OK;
}

###################
# RUNNING METHODS #
###################

## @rmethod protected void updateStatus(string user,string url,string action)
# Inform the status process of the result of the request if it is available.
sub updateStatus {
    my ( $class, $user, $url, $action ) = @_;
    eval {
            print $statusPipe "$user => "
          . $apacheRequest->hostname
          . "$url $action\n"
          if ($statusPipe);
    };
}

## @rmethod protected boolean grant()
# Grant or refuse client using compiled regexp and functions
# @return True if the user is granted to access to the current URL
sub grant {
    my ( $class, $uri ) = @_;
    for ( my $i = 0 ; $i < $locationCount ; $i++ ) {
        return &{ $locationCondition->[$i] }($datas)
          if ( $uri =~ $locationRegexp->[$i] );
    }
    return &$defaultCondition($datas);
}

## @rmethod protected int forbidden()
# Used to reject non authorizated requests.
# Inform the status processus and call logForbidden().
# @return Apache2::Const::FORBIDDEN
sub forbidden {
    my ( $class, $uri ) = @_;
    if ( $datas->{_logout} ) {
        $class->updateStatus( $datas->{$whatToTrace}, $_[0], 'LOGOUT' );
        my $u = $datas->{_logout};
        $class->localUnlog;
        return $class->goToPortal( $u, 'logout=1' );
    }
    $class->updateStatus( $datas->{$whatToTrace}, $_[0], 'REJECT' );
    $apacheRequest->push_handlers(
        PerlLogHandler => sub { $class->logForbidden( $uri, $datas ); DECLINED }
    );
    return FORBIDDEN;
}

## @rmethod protected void logForbidden(string uri,hashref datas)
# Insert a log in Apache errors log system to inform that the user was rejected.
# This method has to be overloaded to use different logs systems
# @param $uri uri asked
# @param $datas hash re to user's datas
sub logForbidden {
    my ( $class, $uri, $datas ) = @_;
    $class->lmLog(
        'User "'
          . $datas->{$whatToTrace}
          . '" was reject when he tried to access to '
          . $uri,
        'notice'
    );
}

## @rmethod protected void logGranted(string uri)
# Insert a log in Apache errors log system to inform that the user was
# authorizated. This method has to be overloaded to use different logs systems
# @param $uri uri asked
sub logGranted {
    my ( $class, $uri, $datas ) = @_;
    $class->lmLog(
        'User "'
          . $datas->{$whatToTrace}
          . '" was granted to access to '
          . $uri,
        'debug'
    );
}

## @rmethod protected void hideCookie()
# Hide Lemonldap::NG cookie to the protected application.
sub hideCookie {
    my $class = shift;
    $class->lmLog( "$class: removing cookie", 'debug' );
    my $tmp = lmHeaderIn( $apacheRequest, 'Cookie' );
    $tmp =~ s/$cookieName[^,;]*[,;]?//o;
    lmSetHeaderIn( $apacheRequest, 'Cookie' => $tmp );
}

## @rmethod protected string encodeUrl(string url)
# Encode URl in the format used by Lemonldap::NG::Portal for redirections.
sub encodeUrl {
    my ( $class, $url ) = @_;
    my $u = $url;
    if ( $url !~ m#^https?://# ) {
        my $portString = $port || $apacheRequest->get_server_port();
        $portString =
            ( $https  && $portString == 443 ) ? ''
          : ( !$https && $portString == 80 )  ? ''
          :                                     ':' . $portString;
        $u = "http"
          . ( $https ? "s" : "" ) . "://"
          . $apacheRequest->get_server_name()
          . $portString
          . $url;
    }
    return encode_base64( $u, '' );
}

## @rmethod protected int goToPortal(string url, string arg)
# Redirect non-authenticated users to the portal by setting "Location:" header.
# @param $url Url requested
# @param $arg optionnal GET parameters
# @return Apache2::Const::REDIRECT
sub goToPortal {
    my ( $class, $url, $arg ) = @_;
    $class->lmLog(
        "Redirect "
          . $apacheRequest->connection->remote_ip
          . " to portal (url was $url)",
        'debug'
    );
    my $urlc_init = $class->encodeUrl($url);
    lmSetHeaderOut( $apacheRequest,
            'Location' => $class->portal()
          . "?url=$urlc_init"
          . ( $arg ? "&$arg" : "" ) );
    return REDIRECT;
}

## @rmethod protected $ fetchId()
# Get user cookies and search for Lemonldap::NG cookie.
# @return Value of the cookie if found, 0 else
sub fetchId {
    my $t = lmHeaderIn( $apacheRequest, 'Cookie' );
    return ( $t =~ /$cookieName=([^,; ]+)/o ) ? $1 : 0;
}

# MAIN SUBROUTINE called by Apache (using PerlHeaderParserHandler option)

## @rmethod int run(Apache2::RequestRec apacheRequest)
# Main method used to control access.
# Calls :
# - fetchId()
# - lmSetApacheUser()
# - grant()
# - forbidden() if user is rejected
# - sendHeaders() if user is granted
# - hideCookie()
# - updateStatus()
# @param $apacheRequest Current request
# @return Apache2::Const value (OK, FORBIDDEN, REDIRECT or SERVER_ERROR)
sub run ($$) {
    my $class;
    ( $class, $apacheRequest ) = @_;
    return DECLINED unless ( $apacheRequest->is_initial_req );
    my $args = $apacheRequest->args;

    # Cross domain authentication
    if ( $cda and $args =~ s/[\?&]?($cookieName=\w+)$//oi ) {
        my $str = $1;
        $class->lmLog( 'CDA request', 'debug' );
        $apacheRequest->args($args);
        my $host = $apacheRequest->get_server_name();
        my $portString = $port || $apacheRequest->get_server_port();
        lmSetErrHeaderOut( $apacheRequest,
                'Location' => "http"
              . ( $https ? 's' : '' )
              . "://$host:$portString"
              . $apacheRequest->uri
              . ( $apacheRequest->args ? "?" . $apacheRequest->args : "" ) );
        $host =~ s/^[^\.]+\.(.*\..*$)/$1/;
        lmSetErrHeaderOut( $apacheRequest,
            'Set-Cookie' => "$str; domain=$host; path=/"
              . ( $https ? "; secure" : "" ) );
        return REDIRECT;
    }
    my $uri = $apacheRequest->uri . ( $args ? "?$args" : "" );

    # AUTHENTICATION
    # I - recover the cookie
    my $id;
    unless ( $id = $class->fetchId ) {
        $class->lmLog( "$class: No cookie found", 'info' );
        $class->updateStatus( $apacheRequest->connection->remote_ip,
            $apacheRequest->uri, 'REDIRECT' );
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
                $class->updateStatus( $apacheRequest->connection->remote_ip,
                    $apacheRequest->uri, 'EXPIRED' );
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
    $class->lmSetApacheUser( $apacheRequest, $datas->{$whatToTrace} );

    # AUTHORIZATION
    return $class->forbidden($uri) unless ( $class->grant($uri) );
    $class->updateStatus( $datas->{$whatToTrace}, $apacheRequest->uri, 'OK' );

    # ACCOUNTING
    # 2 - Inform remote application
    $class->sendHeaders;

    # SECURITY
    # Hide Lemonldap::NG cookie
    $class->hideCookie;

    # Cleanup and log
    $apacheRequest->push_handlers(
        PerlLogHandler => sub { $class->logGranted( $uri, $datas ); DECLINED },
    );
    $apacheRequest->push_handlers(
        PerlCleanupHandler => sub { $class->cleanLocalStorage(@_); DECLINED },
    );

    if ( defined( $transform->{$uri} ) ) {
        return &{ $transform->{$uri} };
    }
    OK;
}

## @rmethod protected void sendHeaders()
# Launch function compiled by forgeHeadersInit()
sub sendHeaders {
    &$forgeHeaders;
}

## @rmethod int unprotect()
# Used to unprotect an area.
# To use it, set "PerlHeaderParserHandler My::Package->unprotect" Apache
# configuration file.
# It replace run() by doing nothing.
# @return Apache2::Const::OK
sub unprotect {
    OK;
}

## @rmethod protected void localUnlog()
# Delete current user from local cache entry.
sub localUnlog {
    my $class = shift;
    if ( my $id = $class->fetchId ) {

        # Delete Apache thread datas
        if ( $id eq $datas->{_session_id} ) {
            $datas = {};
        }

        # Delete Apache local cache
        if ( $refLocalStorage and $refLocalStorage->get($id) ) {
            $refLocalStorage->remove($id);
        }
    }
}

## @rmethod protected int unlog(Apache::RequestRec apacheRequest)
# Call localUnlog() then goToPortal() to unlog the current user.
# @return Apache2::Const value returned by goToPortal()
sub unlog ($$) {
    my $class;
    ( $class, $apacheRequest ) = @_;
    $class->localUnlog;
    $class->updateStatus( $apacheRequest->connection->remote_ip,
        $apacheRequest->uri, 'LOGOUT' );
    return $class->goToPortal( '/', 'logout=1' );
}

## @rmethod protected int redirectFilter(string url, Apache2::Filter f)
# Launch the current HTTP request then redirects the user to $url.
# Used by logout_app and logout_app_sso targets
# @param $url URL to redirect the user
# @param $f Current Apache2::Filter object
# @return Apache2::Const::REDIRECT
sub redirectFilter {
    my $class = shift;
    my $url   = shift;
    my $f     = shift;
    unless ( $f->ctx ) {

        # Here, we can use Apache2 functions instead of lmSetHeaderOut because
        # this function is used only with Apache2.
        $f->r->status(REDIRECT);
        $f->r->status_line("302 Temporary Moved");
        $f->r->headers_out->unset('Location');
        $f->r->err_headers_out->set( 'Location' => $url );
        $f->ctx(1);
    }
    while ( $f->read( my $buffer, 1024 ) ) {
    }
    $class->updateStatus(
        (
              $datas->{$whatToTrace}
            ? $datas->{$whatToTrace}
            : $f->r->connection->remote_ip
        ),
        'filter',
        'REDIRECT'
    );
    return REDIRECT;
}

## @rmethod int status(Apache2::RequestRec $r)
# Get the result from the status process and launch a PerlResponseHandler to
# display it.
# @param $r Current request
# @return Apache2::Const::OK
sub status($$) {
    my ( $class, $r ) = @_;
    $class->lmLog( "$class: request for status", 'debug' );
    return SERVER_ERROR unless ( $statusPipe and $statusOut );
    $r->handler("perl-script");
    print $statusPipe "STATUS" . ( $r->args ? " " . $r->args : '' ) . "\n";
    my $buf;
    while (<$statusOut>) {
        last if (/^END$/);
        $buf .= $_;
    }
    if ( MP() == 2 ) {
        $r->push_handlers(
            'PerlResponseHandler' => sub {
                my $r = shift;
                $r->content_type('text/html; charset=UTF-8');
                $r->print($buf);
                OK;
            }
        );
    }
    else {
        $r->push_handlers(
            'PerlHandler' => sub {
                my $r = shift;
                $r->content_type('text/html; charset=UTF-8');
                $r->send_http_header;
                $r->print($buf);
                OK;
            }
        );
    }
    return OK;
}

#################
# OTHER METHODS #
#################

## @rmethod protected int cleanLocalStorage()
# Clean expired values from the local cache.
# @return Apache2::Const::DECLINED
sub cleanLocalStorage {
    $refLocalStorage->purge() if ($refLocalStorage);
    return DECLINED;
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
             '^/pj/.*$'       => '$qualif="opj"',
             '^/rh/.*$'       => '$ou=~/brh/',
             '^/rh_or_opj.*$' => '$qualif="opj" or $ou=~/brh/',
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

Name of the cookie used by the Lemonldap::NG infrastructure.

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

=item B<port> (default: undef)

If port is not well defined in redirection, you can fix listen port here.

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
