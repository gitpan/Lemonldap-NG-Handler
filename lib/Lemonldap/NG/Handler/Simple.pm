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
use AutoLoader 'AUTOLOAD';
use Safe;
use Lemonldap::NG::Common::Safelib;    #link protected safe Safe object
use Lemonldap::NG::Common::Crypto;
require POSIX;
use CGI::Util 'expires';
use constant SAFEWRAP => ( Safe->can("wrap_code_ref") ? 1 : 0 );
use constant UNPROTECT        => 1;
use constant SKIP             => 2;
use constant MAINTENANCE_CODE => 503;

#inherits Cache::Cache
#inherits Apache::Session
#link Lemonldap::NG::Common::Apache::Session::SOAP protected globalStorage

our $VERSION = '1.2.3';

our %EXPORT_TAGS;

our @EXPORT_OK;

our @EXPORT;

# Shared variables
our (
    $locationRegexp,     $locationCondition,   $defaultCondition,
    $locationProtection, $defaultProtection,   $forgeHeaders,
    $apacheRequest,      $locationCount,       $cookieName,
    $datas,              $globalStorage,       $globalStorageOptions,
    $localStorage,       $localStorageOptions, $whatToTrace,
    $https,              $refLocalStorage,     $safe,
    $port,               $statusPipe,          $statusOut,
    $customFunctions,    $transform,           $cda,
    $childInitDone,      $httpOnly,            $cookieExpiration,
    $timeoutActivity,    $datasUpdate,         $useRedirectOnForbidden,
    $useRedirectOnError, $useSafeJail,         $securedCookie,
    $key,                $cipher,              $headerList,
    $maintenance,
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
              $locationProtection $defaultProtection $datasUpdate
              $locationRegexp $apacheRequest $datas safe $customFunctions
              $useSafeJail
              )
        ],
        import  => [qw( import @EXPORT_OK @EXPORT %EXPORT_TAGS )],
        headers => [
            qw(
              $forgeHeaders lmHeaderIn lmSetHeaderIn lmHeaderOut
              lmSetHeaderOut lmSetErrHeaderOut $cookieName $https $port
              $securedCookie $key $cipher $headerList
              )
        ],
        traces => [qw( $whatToTrace $statusPipe $statusOut)],
        apache => [
            qw( MP OK REDIRECT FORBIDDEN DONE DECLINED SERVER_ERROR
              $useRedirectOnForbidden $useRedirectOnError $maintenance )
        ],
        post   => [qw($transform postFilter)],
        cda    => ['$cda'],
        cookie => [
            qw(
              $cookieName $https $httpOnly $cookieExpiration
              $securedCookie $key $cipher
              )
        ],
        session => ['$timeoutActivity'],
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
        require Apache2::URI;
        Apache2::URI->import();
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
            threads::shared::share($locationProtection);
            threads::shared::share($defaultProtection);
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
            threads::shared::share($timeoutActivity);
            threads::shared::share($useRedirectOnForbidden);
            threads::shared::share($useRedirectOnError);
            threads::shared::share($useSafeJail);
            threads::shared::share($customFunctions);
            threads::shared::share($securedCookie);
            threads::shared::share($key);
            threads::shared::share($headerList);
            threads::shared::share($maintenance);
        };
        print "eval error: $@" if ($@);
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

## @rmethod protected int handler_mp2()
# Launch run() when used under mod_perl version 2
# @return Apache constant
sub handler_mp2 : method {
    shift->run(@_);
}

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
    my ( $class, $mess, $level ) = splice @_;
    die("Level is required") unless ($level);
    my $call;
    unless ( $level eq 'debug' ) {
        my @tmp = caller();
        $call = "$tmp[1] $tmp[2]:";
    }
    if ( MP() == 2 ) {
        Apache2::ServerRec->log->debug($call) if ($call);
        Apache2::ServerRec->log->$level($mess);
    }
    elsif ( MP() == 1 ) {
        Apache->server->log->debug($call) if ($call);
        Apache->server->log->$level($mess);
    }
    else {
        print STDERR "[$level] $mess\n";
    }
}

## @rmethod protected void lmSetApacheUser(Apache2::RequestRec r,string s)
# Inform Apache for the data to use as user for logs
# @param $r current request
# @param $s string to use
sub lmSetApacheUser {
    my ( $class, $r, $s ) = splice @_;
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
    my ( $class, $str ) = splice @_;
    if ( MP() == 2 ) {
        $str =~ s/\$datas->\{ip\}/\$apacheRequest->connection->remote_ip/g;
    }
    else {
        $str =~ s/\$datas->\{ip\}/\$apacheRequest->remote_ip/g;
    }
    return $str;
}

## @rmethod void lmSetHeaderIn(Apache2::RequestRec r, hash headers)
# Set HTTP headers in the HTTP request.
# @param $r Current request
# @param %headers Hash of header names and values
sub lmSetHeaderIn {
    my ( $class, $r, %headers ) = splice @_;
    while ( my ( $h, $v ) = each %headers ) {
        if ( MP() == 2 ) {
            $r->headers_in->set( $h => $v );
        }
        elsif ( MP() == 1 ) {
            $r->header_in( $h => $v );
        }
        $class->lmLog( "Send header $h with value $v", 'debug' );
    }
}

## @rmethod void lmUnsetHeaderIn(Apache2::RequestRec r, array headers)
# Unset HTTP headers in the HTTP request.
# @param $r Current request
# @param @headers Name of the headers
sub lmUnsetHeaderIn {
    my ( $class, $r, @headers ) = splice @_;
    foreach my $h (@headers) {
        if ( MP() == 2 ) {
            $r->headers_in->unset($h);
        }
        elsif ( MP() == 1 ) {
            $r->header_in( $h => "" )
              if ( $r->header_in($h) );
        }
        $class->lmLog( "Unset header $h", 'debug' );
    }
}

## @rfn string lmHeaderIn(Apache2::RequestRec r, string h)
# Return an HTTP header value from the HTTP request.
# @param $r Current request
# @param $h Name of the header
# @return Value of the header
sub lmHeaderIn {
    my ( $r, $h ) = splice @_;
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
    my ( $r, $h, $v ) = splice @_;
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
    my ( $r, $h, $v ) = splice @_;
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
    my ( $r, $h, $v ) = splice @_;
    if ( MP() == 2 ) {
        return $r->headers_out->{$h};
    }
    elsif ( MP() == 1 ) {
        return $r->header_out($h);
    }
}

##############################
# Fake Safe jail subroutines #
##############################

## @method reval
# Fake reval method if useSafeJail desactivated
sub reval {
    my ( $class, $e ) = splice @_;
    return eval $e;
}

## @method wrap_code_ref
# Fake wrap_code_ref method if useSafeJail desactivated
sub wrap_code_ref {
    my ( $class, $e ) = splice @_;
    return $e;
}

## @method share
# Fake share method if useSafeJail desactivated
sub share {
    my ( $class, @vars ) = splice @_;
    $class->share_from( scalar(caller), \@vars );
}

## @method share_form
# Fake share_from method if useSafeJail desactivated
sub share_from {
    my ( $class, $pkg, $vars ) = splice @_;

    no strict 'refs';
    foreach my $arg (@$vars) {
        my ( $var, $type );
        $type = $1 if ( $var = $arg ) =~ s/^(\W)//;
        for ( 1 .. 2 ) {    # assign twice to avoid any 'used once' warnings
            *{$var} =
                ( !$type ) ? \&{ $pkg . "::$var" }
              : ( $type eq '&' ) ? \&{ $pkg . "::$var" }
              : ( $type eq '$' ) ? \${ $pkg . "::$var" }
              : ( $type eq '@' ) ? \@{ $pkg . "::$var" }
              : ( $type eq '%' ) ? \%{ $pkg . "::$var" }
              : ( $type eq '*' ) ? *{ $pkg . "::$var" }
              :                    undef;
        }
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

    $useSafeJail = 1 unless defined $useSafeJail;

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

    if ($useSafeJail) {
        $safe = new Safe;
        $safe->share_from( 'main', ['%ENV'] );
    }
    else {
        $safe = $class;
    }

    # Share objets with Safe jail
    $safe->share_from( 'Lemonldap::NG::Common::Safelib',
        $Lemonldap::NG::Common::Safelib::functions );
    $safe->share( '&encode_base64', '$datas', '&portal', '$apacheRequest', @t );

    return $safe;
}

## @imethod void localInit(hashRef args)
# Call purgeCache() to purge the local cache, launch the status process
# (statusProcess()) in wanted and launch childInit().
# @param $args reference to the initialization hash
sub localInit($$) {
    my ( $class, $args ) = splice @_;
    if ( $localStorage = $args->{localStorage} ) {
        $localStorageOptions = $args->{localStorageOptions};
        $localStorageOptions->{namespace}          ||= "lemonldap";
        $localStorageOptions->{default_expires_in} ||= 600;
        $class->purgeCache();
    }
    if ( $args->{status} ) {
        if ( defined $localStorage ) {
            statusProcess();
        }
        else {

            # localStorage is mandatory for status module
            $class->lmLog(
"Status module can not be loaded without localStorage parameter",
                'warn'
            );
        }
    }
    $class->childInit($args);
}

## @imethod protected boolean childInit()
# Indicates to Apache that it has to launch:
# - initLocalStorage() for each child process (after fork and uid change)
# - cleanLocalStorage() after each requests
# @return True
sub childInit {
    my ( $class, $args ) = splice @_;
    return 1 if ($childInitDone);

    # We don't initialise local storage in the "init" subroutine because it can
    # be used at the starting of Apache and so with the "root" privileges. Local
    # Storage is also initialized just after Apache's fork and privilege lost.

    # Local storage is cleaned after giving the content of the page to increase
    # performances.
    no strict;
    if ( MP() == 2 ) {
        $s = Apache2::ServerUtil->server;
        $s->push_handlers( PerlChildInitHandler =>
              sub { return $class->initLocalStorage( $_[1], $_[0] ); } );
        $s->push_handlers(
            PerlPostConfigHandler => sub {
                my ( $c, $l, $t, $s ) = splice @_;
                $s->add_version_component(
                    'Lemonldap::NG::Handler/' . $VERSION );
            }
        ) unless ( $args->{hideSignature} );
    }
    elsif ( MP() == 1 ) {
        Apache->push_handlers(
            PerlChildInitHandler => sub { return $class->initLocalStorage(@_); }
        );
    }
    $childInitDone++;
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
# - defaultValuesInit()
# - portalInit()
# - locationRulesInit()
# - globalStorageInit()
# - forgeHeadersInit()
# - postUrlInit()
# @param $args reference to the configuration hash
sub globalInit {
    my $class = shift;
    $class->defaultValuesInit(@_);
    $class->portalInit(@_);
    $class->locationRulesInit(@_);
    $class->globalStorageInit(@_);
    $class->headerListInit(@_);
    $class->forgeHeadersInit(@_);
    $class->postUrlInit(@_);
}

## @imethod protected codeRef conditionSub(string cond)
# Returns a compiled function used to grant users (used by
# locationRulesInit(). The second value returned is a non null
# constant if URL is not protected (by "unprotect" or "skip"), 0 else.
# @param $cond The boolean expression to use
# @return array (ref(sub), int)
sub conditionSub {
    my ( $class, $cond ) = splice @_;
    my ( $OK, $NOK ) = ( sub { 1 }, sub { 0 } );

    # Simple cases : accept and deny
    return ( $OK, 0 )
      if ( $cond =~ /^accept$/i );
    return ( $NOK, 0 )
      if ( $cond =~ /^deny$/i );

    # Cases unprotect and skip : 2nd value is 1 or 2
    return ( $OK, UNPROTECT )
      if ( $cond =~ /^unprotect$/i );
    return ( $OK, SKIP )
      if ( $cond =~ /^skip$/i );

    # Case logout
    if ( $cond =~ /^logout(?:_sso)?(?:\s+(.*))?$/i ) {
        my $url = $1;
        return (
            $url
            ? ( sub { $datas->{_logout} = $url; return 0 }, 0 )
            : ( sub { $datas->{_logout} = portal(); return 0 }, 0 )
        );
    }

    # Since filter exists only with Apache>=2, logout_app and logout_app_sso
    # targets are available only for it.
    # This error can also appear with Manager configured as CGI script
    if ( $cond =~ /^logout_app/i and MP() < 2 ) {
        $class->lmLog( "Rules logout_app and logout_app_sso require Apache>=2",
            'warn' );
        return ( sub { 1 }, 0 );
    }

    # logout_app
    if ( $cond =~ /^logout_app(?:\s+(.*))?$/i ) {
        my $u = $1 || $class->portal();
        eval 'use Apache2::Filter' unless ( $INC{"Apache2/Filter.pm"} );
        return (
            sub {
                $apacheRequest->add_output_filter(
                    sub {
                        return $class->redirectFilter( $u, @_ );
                    }
                );
                1;
            },
            0
        );
    }
    elsif ( $cond =~ /^logout_app_sso(?:\s+(.*))?$/i ) {
        eval 'use Apache2::Filter' unless ( $INC{"Apache2/Filter.pm"} );
        my $u = $1 || $class->portal();
        return (
            sub {
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
            },
            0
        );
    }

    # Replace some strings in condition
    $cond =~ s/\$date/&POSIX::strftime("%Y%m%d%H%M%S",localtime())/e;
    $cond =~ s/\$(\w+)/\$datas->{$1}/g;
    $cond =~ s/\$datas->{vhost}/\$apacheRequest->hostname/g;

    # Eval sub
    my $sub = (
        SAFEWRAP
        ? $class->safe->wrap_code_ref(
            $class->safe->reval("sub{return($cond)}")
          )
        : $class->safe->reval("sub{return($cond)}")
    );

    # Return sub and protected flag
    return ( $sub, 0 );
}

## @imethod protected void defaultValuesInit(hashRef args)
# Set default values for non-customized variables
# @param $args reference to the configuration hash
sub defaultValuesInit {
    my ( $class, $args ) = splice @_;

    # Warning: first start of handler load values from MyHanlder.pm
    # and lemonldap-ng.ini
    # These values should be erased by global configuration!
    $cookieName = $args->{cookieName} || $cookieName || 'lemonldap';
    $securedCookie =
        defined( $args->{securedCookie} ) ? $args->{securedCookie}
      : defined($securedCookie)           ? $securedCookie
      :                                     1;
    $whatToTrace = $args->{whatToTrace} || $whatToTrace || 'uid';
    $whatToTrace =~ s/\$//g;
    $https = defined($https) ? $https : $args->{https};
    $port ||= $args->{port};
    $customFunctions  = $args->{customFunctions};
    $cda              = defined($cda) ? $cda : $args->{cda};
    $httpOnly         = defined($httpOnly) ? $httpOnly : $args->{httpOnly};
    $cookieExpiration = $args->{cookieExpiration} || $cookieExpiration;
    $timeoutActivity  = $args->{timeoutActivity} || $timeoutActivity || 0;
    $useRedirectOnError =
      defined($useRedirectOnError)
      ? $useRedirectOnError
      : $args->{useRedirectOnError};
    $useRedirectOnForbidden =
      defined($useRedirectOnForbidden)
      ? $useRedirectOnForbidden
      : $args->{useRedirectOnForbidden};
    $useSafeJail =
      defined($useSafeJail)
      ? $useSafeJail
      : $args->{useSafeJail};
    $key ||= 'lemonldap-ng-key';
    $cipher ||= Lemonldap::NG::Common::Crypto->new($key);

    if ( $args->{key} && ( $args->{key} ne $key ) ) {
        $key    = $args->{key};
        $cipher = Lemonldap::NG::Common::Crypto->new($key);
    }

    $maintenance = defined($maintenance) ? $maintenance : $args->{maintenance};

    1;
}

## @imethod protected void portalInit(hashRef args)
# Verify that portal variable exists. Die unless
# @param $args reference to the configuration hash
sub portalInit {
    my ( $class, $args ) = splice @_;
    die("portal parameter required") unless ( $args->{portal} );
    if ( $args->{portal} =~ /[\$\(&\|"']/ ) {
        my ($portal) = $class->conditionSub( $args->{portal} );
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
    my ( $class, $args ) = splice @_;
    $globalStorage = $args->{globalStorage}
      or die("globalStorage required");
    eval "use $globalStorage;";
    die($@) if ($@);
    $globalStorageOptions = $args->{globalStorageOptions};
}

## @imethod protected int initLocalStorage()
# Prepare local cache (if not done before by Lemonldap::NG::Common::Conf)
# @return Apache2::Const::DECLINED
sub initLocalStorage {
    my ( $class, $r ) = splice @_;
    if ( $localStorage and not $refLocalStorage ) {
        eval
"use $localStorage;\$refLocalStorage = new $localStorage(\$localStorageOptions);";
        $class->lmLog( "Local cache initialization failed: $@", 'error' )
          unless ( defined $refLocalStorage );
    }
    return DECLINED;
}

###################
# RUNNING METHODS #
###################

## @rmethod protected void updateStatus(string user,string url,string action)
# Inform the status process of the result of the request if it is available.
sub updateStatus {
    my ( $class, $user, $url, $action ) = splice @_;
    eval {
            print $statusPipe "$user => "
          . $apacheRequest->hostname
          . "$url $action\n"
          if ($statusPipe);
    };
}

## @rmethod protected int forbidden(string uri)
# Used to reject non authorized requests.
# Inform the status processus and call logForbidden().
# @param uri URI requested
# @return Apache2::Const::REDIRECT or Apache2::Const::FORBIDDEN
sub forbidden {
    my ( $class, $uri ) = splice @_;
    if ( $datas->{_logout} ) {
        $class->updateStatus( $datas->{$whatToTrace}, $_[0], 'LOGOUT' );
        my $u = $datas->{_logout};
        $class->localUnlog;
        return $class->goToPortal( $u, 'logout=1' );
    }
    $class->updateStatus( $datas->{$whatToTrace}, $_[0], 'REJECT' );
    $apacheRequest->push_handlers(
        PerlLogHandler => sub {
            $_[0]->status(FORBIDDEN);
            $class->logForbidden( $uri, $datas );
            DECLINED;
        }
    );

    # Redirect or Forbidden?
    if ($useRedirectOnForbidden) {
        $class->lmLog( "Use redirect for forbidden access", 'debug' );
        return $class->goToPortal( $uri, 'lmError=403' );
    }
    else {
        $class->lmLog( "Return forbidden access", 'debug' );
        return FORBIDDEN;
    }
}

## @rmethod protected void logForbidden(string uri,hashref datas)
# Insert a log in Apache errors log system to inform that the user was rejected.
# This method has to be overloaded to use different logs systems
# @param $uri uri asked
# @param $datas hash re to user's datas
sub logForbidden {
    my ( $class, $uri, $datas ) = splice @_;
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
    my ( $class, $uri, $datas ) = splice @_;
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
    $class->lmLog( "removing cookie", 'debug' );
    my $tmp = lmHeaderIn( $apacheRequest, 'Cookie' );
    $tmp =~ s/$cookieName(http)?=[^,;]*[,;\s]*//og;
    if ($tmp) {
        $class->lmSetHeaderIn( $apacheRequest, 'Cookie' => $tmp );
    }
    else {
        $class->lmUnsetHeaderIn( $apacheRequest, 'Cookie' );
    }
}

## @rmethod protected string encodeUrl(string url)
# Encode URl in the format used by Lemonldap::NG::Portal for redirections.
# @return Base64 encoded string
sub encodeUrl {
    my ( $class, $url ) = splice @_;
    $url = $class->_buildUrl($url) if ( $url !~ m#^https?://# );
    return encode_base64( $url, '' );
}

## @rmethod protected int goToPortal(string url, string arg)
# Redirect non-authenticated users to the portal by setting "Location:" header.
# @param $url Url requested
# @param $arg optionnal GET parameters
# @return Apache2::Const::REDIRECT
sub goToPortal {
    my ( $class, $url, $arg ) = splice @_;
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
    my $lookForHttpCookie = $securedCookie =~ /^(2|3)$/ && $https->{_} == 0;
    my $value =
      $lookForHttpCookie
      ? ( $t =~ /${cookieName}http=([^,; ]+)/o ? $1 : 0 )
      : ( $t =~ /$cookieName=([^,; ]+)/o ? $1 : 0 );

    $value = $cipher->decryptHex( $value, "http" )
      if ( $value && $lookForHttpCookie && $securedCookie == 3 );
    return $value;
}

## @rmethod protected boolean retrieveSession(id)
# Tries to retrieve the session whose index is id
# @return true if the session was found, false else
sub retrieveSession {
    my ( $class, $id ) = @_;

    # 1. search if the user was the same as previous (very efficient in
    #      persistent connection).
    return 1
      if ( $id eq $datas->{_session_id} and ( time() - $datasUpdate < 60 ) );

    # 2. search in the local cache if exists
    return 1
      if ( $refLocalStorage and $datas = $refLocalStorage->get($id) );

    # 3. search in the central cache
    my %h;
    eval { tie %h, $globalStorage, $id, $globalStorageOptions; };
    if ($@) {
        $class->lmLog( "Session $id can't be retrieved: $@", 'info' );
        return 0;
    }

    # Update the session to notify activity, if necessary
    $h{_lastSeen} = time() if ($timeoutActivity);

    # Set _session_id key
    $h{_session_id} = $id;

    # Store data in current shared variables
    $datas->{$_} = $h{$_} foreach ( keys %h );

    # Store the session in local storage
    $refLocalStorage->set( $id, $datas, "10 minutes" )
      if ($refLocalStorage);

    untie %h;
    $datasUpdate = time();
    return 1;
}

# MAIN SUBROUTINE called by Apache (using PerlHeaderParserHandler option)

## @rmethod int run(Apache2::RequestRec apacheRequest)
# Main method used to control access.
# Calls :
# - fetchId()
# - retrieveSession()
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
    ( $class, $apacheRequest ) = splice @_;
    return DECLINED unless ( $apacheRequest->is_initial_req );
    my $args = $apacheRequest->args;

    # Direct return if maintenance mode is active
    if ( $class->checkMaintenanceMode() ) {

        if ($useRedirectOnError) {
            $class->lmLog( "Got to portal with maintenance error code",
                'debug' );
            return $class->goToPortal( '/', 'lmError=' . MAINTENANCE_CODE );
        }
        else {
            $class->lmLog( "Return maintenance error code", 'debug' );
            return MAINTENANCE_CODE;
        }
    }

    # Cross domain authentication
    if ( $cda and $args =~ s/[\?&]?($cookieName(http)?=\w+)$//oi ) {
        my $str = $1;
        $class->lmLog( 'CDA request', 'debug' );
        $apacheRequest->args($args);
        my $redirectUrl   = $class->_buildUrl( $apacheRequest->uri );
        my $redirectHttps = ( $redirectUrl =~ m/^https/ );
        lmSetErrHeaderOut( $apacheRequest,
            'Location' => $redirectUrl . ( $args ? "?" . $args : "" ) );
        lmSetErrHeaderOut(
            $apacheRequest,
            'Set-Cookie' => "$str; path=/"
              . ( $redirectHttps ? "; secure"   : "" )
              . ( $httpOnly      ? "; HttpOnly" : "" )
              . (
                $cookieExpiration
                ? "; expires=" . expires( $cookieExpiration, 'cookie' )
                : ""
              )
        );
        return REDIRECT;
    }
    my $uri = $apacheRequest->uri . ( $args ? "?$args" : "" );
    Apache2::URI::unescape_url($uri);

    my $protection = $class->isUnprotected($uri);

    if ( $protection == SKIP ) {
        $class->lmLog( "Access control skipped", "debug" );
        $class->updateStatus( $apacheRequest->connection->remote_ip,
            $apacheRequest->uri, 'SKIP' );
        $class->hideCookie;
        $class->cleanHeaders;
        return OK;
    }

    my $id;

    # Try to recover cookie and user session
    if ( $id = $class->fetchId and $class->retrieveSession($id) ) {

        # AUTHENTICATION done

        my $kc = keys %$datas;    # in order to detect new local macro

        # ACCOUNTING (1. Inform Apache)
        $class->lmSetApacheUser( $apacheRequest, $datas->{$whatToTrace} );

        # AUTHORIZATION
        return $class->forbidden($uri)
          unless ( $class->grant($uri) );
        $class->updateStatus( $datas->{$whatToTrace},
            $apacheRequest->uri, 'OK' );

        # ACCOUNTING (2. Inform remote application)
        $class->sendHeaders;

        # Store local macros
        if ( keys %$datas > $kc and $refLocalStorage ) {
            $class->lmLog( "Update local cache", "debug" );
            $refLocalStorage->set( $id, $datas, "10 minutes" );
        }

        # Hide Lemonldap::NG cookie
        $class->hideCookie;

        # Log
        $apacheRequest->push_handlers( PerlLogHandler =>
              sub { $class->logGranted( $uri, $datas ); DECLINED }, );

        #  Catch POST rules
        $class->transformUri($uri);

        return OK;
    }

    elsif ( $protection == UNPROTECT ) {

        # Ignore unprotected URIs
        $class->lmLog( "No valid session but unprotected access", "debug" );
        $class->updateStatus( $apacheRequest->connection->remote_ip,
            $apacheRequest->uri, 'UNPROTECT' );
        $class->hideCookie;
        $class->cleanHeaders;
        return OK;
    }

    else {

        # Redirect user to the portal
        $class->lmLog( "$class: No cookie found", 'info' )
          unless ($id);

        # if the cookie was fetched, a log is sent by retrieveSession()
        $class->updateStatus( $apacheRequest->connection->remote_ip,
            $apacheRequest->uri, $id ? 'EXPIRED' : 'REDIRECT' );
        return $class->goToPortal($uri);
    }
}

## @rmethod protected boolean checkMaintenanceMode
# Check if we are in maintenance mode
# @return true if maintenance mode
sub checkMaintenanceMode {
    my ($class) = splice @_;

    if ($maintenance) {
        $class->lmLog( "Maintenance mode activated", 'debug' );
        return 1;
    }

    return 0;
}

1;
__END__

=head1 NAME

=encoding utf8

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

Name and parameters of the optional but recommended Cache::* module used to
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
L<http://lemonldap-ng.org/>

=head1 AUTHOR

=over

=item Clement Oudot, E<lt>clem.oudot@gmail.comE<gt>

=item François-Xavier Deltombe, E<lt>fxdeltombe@gmail.com.E<gt>

=item Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=item Thomas Chemineau, E<lt>thomas.chemineau@gmail.comE<gt>

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

=item Copyright (C) 2012, 2013 by François-Xavier Deltombe, E<lt>fxdeltombe@gmail.com.E<gt>

=item Copyright (C) 2006, 2009, 2010, 2011, 2012, 2013 by Clement Oudot, E<lt>clem.oudot@gmail.comE<gt>

=item Copyright (C) 2010 by Thomas Chemineau, E<lt>thomas.chemineau@gmail.comE<gt>

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
## @rmethod int abort(string mess)
# Logs message and exit or redirect to the portal if "useRedirectOnError" is
# set to true.
# @param $mess Message to log
# @return Apache2::Const::REDIRECT or Apache2::Const::SERVER_ERROR
sub abort {
    my ( $class, $mess ) = splice @_;

    # If abort is called without a valid request, fall to die
    eval {
        my $args = $apacheRequest->args;
        my $uri = $apacheRequest->uri . ( $args ? "?$args" : "" );

        # Set error 500 in logs even if "useRedirectOnError" is set
        $apacheRequest->push_handlers(
            PerlLogHandler => sub { $_[0]->status(SERVER_ERROR); DECLINED; } );
        $class->lmLog( $mess, 'error' );

        # Redirect or die
        if ($useRedirectOnError) {
            $class->lmLog( "Use redirect for error", 'debug' );
            return $class->goToPortal( $uri, 'lmError=500' );
        }
        else {
            return SERVER_ERROR;
        }
    };
    die $mess if ($@);
}

## @rmethod protected int handler_mp1()
# Launch run() when used under mod_perl version 1
# @return Apache constant
sub handler_mp1 ($$) { shift->run(@_); }

## @rmethod protected int logout_mp1()
# Launch unlog() when used under mod_perl version 1
# @return Apache constant
sub logout_mp1 ($$) { shift->unlog(@_); }

## @imethod void init(hashRef args)
# Calls localInit() and globalInit().
# @param $args reference to the initialization hash
sub init($$) {
    my $class = shift;
    $class->localInit(@_);
    $class->globalInit(@_);
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
    my ( $class, $args ) = splice @_;
    $locationCount = 0;

    # Pre compilation : both regexp and conditions
    foreach ( sort keys %{ $args->{locationRules} } ) {
        if ( $_ eq 'default' ) {
            ( $defaultCondition, $defaultProtection ) =
              $class->conditionSub( $args->{locationRules}->{$_} );
        }
        else {
            (
                $locationCondition->[$locationCount],
                $locationProtection->[$locationCount]
            ) = $class->conditionSub( $args->{locationRules}->{$_} );
            $locationRegexp->[$locationCount] = qr/$_/;
            $locationCount++;
        }
    }

    # Default police: all authenticated users are accepted
    ( $defaultCondition, $defaultProtection ) = $class->conditionSub('accept')
      unless ($defaultCondition);
    1;
}

## @imethod protected void forgeHeadersInit(hashRef args)
# Create the &$forgeHeaders subroutine used to insert
# headers into the HTTP request.
# @param $args reference to the configuration hash
sub forgeHeadersInit {
    my ( $class, $args ) = splice @_;

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
        $sub .= "'$_' => join('',split(/[\\r\\n]+/,$tmp{$_})),";
    }
    $forgeHeaders = (
        SAFEWRAP
        ? $class->safe->wrap_code_ref( $class->safe->reval("sub{$sub}") )
        : $class->safe->reval("sub{return($sub)}")
    );
    $class->lmLog( "$class: Unable to forge headers: $@: sub {$sub}", 'error' )
      if ($@);
    1;
}

## @imethod protected void headerListInit(hashRef args)
# Lists the exported HTTP headers into $headerList
# @param $args reference to the configuration hash
sub headerListInit {
    my ( $class, $args ) = splice @_;

    if ( $args->{exportedHeaders} ) {
        my @tmp = keys %{ $args->{exportedHeaders} };
        $headerList = \@tmp;
    }
    1;
}

## @imethod protected buildPostForm(string url, int count)
# Build form that will be posted by client
# Fill an input hidden with fake value to
# reach the size of initial request
# @param url Target of POST
# @param count Fake input size
# @return Apache2::Const::OK
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
qq{<html><body onload="document.getElementById('f').submit()"><form id="f" method="post" action="$url" style="visibility:hidden"><input type=hidden name="a" value="}
                  . sprintf( "%0" . $count . "d", 1 )
                  . qq{"/><input type="submit" value="Ok"/></form></body></html>}
            );
            OK;
        }
    );
    OK;
}

## @rmethod protected void sendHeaders()
# Launch function compiled by forgeHeadersInit()
sub sendHeaders {
    my ($class) = splice @_;
    $class->lmSetHeaderIn( $apacheRequest, &$forgeHeaders );
}

## @rmethod protected void cleanHeaders()
# Clean HTTP headers to prevent user to send custom headers
# that would not be caught if access rule is unprotect or skip
sub cleanHeaders {
    my ($class) = splice @_;
    $class->lmUnsetHeaderIn( $apacheRequest, @{$headerList} );
}

## @rmethod protected int isUnprotected()
# @return 0 if URI is protected,
# UNPROTECT if it is unprotected by "unprotect",
# SKIP if it is unprotected by "skip"
sub isUnprotected {
    my ( $class, $uri ) = splice @_;
    for ( my $i = 0 ; $i < $locationCount ; $i++ ) {
        return $locationProtection->[$i]
          if ( $uri =~ $locationRegexp->[$i] );
    }
    return $defaultProtection;
}

## @rmethod protected boolean grant(string uri)
# Grant or refuse client using compiled regexp and functions
# @param uri URI requested
# @return True if the user is granted to access to the current URL
sub grant {
    my ( $class, $uri ) = splice @_;
    for ( my $i = 0 ; $i < $locationCount ; $i++ ) {
        return &{ $locationCondition->[$i] }($datas)
          if ( $uri =~ $locationRegexp->[$i] );
    }
    return &$defaultCondition($datas);
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

    #  Browse all POST URI
    while ( my ( $url, $d ) = each( %{ $args->{post} } ) ) {

        # Where to POST
        $d->{postUrl} ||= $url;

        # Register POST form for POST URL
        $transform->{$url} = sub { $class->buildPostForm( $d->{postUrl} ) }
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
            $postdata{$_} = "'$postdata{$_}'" if ( $postdata{$_} =~ /^\w+$/ );
            $tmp .= "'$_'=>$postdata{$_},";
        }

        $class->lmLog( "Compiling POST request for $url", 'debug' );
        $transform->{ $d->{postUrl} } = sub {
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

## @rmethod protected int postFilter(hashref data, Apache2::Filter f)
# POST data
# @param $data Data to POST
# @param $f Current Apache2::Filter object
# @return Apache2::Const::OK
sub postFilter {
    my $class = shift;
    my $data  = shift;
    my $f     = shift;
    my $l;

    unless ( $f->ctx ) {
        $f->ctx(1);

        # Create the transformed form data
        my $u = URI->new('http:');
        $u->query_form( { $class->safe->reval($data) } );
        my $s = $u->query();

        # Eat all fake data sent by client
        $l = $f->r->headers_in->{'Content-Length'};
        while ( $f->read( my $b, $l ) ) { }

        # Send to application real data
        $f->r->headers_in->set( 'Content-Length' => length($s) );
        $f->r->headers_in->set(
            'Content-Type' => 'application/x-www-form-urlencoded' );
        $f->print($s);

        $class->lmLog( "Send POST data $s", 'debug' );

        # Mark this filter as done
        $f->seen_eos(1);
    }
    return OK;
}

## @rmethod protected transformUri(string uri)
# Transform URI to replay POST forms
# @param uri URI to catch
# @return Apache2::Const
sub transformUri {
    my ( $class, $uri ) = splice @_;

    if ( defined( $transform->{$uri} ) ) {
        return &{ $transform->{$uri} };
    }

    OK;
}

## @method private string _buildUrl(string s)
# Transform /<s> into http(s?)://<host>:<port>/s
# @param $s path
# @return URL
sub _buildUrl {
    my ( $class, $s ) = splice @_;
    my $portString = $port || $apacheRequest->get_server_port();
    $portString =
        ( $https  && $portString == 443 ) ? ''
      : ( !$https && $portString == 80 )  ? ''
      :                                     ':' . $portString;
    return
        "http"
      . ( $https ? "s" : "" ) . "://"
      . $apacheRequest->get_server_name()
      . $portString
      . $s;
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
        require Data::Dumper;
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
    ( $class, $apacheRequest ) = splice @_;
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
# @return Apache2::Const::OK
sub redirectFilter {
    my $class = shift;
    my $url   = shift;
    my $f     = shift;
    unless ( $f->ctx ) {

        # Here, we can use Apache2 functions instead of lmSetHeaderOut because
        # this function is used only with Apache2.
        $f->r->status(REDIRECT);
        $f->r->status_line("303 See Other");
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
    return OK;
}

## @rmethod int status(Apache2::RequestRec $r)
# Get the result from the status process and launch a PerlResponseHandler to
# display it.
# @param $r Current request
# @return Apache2::Const::OK
sub status($$) {
    my ( $class, $r ) = splice @_;
    $class->lmLog( "$class: request for status", 'debug' );
    return $class->abort("$class: status page can not be displayed")
      unless ( $statusPipe and $statusOut );
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

