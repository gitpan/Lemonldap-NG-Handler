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
require POSIX;
use CGI::Util 'expires';
use constant SAFEWRAP => ( Safe->can("wrap_code_ref") ? 1 : 0 );

#inherits Cache::Cache
#inherits Apache::Session
#link Lemonldap::NG::Common::Apache::Session::SOAP protected globalStorage

our $VERSION = '0.991';

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
    $useRedirectOnError,
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
              )
        ],
        import  => [qw( import @EXPORT_OK @EXPORT %EXPORT_TAGS )],
        headers => [
            qw(
              $forgeHeaders lmHeaderIn lmSetHeaderIn lmHeaderOut
              lmSetHeaderOut lmSetErrHeaderOut $cookieName $https $port
              )
        ],
        traces => [qw( $whatToTrace $statusPipe $statusOut)],
        apache => [
            qw( MP OK REDIRECT FORBIDDEN DONE DECLINED SERVER_ERROR
	    $useRedirectOnForbidden $useRedirectOnError )
        ],
        post    => [qw($transform)],
        cda     => ['$cda'],
        cookie  => [qw($cookieName $https $httpOnly $cookieExpiration)],
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

## @rfn void lmSetHeaderIn(Apache2::RequestRec r, string h, string v)
# Set an HTTP header in the HTTP request.
# @param $r Current request
# @param $h Name of the header
# @param $v Value of the header
sub lmSetHeaderIn {
    my ( $r, $h, $v ) = splice @_;
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
    $safe->share_from( 'main', [ '%ENV', 'APR::Table::set' ] );
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

## @imethod protected codeRef conditionSub(string cond)
# Returns a compiled function used to grant users (used by
# locationRulesInit(). The second value returned is a boolean that
# tell if URL is protected.
# @param $cond The boolean expression to use
# @return array (ref(sub),boolean)
sub conditionSub {
    my ( $class, $cond ) = splice @_;
    my ( $OK, $NOK ) = ( sub { 1 }, sub { 0 } );

    # Simple cases : accept and deny
    return ( $OK, 1 )
      if ( $cond =~ /^accept$/i );
    return ( $NOK, 1 )
      if ( $cond =~ /^deny$/i );

    # Case unprotect : 2nd value is 0 since this URL is not protected
    return ( $OK, 0 )
      if ( $cond =~ /^unprotect$/i );

    # Case logout
    if ( $cond =~ /^logout(?:_sso)?(?:\s+(.*))?$/i ) {
        my $url = $1;
        return (
            $url
            ? ( sub { $datas->{_logout} = $url; return 0 }, 1 )
            : ( sub { $datas->{_logout} = portal(); return 0 }, 1 )
        );
    }

    # Since filter exists only with Apache>=2, logout_app and logout_app_sso
    # targets are available only for it.
    if ( MP() == 2 ) {

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
                1
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
                1
            );
        }
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
    return ( $sub, 1 );
}

## @imethod protected void defaultValuesInit(hashRef args)
# Set default values for non-customized variables
# @param $args reference to the configuration hash
sub defaultValuesInit {
    my ( $class, $args ) = splice @_;

    # Warning: first start of handler load values from MyHanlder.pm
    # and lemonldap-ng.ini
    # These values should be erased by global configuration!
    $cookieName  = $args->{cookieName}  || $cookieName  || 'lemonldap';
    $whatToTrace = $args->{whatToTrace} || $whatToTrace || 'uid';
    $whatToTrace =~ s/\$//g;
    $https = defined($https) ? $https : $args->{https};
    $args->{securedCookie} = 1 unless defined( $args->{securedCookie} );
    $cookieName .= 'http' if ( $args->{securedCookie} == 2 and $https == 0 );
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
    1;
}

## @imethod protected void portalInit(hashRef args)
# Verify that portal variable exists. Die unless
# @param $args reference to the configuration hash
sub portalInit {
    my ( $class, $args ) = splice @_;
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
    my ( $class, $args ) = splice @_;
    $globalStorage = $args->{globalStorage}
      or die("globalStorage required");
    eval "use $globalStorage;";
    die($@) if ($@);
    $globalStorageOptions = $args->{globalStorageOptions};
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
        $sub .=
          "lmSetHeaderIn(\$apacheRequest,'$_' => join('',split(/[\\r\\n]+/,"
          . $tmp{$_} . ")));";
    }
    $forgeHeaders = (
        SAFEWRAP
        ? $class->safe->wrap_code_ref( $class->safe->reval("sub{$sub}") )
        : $class->safe->reval("sub{$sub}")
    );
    $class->lmLog( "$class: Unable to forge headers: $@: sub {$sub}", 'error' )
      if ($@);
    1;
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
        $transform->{ $d->{postUrl} } =
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
            $postdata{$_} = "'$postdata{$_}'" if ( $postdata{$_} =~ /^\w+$/ );
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
        $class->lmLog( "Compiling POST request for $url", 'debug' );
        $transform->{$url} = sub {
            return $class->buildPostForm($url)
              if ( $apacheRequest->method ne 'POST' );
            $apacheRequest->add_input_filter($sub);
            OK;
          }
    }
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
    my ( $class, $user, $url, $action ) = splice @_;
    eval {
            print $statusPipe "$user => "
          . $apacheRequest->hostname
          . "$url $action\n"
          if ($statusPipe);
    };
}

## @rmethod protected boolean isProtected()
# @return True if URI isn't protected (rule "unprotect")
sub isProtected {
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

## @rmethod protected int forbidden(string uri)
# Used to reject non authorizated requests.
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
    $class->lmLog( "$class: removing cookie", 'debug' );
    my $tmp = lmHeaderIn( $apacheRequest, 'Cookie' );
    $tmp =~ s/$cookieName(?:http)?[^,;]*[,;]?//og;
    lmSetHeaderIn( $apacheRequest, 'Cookie' => $tmp );
}

## @rmethod protected string encodeUrl(string url)
# Encode URl in the format used by Lemonldap::NG::Portal for redirections.
sub encodeUrl {
    my ( $class, $url ) = splice @_;
    $url = $class->_buildUrl($url) if ( $url !~ m#^https?://# );
    return encode_base64( $url, '' );
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
    return ( $t =~ /$cookieName=([^,; ]+)/o ) ? $1 : 0;
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
    ( $class, $apacheRequest ) = splice @_;
    return DECLINED unless ( $apacheRequest->is_initial_req );
    my $args = $apacheRequest->args;

    # Cross domain authentication
    if ( $cda and $args =~ s/[\?&]?($cookieName=\w+)$//oi ) {
        my $str = $1;
        $class->lmLog( 'CDA request', 'debug' );
        $apacheRequest->args($args);
        my $host          = $apacheRequest->get_server_name();
        my $redirectUrl   = $class->_buildUrl( $apacheRequest->uri );
        my $redirectHttps = ( $redirectUrl =~ m/^ĥttps/ );
        lmSetErrHeaderOut( $apacheRequest,
            'Location' => $redirectUrl . ( $args ? "?" . $args : "" ) );
        $host =~ s/^[^\.]+\.(.*\..*$)/$1/;
        lmSetErrHeaderOut(
            $apacheRequest,
            'Set-Cookie' => "$str; domain=$host; path=/"
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

    # AUTHENTICATION
    # I - recover the cookie
    my $id;
    unless ( $id = $class->fetchId ) {

        # 1.1 Ignore unprotected URIs
        unless ( $class->isProtected($uri) ) {
            $class->updateStatus( $apacheRequest->connection->remote_ip,
                $apacheRequest->uri, 'UNPROTECT' );
            return OK;
        }

        # 1.2 Redirect users to the portal
        $class->lmLog( "$class: No cookie found", 'info' );
        $class->updateStatus( $apacheRequest->connection->remote_ip,
            $apacheRequest->uri, 'REDIRECT' );
        return $class->goToPortal($uri);
    }

    # II - recover the user datas
    #  2.1 search if the user was the same as previous (very efficient in
    #      persistent connection).
    unless ( $id eq $datas->{_session_id} and ( time() - $datasUpdate < 60 ) ) {

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

                # For unprotected URI, user is not redirected
                unless ( $class->isProtected($uri) ) {
                    $class->updateStatus( $apacheRequest->connection->remote_ip,
                        $apacheRequest->uri, 'UNPROTECT' );
                    return OK;
                }
                return $class->goToPortal($uri);
            }

            # Update the session to notify activity, if necessary
            $h{_lastSeen} = time() if ($timeoutActivity);

            # Store data in current shared variables
            $datas->{$_} = $h{$_} foreach ( keys %h );

            # Store now the user in the local storage
            if ($refLocalStorage) {
                $refLocalStorage->set( $id, $datas, "10 minutes" );
            }
            untie %h;
            $datasUpdate = time();
        }
    }

    # ACCOUNTING
    # 1 - Inform Apache
    $class->lmSetApacheUser( $apacheRequest, $datas->{$whatToTrace} );

    # AUTHORIZATION
    my $kc = keys %$datas;
    return $class->forbidden($uri) unless ( $class->grant($uri) );
    $class->updateStatus( $datas->{$whatToTrace}, $apacheRequest->uri, 'OK' );

    # Store local macros
    if ( keys %$datas > $kc and $refLocalStorage ) {
        $class->lmLog( "Update local cache", "debug" );
        $refLocalStorage->set( $id, $datas, "10 minutes" );
    }

    # ACCOUNTING
    # 2 - Inform remote application
    $class->sendHeaders;

    # SECURITY
    # Hide Lemonldap::NG cookie
    $class->hideCookie;

    # Log
    $apacheRequest->push_handlers(
        PerlLogHandler => sub { $class->logGranted( $uri, $datas ); DECLINED },
    );

    #  Catch POST rules
    $class->transformUri($uri);

    # Return OK
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
# @return Apache2::Const::REDIRECT
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
    return REDIRECT;
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
