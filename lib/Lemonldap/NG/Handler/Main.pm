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
package Lemonldap::NG::Handler::Main;

#use strict;

use MIME::Base64;
use Exporter 'import';

#use AutoLoader 'AUTOLOAD';
use Lemonldap::NG::Common::Crypto;
use Lemonldap::NG::Common::Session;
require POSIX;
use CGI::Util 'expires';
use constant UNPROTECT        => 1;
use constant SKIP             => 2;
use constant MAINTENANCE_CODE => 503;

#inherits Cache::Cache
#inherits Apache::Session
#link Lemonldap::NG::Common::Apache::Session::SOAP protected globalStorage

our $VERSION = '1.4.1';

our %EXPORT_TAGS;

our @EXPORT_OK;

our @EXPORT;

# my @tSharedVar = qw(
#     cookieName           customFunctions        defaultCondition
#     defaultProtection    forgeHeaders           globalStorage
#     globalStorageOptions headerList             https
#     key                  localStorage           localStorageOptions
#     locationCondition    locationConditionText  locationCount
#     locationProtection   locationRegexp         maintenance
#     port                 refLocalStorage        securedCookie
#     statusOut            statusPipe             timeoutActivity
#     useRedirectOnError   useRedirectOnForbidden useSafeJail
#     whatToTrace
# );
#
# my @nontSharedVar = qw(
#     safe
#     cipher               datasUpdate            transform
#     cda                  childInitDone          httpOnly
#     cookieExpiration
# );
#
# non threaded shared vars non being part of $ntsv hashref
# (because of share_from in Jail.pm):
# $apacheRequest
# $datas

# Shared variables
our ( $apacheRequest, $datas, $tsv, $ntsv, );

##########################################
# COMPATIBILITY WITH APACHE AND APACHE 2 #
##########################################

BEGIN {

    # globalStorage and locationRules are set for Manager compatibility only
    %EXPORT_TAGS = (
        globalStorage  => [qw(  )],
        locationRules  => [qw( )],
        jailSharedVars => [qw( $apacheRequest $datas )],
        tsv            => [qw( $tsv )],
        ntsv           => [qw( $ntsv )],
        import         => [qw( import @EXPORT_OK @EXPORT %EXPORT_TAGS )],
        headers        => [
            qw(
              lmHeaderIn lmSetHeaderIn lmHeaderOut
              lmSetHeaderOut lmSetErrHeaderOut
              )
        ],
        apache => [
            qw( MP OK REDIRECT FORBIDDEN DONE DECLINED SERVER_ERROR
              )
        ],
        post => [qw(postFilter)],
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
            threads::shared::share($tsv);
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

use Lemonldap::NG::Handler::Initialization::LocalInit;
use Lemonldap::NG::Handler::Initialization::GlobalInit;
use Lemonldap::NG::Handler::Main::Jail;
use Lemonldap::NG::Handler::Main::Headers;
use Lemonldap::NG::Handler::Main::PostForm;
use Lemonldap::NG::Handler::Main::Logger;

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

## @rmethod protected void updateStatus(string user,string url,string action)
# Inform the status process of the result of the request if it is available.
sub updateStatus {
    my ( $class, $user, $url, $action ) = splice @_;
    my $statusPipe = $tsv->{statusPipe};
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
        $class->updateStatus( $datas->{ $tsv->{whatToTrace} }, $_[0],
            'LOGOUT' );
        my $u = $datas->{_logout};
        $class->localUnlog;
        return $class->goToPortal( $u, 'logout=1' );
    }
    $class->updateStatus( $datas->{ $tsv->{whatToTrace} }, $_[0], 'REJECT' );
    $apacheRequest->push_handlers(
        PerlLogHandler => sub {
            $_[0]->status(FORBIDDEN);
            $class->logForbidden( $uri, $datas );
            DECLINED;
        }
    );

    # Redirect or Forbidden?
    if ( $tsv->{useRedirectOnForbidden} ) {
        Lemonldap::NG::Handler::Main::Logger->lmLog(
            "Use redirect for forbidden access", 'debug' );
        return $class->goToPortal( $uri, 'lmError=403' );
    }
    else {
        Lemonldap::NG::Handler::Main::Logger->lmLog( "Return forbidden access",
            'debug' );
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
    Lemonldap::NG::Handler::Main::Logger->lmLog(
        'User "'
          . $datas->{ $tsv->{whatToTrace} }
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
    Lemonldap::NG::Handler::Main::Logger->lmLog(
        'User "'
          . $datas->{ $tsv->{whatToTrace} }
          . '" was granted to access to '
          . $uri,
        'debug'
    );
}

## @rmethod protected void hideCookie()
# Hide Lemonldap::NG cookie to the protected application.
sub hideCookie {
    my $class = shift;
    Lemonldap::NG::Handler::Main::Logger->lmLog( "removing cookie", 'debug' );
    my $tmp = Lemonldap::NG::Handler::Main::Headers->lmHeaderIn( $apacheRequest,
        'Cookie' );
    $tmp =~ s/$tsv->{cookieName}(http)?=[^,;]*[,;\s]*//og;
    if ($tmp) {
        Lemonldap::NG::Handler::Main::Headers->lmSetHeaderIn( $apacheRequest,
            'Cookie' => $tmp );
    }
    else {
        Lemonldap::NG::Handler::Main::Headers->lmUnsetHeaderIn( $apacheRequest,
            'Cookie' );
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
    Lemonldap::NG::Handler::Main::Logger->lmLog(
        "Redirect " . $class->ip() . " to portal (url was $url)", 'debug' );
    my $urlc_init = $class->encodeUrl($url);
    Lemonldap::NG::Handler::Main::Headers->lmSetHeaderOut( $apacheRequest,
            'Location' => $class->portal()
          . "?url=$urlc_init"
          . ( $arg ? "&$arg" : "" ) );
    return REDIRECT;
}

## @rmethod protected $ fetchId()
# Get user cookies and search for Lemonldap::NG cookie.
# @return Value of the cookie if found, 0 else
sub fetchId {
    my $t = Lemonldap::NG::Handler::Main::Headers->lmHeaderIn( $apacheRequest,
        'Cookie' );
    my $vhost = $apacheRequest->hostname;
    my $lookForHttpCookie = $tsv->{securedCookie} =~ /^(2|3)$/
      && !(
        defined( $tsv->{https}->{$vhost} )
        ? $tsv->{https}->{$vhost}
        : $tsv->{https}->{_}
      );
    my $value =
      $lookForHttpCookie
      ? ( $t =~ /$tsv->{cookieName}http=([^,; ]+)/o ? $1 : 0 )
      : ( $t =~ /$tsv->{cookieName}=([^,; ]+)/o ? $1 : 0 );

    $value = $ntsv->{cipher}->decryptHex( $value, "http" )
      if ( $value && $lookForHttpCookie && $tsv->{securedCookie} == 3 );
    return $value;
}

## @rmethod protected boolean retrieveSession(id)
# Tries to retrieve the session whose index is id
# @return true if the session was found, false else
sub retrieveSession {
    my ( $class, $id ) = @_;

    # 1. Search if the user was the same as previous (very efficient in
    # persistent connection).
    return 1
      if (  defined $datas->{_session_id}
        and $id eq $datas->{_session_id}
        and ( time() - $ntsv->{datasUpdate} < 60 ) );

    # 2. Get the session from cache or backend
    my $apacheSession = Lemonldap::NG::Common::Session->new(
        {
            storageModule        => $tsv->{globalStorage},
            storageModuleOptions => $tsv->{globalStorageOptions},
            cacheModule          => $tsv->{localSessionStorage},
            cacheModuleOptions   => $tsv->{localSessionStorageOptions},
            id                   => $id,
            kind                 => "SSO",
        }
    );

    unless ( $apacheSession->error ) {

        $datas = $apacheSession->data;

        # Update the session to notify activity, if necessary
        if ( $tsv->{timeoutActivity} ) {
            $apacheSession->update( { '_lastSeen' => time } );

            if ( $apacheSession->error ) {
                Lemonldap::NG::Handler::Main::Logger->lmLog(
                    "Cannot update session $id", 'error' );
                Lemonldap::NG::Handler::Main::Logger->lmLog(
                    $apacheSession->error, 'error' );
            }
        }

        $datasUpdate = time();
        return 1;
    }
    else {
        Lemonldap::NG::Handler::Main::Logger->lmLog(
            "Session $id can't be retrieved", 'info' );
        Lemonldap::NG::Handler::Main::Logger->lmLog( $apacheSession->error,
            'info' );

        return 0;
    }
}

sub ip {
    my $ip = 'unknownIP';
    eval {
        $ip =
          ( MP() == 2 )
          ? $apacheRequest->connection->remote_ip
          : $apacheRequest->remote_ip;
    };
    return $ip;
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

        if ( $tsv->{useRedirectOnError} ) {
            Lemonldap::NG::Handler::Main::Logger->lmLog(
                "Got to portal with maintenance error code", 'debug' );
            return $class->goToPortal( '/', 'lmError=' . MAINTENANCE_CODE );
        }
        else {
            Lemonldap::NG::Handler::Main::Logger->lmLog(
                "Return maintenance error code", 'debug' );
            return MAINTENANCE_CODE;
        }
    }

    # Cross domain authentication
    if (    $ntsv->{cda}
        and $args =~ s/[\?&]?($tsv->{cookieName}(http)?=\w+)$//oi )
    {
        my $str = $1;
        Lemonldap::NG::Handler::Main::Logger->lmLog( 'CDA request', 'debug' );
        $apacheRequest->args($args);
        my $redirectUrl = $class->_buildUrl( $apacheRequest->uri );
        my $redirectHttps = ( $redirectUrl =~ m/^https/ );
        Lemonldap::NG::Handler::Main::Headers->lmSetErrHeaderOut(
            $apacheRequest,
            'Location' => $redirectUrl . ( $args ? "?" . $args : "" ) );
        Lemonldap::NG::Handler::Main::Headers->lmSetErrHeaderOut(
            $apacheRequest,
            'Set-Cookie' => "$str; path=/"
              . ( $redirectHttps    ? "; secure"   : "" )
              . ( $ntsv->{httpOnly} ? "; HttpOnly" : "" )
              . (
                $ntsv->{cookieExpiration}
                ? "; expires=" . expires( $ntsv->{cookieExpiration}, 'cookie' )
                : ""
              )
        );
        return REDIRECT;
    }
    my $uri      = $apacheRequest->unparsed_uri();
    my $uri_orig = $uri;
    Apache2::URI::unescape_url($uri);

    my $protection = $class->isUnprotected($uri);

    if ( $protection == SKIP ) {
        Lemonldap::NG::Handler::Main::Logger->lmLog( "Access control skipped",
            "debug" );
        $class->updateStatus( $class->ip(), $apacheRequest->uri, 'SKIP' );
        $class->hideCookie;
        Lemonldap::NG::Handler::Main::Headers->cleanHeaders( $apacheRequest,
            $tsv->{forgeHeaders}, $tsv->{headerList} );
        return OK;
    }

    my $id;

    # Try to recover cookie and user session
    if ( $id = $class->fetchId and $class->retrieveSession($id) ) {

        # AUTHENTICATION done

        # Local macros
        my $kc = keys %$datas;    # in order to detect new local macro

        # ACCOUNTING (1. Inform Apache)
        $class->lmSetApacheUser( $apacheRequest,
            $datas->{ $tsv->{whatToTrace} } );

        # AUTHORIZATION
        return $class->forbidden($uri)
          unless ( $class->grant($uri) );
        $class->updateStatus( $datas->{ $tsv->{whatToTrace} },
            $apacheRequest->uri, 'OK' );

        # ACCOUNTING (2. Inform remote application)
        Lemonldap::NG::Handler::Main::Headers->sendHeaders( $apacheRequest,
            $tsv->{forgeHeaders} );

        # Store local macros
        if ( keys %$datas > $kc and $tsv->{refLocalStorage} ) {
            Lemonldap::NG::Handler::Main::Logger->lmLog( "Update local cache",
                "debug" );
            $tsv->{refLocalStorage}->set( $id, $datas, "10 minutes" );
        }

        # Hide Lemonldap::NG cookie
        $class->hideCookie;

        # Log
        $apacheRequest->push_handlers( PerlLogHandler =>
              sub { $class->logGranted( $uri, $datas ); DECLINED }, );

        #  Catch POST rules
        Lemonldap::NG::Handler::Main::PostForm->transformUri($uri);

        return OK;
    }

    elsif ( $protection == UNPROTECT ) {

        # Ignore unprotected URIs
        Lemonldap::NG::Handler::Main::Logger->lmLog(
            "No valid session but unprotected access", "debug" );
        $class->updateStatus( $class->ip(), $apacheRequest->uri, 'UNPROTECT' );
        $class->hideCookie;
        Lemonldap::NG::Handler::Main::Headers->cleanHeaders( $apacheRequest,
            $tsv->{forgeHeaders}, $tsv->{headerList} );
        return OK;
    }

    else {

        # Redirect user to the portal
        Lemonldap::NG::Handler::Main::Logger->lmLog( "$class: No cookie found",
            'info' )
          unless ($id);

        # if the cookie was fetched, a log is sent by retrieveSession()
        $class->updateStatus( $class->ip(), $apacheRequest->uri,
            $id ? 'EXPIRED' : 'REDIRECT' );
        return $class->goToPortal($uri_orig);
    }
}

## @rmethod protected boolean checkMaintenanceMode
# Check if we are in maintenance mode
# @return true if maintenance mode
sub checkMaintenanceMode {
    my ($class) = splice @_;
    my $vhost = $apacheRequest->hostname;
    my $_maintenance =
      ( defined $tsv->{maintenance}->{$vhost} )
      ? $tsv->{maintenance}->{$vhost}
      : $tsv->{maintenance}->{_};

    if ($_maintenance) {
        Lemonldap::NG::Handler::Main::Logger->lmLog(
            "Maintenance mode activated", 'debug' );
        return 1;
    }

    return 0;
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
        my $uri  = $apacheRequest->unparsed_uri();

        # Set error 500 in logs even if "useRedirectOnError" is set
        $apacheRequest->push_handlers(
            PerlLogHandler => sub { $_[0]->status(SERVER_ERROR); DECLINED; } );
        Lemonldap::NG::Handler::Main::Logger->lmLog( $mess, 'error' );

        # Redirect or die
        if ( $tsv->{useRedirectOnError} ) {
            Lemonldap::NG::Handler::Main::Logger->lmLog(
                "Use redirect for error", 'debug' );
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

## @imethod void localInit(hashRef args)
# instanciate a LocalInit object with variables:
# localStorage, localStorageOptions, refLocalStorage, childInitDone
# launch localInit method:
#  - calls purgeCache() to purge the local cache,
#  - launch the status processus,
#  - launch childInit (to init / clean local storage)
# @param $args reference to the initialization hash
sub localInit($$) {
    my ( $class, $args ) = splice @_;

    my $localinit = Lemonldap::NG::Handler::Initialization::LocalInit->new(
        localStorage        => $tsv->{localStorage},
        refLocalStorage     => $tsv->{refLocalStorage},
        localStorageOptions => $tsv->{localStorageOptions},
        childInitDone       => $tsv->{childInitDone},
    );
    (
        @$tsv{
            qw( localStorage refLocalStorage localStorageOptions statusPipe statusOut )
        },
        $ntsv->{childInitDone}
    ) = $localinit->localInit($args);

}

## @imethod void globalInit(hashRef args)
# instanciate a GlobalInit object with variables:
# customFunctions, useSafeJail, and safe
# Global initialization process launches :
# - defaultValuesInit()
# - portalInit()
# - locationRulesInit()
# - globalStorageInit()
# - localSessionStorageInit()
# - headerListInit()
# - forgeHeadersInit()
# - postUrlInit()
# @param $args reference to the configuration hash
sub globalInit {
    my $class = shift;

    my $globalinit = Lemonldap::NG::Handler::Initialization::GlobalInit->new(
        customFunctions => $tsv->{customFunctions},
        useSafeJail     => $tsv->{useSafeJail},
        safe            => $ntsv->{safe},
    );

    (
        @$tsv{
            qw( cookieName      securedCookie      whatToTrace
              https           port               customFunctions
              timeoutActivity useRedirectOnError useRedirectOnForbidden
              useSafeJail     key                maintenance )
        },
        @$ntsv{
            qw( cda             httpOnly           cookieExpiration
              cipher
              )
        }
      )
      = $globalinit->defaultValuesInit(
        @$tsv{
            qw( cookieName      securedCookie      whatToTrace
              https           port               customFunctions
              timeoutActivity useRedirectOnError useRedirectOnForbidden
              useSafeJail     key                maintenance )
        },
        @$ntsv{
            qw( cda             httpOnly           cookieExpiration
              cipher )
        },
        @_
      );

    ( *portal, $ntsv->{safe} ) = $globalinit->portalInit( $class, @_ );

    (
        @$tsv{
            qw( locationCount defaultCondition
              defaultProtection locationCondition
              locationProtection locationRegexp
              locationConditionText )
        },
        $ntsv->{safe}
      )
      = $globalinit->locationRulesInit(
        $class,
        @$tsv{
            qw( locationCount defaultCondition
              defaultProtection locationCondition
              locationProtection locationRegexp
              locationConditionText )
        },
        @_
      );

    @$tsv{qw( globalStorage globalStorageOptions )} =
      $globalinit->globalStorageInit(
        @$tsv{qw( globalStorage globalStorageOptions )}, @_ );

    @$tsv{qw( localSessionStorage localSessionStorageOptions )} =
      $globalinit->localSessionStorageInit(
        @$tsv{qw( localSessionStorage localSessionStorageOptions )}, @_ );

    $tsv->{headerList} = $globalinit->headerListInit( $tsv->{headerList}, @_ );

    $tsv->{forgeHeaders} =
      $globalinit->forgeHeadersInit( $tsv->{forgeHeaders}, @_ );

    $ntsv->{transform} = $globalinit->postUrlInit( $ntsv->{transform}, @_ );

}

## @rmethod boolean grant()
# Grant or refuse client using compiled regexp and functions
# @return True if the user is granted to access to the current URL
sub grant {
    my ( $class, $uri ) = splice @_;
    my $vhost = $apacheRequest->hostname;
    for ( my $i = 0 ; $i < $tsv->{locationCount}->{$vhost} ; $i++ ) {
        if ( $uri =~ $tsv->{locationRegexp}->{$vhost}->[$i] ) {
            Lemonldap::NG::Handler::Main::Logger->lmLog(
                'Regexp "'
                  . $tsv->{locationConditionText}->{$vhost}->[$i]
                  . '" match',
                'debug'
            );
            return &{ $tsv->{locationCondition}->{$vhost}->[$i] }($datas);
        }
    }
    unless ( $tsv->{defaultCondition}->{$vhost} ) {
        Lemonldap::NG::Handler::Main::Logger->lmLog(
            "User rejected because VirtualHost \"$vhost\" has no configuration",
            'warn'
        );
        return 0;
    }
    Lemonldap::NG::Handler::Main::Logger->lmLog( "$vhost: Apply default rule",
        'debug' );
    return &{ $tsv->{defaultCondition}->{$vhost} }($datas);
}

## @cmethod private string _buildUrl(string s)
# Transform /<s> into http(s?)://<host>:<port>/s
# @param $s path
# @return URL
sub _buildUrl {
    my ( $class, $s ) = splice @_;
    my $vhost = $apacheRequest->hostname;
    my $portString =
         $tsv->{port}->{$vhost}
      || $tsv->{port}->{_}
      || $apacheRequest->get_server_port();
    my $_https = (
        defined( $tsv->{https}->{$vhost} )
        ? $tsv->{https}->{$vhost}
        : $tsv->{https}->{_}
    );
    $portString =
        ( $_https  && $portString == 443 ) ? ''
      : ( !$_https && $portString == 80 )  ? ''
      :                                      ':' . $portString;
    my $url = "http"
      . ( $_https ? "s" : "" ) . "://"
      . $apacheRequest->get_server_name()
      . $portString
      . $s;
    Lemonldap::NG::Handler::Main::Logger->lmLog( "Build URL $url", 'debug' );
    return $url;
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
        if ( $tsv->{refLocalStorage} and $tsv->{refLocalStorage}->get($id) ) {
            $tsv->{refLocalStorage}->remove($id);
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
    $class->updateStatus( $class->ip(), $apacheRequest->uri, 'LOGOUT' );
    return $class->goToPortal( '/', 'logout=1' );
}

## @rmethod int status(Apache2::RequestRec $r)
# Get the result from the status process and launch a PerlResponseHandler to
# display it.
# @param $r Current request
# @return Apache2::Const::OK
sub status($$) {
    my ( $class, $r ) = splice @_;

    my $statusOut  = $tsv->{statusOut};
    my $statusPipe = $tsv->{statusPipe};

    Lemonldap::NG::Handler::Main::Logger->lmLog( "$class: request for status",
        'debug' );
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
              $datas->{ $tsv->{whatToTrace} }
            ? $datas->{ $tsv->{whatToTrace} }
            : $f->r->connection->remote_ip
        ),
        'filter',
        'REDIRECT'
    );
    return OK;
}

## @rmethod protected int isUnprotected()
# @return 0 if URI is protected,
# UNPROTECT if it is unprotected by "unprotect",
# SKIP if is is unprotected by "skip"
sub isUnprotected {
    my ( $class, $uri ) = splice @_;
    my $vhost = $apacheRequest->hostname;
    for ( my $i = 0 ; $i < $tsv->{locationCount}->{$vhost} ; $i++ ) {
        if ( $uri =~ $tsv->{locationRegexp}->{$vhost}->[$i] ) {
            return $tsv->{locationProtection}->{$vhost}->[$i];
        }
    }
    return $tsv->{defaultProtection}->{$vhost};
}

1;
