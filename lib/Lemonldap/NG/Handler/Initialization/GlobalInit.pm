package Lemonldap::NG::Handler::Initialization::GlobalInit;

#use Lemonldap::NG::Handler::Main qw(:all);
use Lemonldap::NG::Common::Safelib;    #link protected safe Safe object
use Safe;
use constant UNPROTECT => 1;
use constant SKIP      => 2;

use Mouse;

use Lemonldap::NG::Handler::Main::Jail;
use Lemonldap::NG::Handler::Main::Logger;

has customFunctions => ( is => 'rw', isa => 'Maybe[Str]' );

has useSafeJail => ( is => 'rw', isa => 'Maybe[Int]' );

has safe => ( is => 'rw' );

BEGIN {
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
        eval '
        use constant OK           => Apache2::Const::OK;
        ';
    }
    else {    # For Test or CGI
        eval '
        use constant OK           => 1;
        ';
    }
}

## @imethod protected void defaultValuesInit(hashRef args)
# Set default values for non-customized variables
# @param $args reference to the configuration hash
sub defaultValuesInit {

    my (
        $self,                   $cookieName,      $securedCookie,
        $whatToTrace,            $https,           $port,
        $customFunctions,        $timeoutActivity, $useRedirectOnError,
        $useRedirectOnForbidden, $useSafeJail,     $key,
        $maintenance,            $cda,             $httpOnly,
        $cookieExpiration,       $cipher,          $args,
    ) = splice @_;
    foreach my $t (qw(https port maintenance)) {

        # Skip Handler initialization (values not defined)
        next unless defined $args->{$t};

        # Record default value in key '_'
        $args->{$t} = { _ => $args->{$t} } unless ( ref( $args->{$t} ) );

        # Override with vhost options
        if ( defined $args->{vhostOptions} ) {
            my $n = 'vhost' . ucfirst($t);
            foreach my $k ( keys %{ $args->{vhostOptions} } ) {
                foreach my $alias (
                    @{ $self->getAliases( $k, $args->{vhostOptions} ) } )
                {
                    my $v = $args->{vhostOptions}->{$k}->{$n};
                    Lemonldap::NG::Handler::Main::Logger->lmLog(
                        "Options $t for vhost $alias: $v", 'debug' );
                    $args->{$t}->{$alias} = $v
                      if ( $v >= 0 );    # Keep default value if $v is negative
                }
            }
        }
    }

    # Default values are defined in Common::Conf::Attributes
    # These values should be erased by global configuration
    $cookieName = $args->{cookieName} || $cookieName;
    $securedCookie =
      defined( $args->{securedCookie} )
      ? $args->{securedCookie}
      : $securedCookie;
    $whatToTrace = $args->{whatToTrace} || $whatToTrace;
    $https = defined($https) ? $https : $args->{https};
    $port ||= $args->{port};
    $customFunctions = $args->{customFunctions};
    $self->customFunctions($customFunctions);
    $cda      = defined($cda)      ? $cda      : $args->{cda};
    $httpOnly = defined($httpOnly) ? $httpOnly : $args->{httpOnly};
    $cookieExpiration = $args->{cookieExpiration} || $cookieExpiration;
    $timeoutActivity  = $args->{timeoutActivity}  || $timeoutActivity;
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
    $self->useSafeJail($useSafeJail);
    $key ||= 'lemonldap-ng-key';
    $cipher ||= Lemonldap::NG::Common::Crypto->new($key);

    if ( $args->{key} && ( $args->{key} ne $key ) ) {
        $key    = $args->{key};
        $cipher = Lemonldap::NG::Common::Crypto->new($key);
    }

    $maintenance = defined($maintenance) ? $maintenance : $args->{maintenance};

    return (
        $cookieName,      $securedCookie,      $whatToTrace,
        $https,           $port,               $customFunctions,
        $timeoutActivity, $useRedirectOnError, $useRedirectOnForbidden,
        $useSafeJail,     $key,                $maintenance,
        $cda,             $httpOnly,           $cookieExpiration,
        $cipher
    );
    1;
}

## @imethod protected void portalInit(hashRef args)
# Verify that portal variable exists. Die unless
# @param $args reference to the configuration hash
sub portalInit {
    my ( $self, $mainClass, $args ) = splice @_;
    die("portal parameter required") unless ( $args->{portal} );
    if ( $args->{portal} =~ /[\$\(&\|"']/ ) {
        my ($portal) = $self->conditionSub( $mainClass, $args->{portal} );
        eval "sub portal {return &\$portal}";
    }
    else {
        eval "sub portal {return '$args->{portal}'}";
    }
    die("Unable to read portal parameter ($@)") if ($@);
    return ( \&portal, $self->{safe} );
    1;
}

## @imethod void locationRulesInit(hashRef args)
# Compile rules.
# Rules are stored in $args->{locationRules}->{&lt;virtualhost&gt;} that contains
# regexp=>test expressions where :
# - regexp is used to test URIs
# - test contains an expression used to grant the user
#
# This function creates 2 hashRef containing :
# - one list of the compiled regular expressions for each virtual host
# - one list of the compiled functions (compiled with conditionSub()) for each
# virtual host
# @param $args reference to the configuration hash
sub locationRulesInit {
    my (
        $self,               $mainClass,         $locationCount,
        $defaultCondition,   $defaultProtection, $locationCondition,
        $locationProtection, $locationRegexp,    $locationConditionText,
        $args
    ) = splice @_;
    foreach my $vhost ( keys %{ $args->{locationRules} } ) {
        foreach
          my $alias ( @{ $self->getAliases( $vhost, $args->{vhostOptions} ) } )
        {
            $locationCount->{$alias} = 0;
            foreach ( sort keys %{ $args->{locationRules}->{$vhost} } ) {
                if ( $_ eq 'default' ) {
                    (
                        $defaultCondition->{$alias},
                        $defaultProtection->{$alias}
                      )
                      = $self->conditionSub( $mainClass,
                        $args->{locationRules}->{$vhost}->{$_} );
                }
                else {
                    (
                        $locationCondition->{$alias}
                          ->[ $locationCount->{$alias} ],
                        $locationProtection->{$alias}
                          ->[ $locationCount->{$alias} ]
                      )
                      = $self->conditionSub( $mainClass,
                        $args->{locationRules}->{$vhost}->{$_} );
                    $locationRegexp->{$alias}->[ $locationCount->{$alias} ] =
                      qr/$_/;
                    $locationConditionText->{$alias}
                      ->[ $locationCount->{$alias} ] =
                      /^\(\?#(.*?)\)/ ? $1 : /^(.*?)##(.+)$/ ? $2 : $_;
                    $locationCount->{$alias}++;
                }
            }

            # Default police
            ( $defaultCondition->{$alias}, $defaultProtection->{$alias} ) =
              $self->conditionSub( $mainClass, 'accept' )
              unless ( $defaultCondition->{$alias} );
        }

    }

    return (
        $locationCount,         $defaultCondition,   $defaultProtection,
        $locationCondition,     $locationProtection, $locationRegexp,
        $locationConditionText, $self->{safe}
    );
    1;
}

## @imethod protected void globalStorageInit(hashRef args)
# Initialize the Apache::Session::* module choosed to share user's variables.
# @param $args reference to the configuration hash
sub globalStorageInit {
    my ( $self, $globalStorage, $globalStorageOptions, $args ) = splice @_;
    $globalStorage = $args->{globalStorage}
      or die("globalStorage required");
    eval "use $globalStorage;";
    die($@) if ($@);
    $globalStorageOptions = $args->{globalStorageOptions};
    return ( $globalStorage, $globalStorageOptions );
}

## @imethod protected void localSessionStorageInit(hashRef args)
# Initialize the Cache::Cache module choosed to cache sessions.
# @param $args reference to the configuration hash
sub localSessionStorageInit {
    my ( $self, $localSessionStorage, $localSessionStorageOptions, $args ) =
      splice @_;
    $localSessionStorage        = $args->{localSessionStorage};
    $localSessionStorageOptions = $args->{localSessionStorageOptions};
    return ( $localSessionStorage, $localSessionStorageOptions );
}

## @imethod void headerListInit(hashRef args)
# Lists the exported HTTP headers into $headerList
# @param $args reference to the configuration hash
sub headerListInit {
    my ( $self, $headerList, $args ) = splice @_;

    foreach my $vhost ( keys %{ $args->{exportedHeaders} } ) {
        foreach
          my $alias ( @{ $self->getAliases( $vhost, $args->{vhostOptions} ) } )
        {
            my @tmp = keys %{ $args->{exportedHeaders}->{$vhost} };
            $headerList->{$alias} = \@tmp;
        }
    }
    return $headerList;
    1;
}

## @imethod void forgeHeadersInit(hashRef args)
# Create the &$forgeHeaders->{&lt;virtualhost&gt;} subroutines used to insert
# headers into the HTTP request.
# @param $args reference to the configuration hash
sub forgeHeadersInit {
    my ( $self, $forgeHeaders, $args ) = splice @_;

    # Creation of the subroutine which will generate headers
    foreach my $vhost ( keys %{ $args->{exportedHeaders} } ) {
        foreach
          my $alias ( @{ $self->getAliases( $vhost, $args->{vhostOptions} ) } )
        {
            my %tmp = %{ $args->{exportedHeaders}->{$vhost} };
            foreach ( keys %tmp ) {
                $tmp{$_} =~ s/\$(\w+)/\$datas->{$1}/g;
                $tmp{$_} = $self->regRemoteIp( $tmp{$_} );
            }

            my $sub;
            foreach ( keys %tmp ) {
                $sub .= "'$_' => join('',split(/[\\r\\n]+/,$tmp{$_})),";
            }

            my $jail = Lemonldap::NG::Handler::Main::Jail->new(
                'safe'            => $self->safe,
                'useSafeJail'     => $self->useSafeJail,
                'customFunctions' => $self->customFunctions
            );
            $self->safe( $jail->build_safe() );
            $forgeHeaders->{$alias} = $jail->jail_reval("sub{$sub}");

            Lemonldap::NG::Handler::Main::Logger->lmLog(
                "$self: Unable to forge headers: $@: sub {$sub}", 'error' )
              if ($@);
        }

    }
    return $forgeHeaders;
    1;
}

## @imethod protected void postUrlInit()
# Prepare methods to post form attributes
sub postUrlInit {
    my ( $self, $transform, $args ) = splice @_;

    # Do nothing if no POST configured
    return unless ( $args->{post} );

    # Load required modules
    eval 'use Apache2::Filter;use URI';

    # Prepare transform sub
    $transform = {};

    # Browse all vhost
    foreach my $vhost ( keys %{ $args->{post} } ) {

        foreach
          my $alias ( @{ $self->getAliases( $vhost, $args->{vhostOptions} ) } )
        {

            my $mypost = $args->{post}->{$vhost};

            #  Browse all POST URI
            while ( my ( $url, $d ) = each( %{ $args->{post}->{$vhost} } ) ) {

                # Where to POST
                $d->{postUrl} ||= $url;

                # Register POST form for POST URL
                $transform->{$alias}->{$url} = sub {
                    Lemonldap::NG::Handler::Main::PostForm->buildPostForm(
                        $d->{postUrl} );
                  }
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
                    $postdata{$_} = "'$postdata{$_}'"
                      if ( $postdata{$_} =~ /^\w+$/ );
                    $tmp .= "'$_'=>$postdata{$_},";
                }

                Lemonldap::NG::Handler::Main::Logger->lmLog(
                    "Compiling POST request for $url", 'debug' );
                $transform->{$alias}->{ $d->{postUrl} } = sub {
                    return
                      Lemonldap::NG::Handler::Main::PostForm->buildPostForm(
                        $d->{postUrl} )
                      if (
                        $Lemonldap::NG::Handler::Main::apacheRequest->method ne
                        'POST' );
                    $Lemonldap::NG::Handler::Main::apacheRequest
                      ->add_input_filter(
                        sub {
                            Lemonldap::NG::Handler::Main::PostForm->postFilter(
                                $tmp, @_ );
                        }
                      );
                    OK;
                };
            }
        }
    }
    return $transform;
}

## @imethod protected codeRef conditionSub(string cond)
# Returns a compiled function used to grant users (used by
# locationRulesInit(). The second value returned is a non null
# constant if URL is not protected (by "unprotect" or "skip"), 0 else.
# @param $cond The boolean expression to use
# @return array (ref(sub), int)
sub conditionSub {
    my ( $self, $mainClass, $cond ) = splice @_;
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
            ? (
                sub {
                    $Lemonldap::NG::Handler::Main::datas->{_logout} = $url;
                    return 0;
                },
                0
              )
            : (
                sub {
                    $Lemonldap::NG::Handler::Main::datas->{_logout} =
                      $self->portal();
                    return 0;
                },
                0
            )
        );
    }

    # Since filter exists only with Apache>=2, logout_app and logout_app_sso
    # targets are available only for it.
    # This error can also appear with Manager configured as CGI script
    if ( $cond =~ /^logout_app/i and MP() < 2 ) {
        Lemonldap::NG::Handler::Main::Logger->lmLog(
            "Rules logout_app and logout_app_sso require Apache>=2", 'warn' );
        return ( sub { 1 }, 0 );
    }

    # logout_app
    if ( $cond =~ /^logout_app(?:\s+(.*))?$/i ) {
        my $u = $1 || $self->portal();
        eval 'use Apache2::Filter' unless ( $INC{"Apache2/Filter.pm"} );
        return (
            sub {
                $Lemonldap::NG::Handler::Main::apacheRequest->add_output_filter(
                    sub {
                        return $mainClass->redirectFilter( $u, @_ );
                    }
                );
                1;
            },
            0
        );
    }
    elsif ( $cond =~ /^logout_app_sso(?:\s+(.*))?$/i ) {
        eval 'use Apache2::Filter' unless ( $INC{"Apache2/Filter.pm"} );
        my $u = $1 || $self->portal();
        return (
            sub {
                $mainClass->localUnlog;
                $Lemonldap::NG::Handler::Main::apacheRequest->add_output_filter(
                    sub {
                        return $mainClass->redirectFilter(
                            $self->portal() . "?url="
                              . $mainClass->encodeUrl($u)
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

    my $jail = Lemonldap::NG::Handler::Main::Jail->new(
        'safe'            => $self->safe,
        'useSafeJail'     => $self->useSafeJail,
        'customFunctions' => $self->customFunctions
    );
    $self->safe( $jail->build_safe() );
    my $sub = $jail->jail_reval("sub{return($cond)}");

    # Return sub and protected flag
    return ( $sub, 0 );
}

## @method arrayref getAliases(scalar vhost, hashref options)
# Check aliases of a vhost
# @param vhost vhost name
# @param options vhostOptions configuration item
# @return arrayref of vhost and aliases
sub getAliases {
    my ( $self, $vhost, $options ) = splice @_;
    my $aliases = [$vhost];

    if ( $options->{$vhost}->{vhostAliases} ) {
        foreach ( split /\s+/, $options->{$vhost}->{vhostAliases} ) {
            push @$aliases, $_;
            Lemonldap::NG::Handler::Main::Logger->lmLog(
                "$_ is an alias for $vhost", 'debug' );
        }
    }

    return $aliases;
}

## @ifn protected string protected regRemoteIp(string str)
# Replaces $ip by the client IP address in the string
# @param $str string
# @return string
sub regRemoteIp {
    my ( $self, $str ) = splice @_;
    $str =~ s/\$datas->\{ip\}/ip()/g;
    return $str;
}

1;
