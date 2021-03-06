## @file
# Main handler.

## @class
# Main handler.
# All methods in handler are class methods: in ModPerl environment, handlers
# are always launched without object created.
#
# The main method is run() who is called by Apache for each requests (using
# handler() wrapper).
#
# The initialization process is splitted in two parts :
# - init() is launched as Apache startup
# - globalInit() is launched at each first request received by an Apache child
# and each time a new configuration is detected
package Lemonldap::NG::Handler::SharedConf;

#use strict;

use Lemonldap::NG::Handler::Main qw(:all);
use Lemonldap::NG::Handler::Initialization::GlobalInit;

#use Lemonldap::NG::Handler::Vhost;
use Lemonldap::NG::Common::Conf;               #link protected lmConf
use Lemonldap::NG::Common::Conf::Constants;    #inherits
use Cache::Cache qw($EXPIRES_NEVER);
use Lemonldap::NG::Handler::Main::Logger;

use Mouse;

extends qw(Lemonldap::NG::Handler::Main);      # Lemonldap::NG::Handler::Vhost

#use base qw(Lemonldap::NG::Handler::Vhost Lemonldap::NG::Handler::Main);

#parameter reloadTime Time in second between 2 configuration check (600)

our $VERSION    = '1.4.0';
our $cfgNum     = 0;
our $lastReload = 0;
our $reloadTime;
our $lmConf;
our $localConfig;

BEGIN {
    if ( MP() == 2 ) {
        eval {
            require threads::shared;
            Apache2::RequestUtil->import();
            threads::shared::share($cfgNum);
            threads::shared::share($lastReload);
            threads::shared::share($reloadTime);
            threads::shared::share($lmConf);
            threads::shared::share($localConfig);
        };
    }
    *EXPORT_TAGS = *Lemonldap::NG::Handler::Main::EXPORT_TAGS;
    *EXPORT_OK   = *Lemonldap::NG::Handler::Main::EXPORT_OK;
    push(
        @{ $EXPORT_TAGS{$_} },
        qw($cfgNum $lastReload $reloadTime $lmConf $localConfig)
    ) foreach (qw(variables localStorage));
    push @EXPORT_OK, qw($cfgNum $lastReload $reloadTime $lmConf $localConfig);
}

# INIT PROCESS

## @imethod void init(hashRef args)
# Constructor.
# init is overloaded to call only localInit. globalInit is called later.
# @param $args hash containing parameters
sub init($$) {
    my ( $class, $args ) = splice @_;

    # TODO reloadTime in defaultValuesInit ?
    $reloadTime = $args->{reloadTime} || 600;
    $class->localInit($args);
}

## @imethod protected void defaultValuesInit(hashRef args)
# Set default values for non-customized variables
# @param $args hash containing parameters
# @return boolean
sub defaultValuesInit {
    my ( $class, $args ) = splice @_;

    # Local configuration overrides global configuration
    my %h = ( %$args, %$localConfig );

    #return $class->SUPER::defaultValuesInit( \%h );

    my $globalinit = Lemonldap::NG::Handler::Initialization::GlobalInit->new(
        customFunctions => $tsv->{customFunctions},
        useSafeJail     => $tsv->{useSafeJail},
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
        \%h
      );

}

## @imethod void localInit(hashRef args)
# Load parameters and build the Lemonldap::NG::Common::Conf object.
# @return boolean
sub localInit {
    my ( $class, $args ) = splice @_;
    die(
"$class : unable to build configuration : $Lemonldap::NG::Common::Conf::msg"
      )
      unless ( $lmConf =
        Lemonldap::NG::Common::Conf->new( $args->{configStorage} ) );

    # Get local configuration parameters
    my $localconf = $lmConf->getLocalConf(HANDLERSECTION);
    if ($localconf) {
        $args->{$_} ||= $localconf->{$_} foreach ( keys %$localconf );
    }

    # Store in localConfig global variable
    $localConfig = $args;

    # localStorage can be declared in configStorage or at the root or both
    foreach (qw(localStorage localStorageOptions)) {
        $args->{$_} ||= $args->{configStorage}->{$_} || $lmConf->{$_};
        $args->{configStorage}->{$_} ||= $args->{$_};
    }

    $class->defaultValuesInit($args);
    $class->SUPER::localInit($args);
}

# MAIN

## @rmethod int run(Apache2::RequestRec r)
# Check configuration and launch Lemonldap::NG::Handler::Main::run().
# Each $reloadTime, the Apache child verify if its configuration is the same
# as the configuration stored in the local storage.
# @param $r Apache2::RequestRec object
# @return Apache constant
sub run($$) {
    my ( $class, $r ) = splice @_;
    if ( time() - $lastReload > $reloadTime ) {
        die("$class: No configuration found")
          unless ( $class->testConf(1) == OK );
    }
    return $class->SUPER::run($r);
}

# CONFIGURATION UPDATE

## @rmethod protected int testConf(boolean local)
# Test if configuration has changed and launch setConf() if needed.
# If the optional boolean $local is true, remote configuration is not tested:
# only local cached configuration is tested if available. $local is given to
# Lemonldap::NG::Common::getConf()
# @param $local boolean
# @return Apache constant
sub testConf {
    my ( $class, $local ) = splice @_;
    my $conf = $lmConf->getConf( { local => $local } );
    unless ( ref($conf) ) {
        Lemonldap::NG::Handler::Main::Logger->lmLog(
"$class: Unable to load configuration: $Lemonldap::NG::Common::Conf::msg",
            'error'
        );
        return $cfgNum ? OK : SERVER_ERROR;
    }
    if ( !$cfgNum or $cfgNum != $conf->{cfgNum} ) {
        Lemonldap::NG::Handler::Main::Logger->lmLog(
"$class: get configuration $conf->{cfgNum} ($Lemonldap::NG::Common::Conf::msg)",
            'debug'
        );
        $lastReload = time();
        return $class->setConf($conf);
    }
    Lemonldap::NG::Handler::Main::Logger->lmLog(
        "$class: configuration is up to date", 'debug' );
    OK;
}

## @rmethod protected int setConf(hashRef conf)
# Launch globalInit().
# Local parameters have best precedence on configuration parameters.
# @return Apache constant
sub setConf {
    my ( $class, $conf ) = splice @_;

    # Local configuration overrides global configuration
    $cfgNum = $conf->{cfgNum};
    $conf->{$_} = $localConfig->{$_} foreach ( keys %$localConfig );
    $class->globalInit($conf);
    OK;
}

# RELOAD SYSTEM

*reload = *refresh;

## @rmethod int refresh(Apache::RequestRec r)
# Launch testConf() with $local=0, so remote configuration is tested.
# Then build a simple HTTP response that just returns "200 OK" or
# "500 Server Error".
# @param $r current request
# @return Apache constant (OK or SERVER_ERROR)
sub refresh($$) {
    my ( $class, $r ) = splice @_;
    Lemonldap::NG::Handler::Main::Logger->lmLog(
        "$class: request for configuration reload", 'notice' );
    $r->handler("perl-script");
    if ( $class->testConf(0) == OK ) {
        if ( MP() == 2 ) {
            $r->push_handlers( 'PerlResponseHandler' =>
                  sub { my $r = shift; $r->content_type('text/plain'); OK } );
        }
        elsif ( MP() == 1 ) {
            $r->push_handlers(
                'PerlHandler' => sub { my $r = shift; $r->send_http_header; OK }
            );
        }
        else {
            return 1;
        }
    }
    else {
        if ( MP() == 2 ) {
            $r->push_handlers( 'PerlResponseHandler' => sub { SERVER_ERROR } );
        }
        elsif ( MP() == 1 ) {
            $r->push_handlers( 'PerlHandler' => sub { SERVER_ERROR } );
        }
        else {
            return 0;
        }
    }
    return OK;
}

1;
__END__

=head1 NAME

=encoding utf8

Lemonldap::NG::Handler::SharedConf - Perl extension to use dynamic
configuration provide by Lemonldap::NG::Manager.

=head1 SYNOPSIS

  package My::Package;
  use Lemonldap::NG::Handler::SharedConf;
  @ISA = qw(Lemonldap::NG::Handler::SharedConf);
  __PACKAGE__->init ( {
    localStorage        => "Cache::FileCache",
    localStorageOptions => {
        'namespace' => 'lemonldap-ng',
        'default_expires_in' => 600,
      },
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

This library inherit from L<Lemonldap::NG::Handler::Main> to build a
complete SSO Handler System: a central database contains the policy of your
domain. People that want to access to a protected applications are redirected
to the portal that run L<Lemonldap::NG::Portal::SharedConf>. After reading
configuration from the database and authenticating the user, it stores a key
word for each application the user is granted to access to.
Then the user is redirected to the application he wanted to access and the
Apache handler build with L<Lemonldap::NG::Handler::SharedConf::DBI> has just
to verify that the keyword corresponding to the protected area is stored in
the database.

=head2 OVERLOADED SUBROUTINES

=head3 init

Like L<Lemonldap::NG::Handler::Main>::init() but read only localStorage
related options. You may change default time between two configuration checks
with the C<reloadTime> parameter (default 600s).

=head1 OPERATION

Each new Apache child checks if there's a configuration stored in the local
store. If not, it calls getConf to get one and store it in the local store by
calling setconf.

Every 600 seconds, each Apache child checks if the local stored configuration
has changed and reload it if it has.

When refresh subroutine is called (by http for example: see synopsis), getConf
is called to get the new configuration and setconf is called to store it in the
local store.

=head1 SEE ALSO

L<Lemonldap::NG::Handler>, L<Lemonldap::NG::Manager>, L<Lemonldap::NG::Portal>,
L<http://lemonldap-ng.org/>

=head1 AUTHOR

=over

=item Clement Oudot, E<lt>clem.oudot@gmail.comE<gt>

=item Fran�ois-Xavier Deltombe, E<lt>fxdeltombe@gmail.com.E<gt>

=item Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=back

=head1 BUG REPORT

Use OW2 system to report bug or ask for features:
L<http://jira.ow2.org>

=head1 DOWNLOAD

Lemonldap::NG is available at
L<http://forge.objectweb.org/project/showfiles.php?group_id=274>

=head1 COPYRIGHT AND LICENSE

=over

=item Copyright (C) 2006, 2007, 2008, 2009, 2010, 2013 by Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=item Copyright (C) 2012 by Fran�ois-Xavier Deltombe, E<lt>fxdeltombe@gmail.com.E<gt>

=item Copyright (C) 2006, 2008, 2009, 2010, 2011, 2012 by Clement Oudot, E<lt>clem.oudot@gmail.comE<gt>

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
