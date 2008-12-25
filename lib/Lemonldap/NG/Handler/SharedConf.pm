package Lemonldap::NG::Handler::SharedConf;

use strict;

use Lemonldap::NG::Handler::Simple qw(:all);
use Lemonldap::NG::Handler::Vhost;
use Lemonldap::NG::Common::Conf;
use Cache::Cache qw($EXPIRES_NEVER);

use base qw(Lemonldap::NG::Handler::Vhost Lemonldap::NG::Handler::Simple);

our $VERSION    = '0.7';
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
    *EXPORT_TAGS = *Lemonldap::NG::Handler::Simple::EXPORT_TAGS;
    *EXPORT_OK   = *Lemonldap::NG::Handler::Simple::EXPORT_OK;
    push(
        @{ $EXPORT_TAGS{$_} },
        qw($cfgNum $lastReload $reloadTime $lmConf $localConfig)
    ) foreach (qw(variables localStorage));
    push @EXPORT_OK, qw($cfgNum $lastReload $reloadTime $lmConf $localConfig);
}

# INIT PROCESS

# init is overloaded to call only localInit. globalInit is called later
sub init($$) {
    my ( $class, $args ) = @_;
    $reloadTime = $args->{reloadTime} || 600;
    $localConfig = $args;
    $class->localInit($args);
}

# defaultValuesInit : set default values for non-customized variables
sub defaultValuesInit {
    my ( $class, $args ) = @_;

    # Local configuration overrides global configuration
    my %h = ( %$args, %$localConfig );
    return $class->SUPER::defaultValuesInit( \%h );
}

sub localInit {
    my ( $class, $args ) = @_;
    die("$class : unable to build configuration : $Lemonldap::NG::Common::Conf::msg")
        unless($lmConf = Lemonldap::NG::Common::Conf->new( $args->{configStorage} ));

    # localStorage can be declared in configStorage or at the root or both
    foreach (qw(localStorage localStorageOptions)) {
        $args->{$_} ||= $args->{configStorage}->{$_} || $lmConf->{$_};
        $args->{configStorage}->{$_} ||= $args->{$_};
    }
    $class->defaultValuesInit($args);
    $class->SUPER::localInit($args);
}

# MAIN

# Each $reloadTime, the Apache child verify if its configuration is the same
# as the configuration stored in the local storage.
sub run($$) {
    my ( $class, $r ) = @_;
    if ( time() - $lastReload > $reloadTime ) {
        unless ( my $tmp = $class->testConf(1) == OK ) {
            $class->lmLog( "$class: No configuration found", 'error' );
            return $tmp;
        }
    }
    return $class->SUPER::run($r);
}

# CONFIGURATION UPDATE

sub testConf {
    my ( $class, $local ) = @_;
    my $conf = $lmConf->getConf( { local => $local } );
    unless ( ref($conf) ) {
        $class->lmLog( "$class: Unable to load configuration : $Lemonldap::NG::Common::Conf::msg", 'error' );
        return $cfgNum ? OK : SERVER_ERROR;
    }
    if ( $cfgNum != $conf->{cfgNum} ) {
        $class->lmLog( "$class: get configuration ($Lemonldap::NG::Common::Conf::msg)",
            'debug' );
    $lastReload = time();
        return $class->setConf($conf);
    }
    $class->lmLog( "$class: configuration is up to date", 'debug' );
    OK;
}

sub setConf {
    my ( $class, $conf ) = @_;

    # Local configuration overrides global configuration
    $cfgNum = $conf->{cfgNum};
    $conf->{$_} = $localConfig->{$_} foreach ( keys %$localConfig );
    $class->globalInit($conf);
    OK;
}

# RELOAD SYSTEM

*reload = *refresh;

sub refresh($$) {
    my ( $class, $r ) = @_;
    $class->lmLog( "$class: request for configuration reload", 'notice' );
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

Lemonldap::NG::Handler::SharedConf - Perl extension to use dynamic
configuration provide by Lemonldap::NG::Manager.

=head1 SYNOPSIS

  package My::Package;
  use Lemonldap::NG::Handler::SharedConf;
  @ISA = qw(Lemonldap::NG::Handler::SharedConf);
  __PACKAGE__->init ( {
    localStorage        => "Cache::FileCache",
    localStorageOptions => {
        'namespace' => 'MyNamespace',
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

This library inherit from L<Lemonldap::NG::Handler::Simple> to build a
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

Like L<Lemonldap::NG::Handler::Simple>::init() but read only localStorage
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
