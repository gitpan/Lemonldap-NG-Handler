package Lemonldap::NG::Handler::SharedConf;

use strict;

use Lemonldap::NG::Handler::Simple qw(:all);
use Lemonldap::NG::Handler::Vhost;
use Lemonldap::NG::Manager::Conf;
use Cache::Cache qw($EXPIRES_NEVER);

our @ISA = qw(Lemonldap::NG::Handler::Vhost Lemonldap::NG::Handler::Simple);

our $VERSION    = '0.62';
our $cfgNum     = 0;
our $lastReload = 0;
our $reloadTime;
our $childLock = 0;
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
            threads::shared::share($childLock);
            threads::shared::share($lmConf);
            threads::shared::share($localConfig);
        };
    }
    *EXPORT_TAGS = *Lemonldap::NG::Handler::Simple::EXPORT_TAGS;
    *EXPORT_OK   = *Lemonldap::NG::Handler::Simple::EXPORT_OK;
    push(
        @{ $EXPORT_TAGS{$_} },
        qw($cfgNum $lastReload $reloadTime $childLock $lmConf $localConfig)
    ) foreach (qw(variables localStorage));
    push @EXPORT_OK,
      qw($cfgNum $lastReload $reloadTime $childLock $lmConf $localConfig);
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
    $cookieName =
         $localConfig->{cookieName}
      || $args->{cookieName}
      || 'lemonldap';
    $cookieSecured =
         $localConfig->{cookieSecured}
      || $args->{cookieSecured}
      || 0;
    $whatToTrace =
         $localConfig->{whatToTrace}
      || $args->{whatToTrace}
      || '$uid';
    $whatToTrace =~ s/\$//g;
    $https = $localConfig->{https} unless defined($https);
    $https = $args->{https}        unless defined($https);
    $https = 1                     unless defined($https);
    1;
}

sub localInit {
    my ( $class, $args ) = @_;
    $lmConf = Lemonldap::NG::Manager::Conf->new( $args->{configStorage} );
    $class->defaultValuesInit($args);
    $class->SUPER::localInit($args);
}

# Each $reloadTime, the Apache child verify if its configuration is the same
# as the configuration stored in the local storage.
sub run($$) {
    my ( $class, $r ) = @_;
    if ( time() - $lastReload > $reloadTime ) {
        unless ( $class->localConfUpdate($r) == OK ) {
            $class->lmLog( "$class: No configuration found", 'error' );
            return SERVER_ERROR;
        }
    }
    return $class->SUPER::run($r);
}

sub logout($$) {
    my ( $class, $r ) = @_;
    if ( time() - $lastReload > $reloadTime ) {
        unless ( $class->localConfUpdate($r) == OK ) {
            $class->lmLog( "$class: No configuration found", 'error' );
            return SERVER_ERROR;
        }
    }
    return $class->SUPER::logout($r);
}

sub confTest($$) {
    my ( $class, $args ) = @_;
    if ( $args->{_n_conf} ) {
        return 1 if ( $args->{_n_conf} == $cfgNum );
        if ($childLock) {
            $class->lmLog(
                "$class: child $$ detects configuration but local "
                  . 'storage is locked, continues to work with the old one',
                'debug'
            );
            return 1;
        }
        $childLock = 1;
        $class->globalInit($args);
        $childLock = 0;
        return 1;
    }
    return 0;
}

sub localConfUpdate($$) {
    my ( $class, $r ) = @_;
    my $args;
    return SERVER_ERROR unless ($refLocalStorage);
    unless ( $args = $refLocalStorage->get("conf") and $class->confTest($args) )
    {

        # TODO: LOCK
        #unless ( $class->confTest($args) ) {
        $class->globalConfUpdate($r);
        #}
        # TODO: UNLOCK;
    }
    $lastReload = time();
    OK;
}

sub globalConfUpdate {
    my $class = shift;
    my $tmp   = $class->getConf;

    # getConf can return an Apache constant in case of error
    return $tmp unless ( ref($tmp) );

    # Local arguments have a best precedence
    foreach ( keys %$tmp ) {
        $tmp->{$_} = $localConfig->{$_} if ( $localConfig->{$_} );
    }
    $class->setConf($tmp);
    OK;
}

sub setConf {
    my ( $class, $args ) = @_;
    $cfgNum++;
    $args->{_n_conf} = $cfgNum;
    $refLocalStorage->set( "conf", $args, $EXPIRES_NEVER );
    $class->lmLog( "$class: store configuration " . $args->{cfgNum}, 'debug' );
    $class->globalInit($args);
}

sub getConf {
    my $class = shift;
    my $tmp   = $lmConf->getConf;
    unless ( ref($tmp) ) {
        $class->lmLog( "$class: Unable to load configuration", 'error' );
        return SERVER_ERROR;
    }
    $class->lmLog( "$class: get configuration " . $tmp->{cfgNum}, 'debug' );
    return $tmp;
}

sub refresh($$) {
    my ( $class, $r ) = @_;
    $class->lmLog( "$class: request for configuration reload", 'notice' );
    $r->handler("perl-script");
    if ( MP() == 2 ) {
        if ( $class->globalConfUpdate($r) == OK ) {
            $r->push_handlers( 'PerlResponseHandler' =>
                  sub { my $r = shift; $r->content_type('text/plain'); OK } );
        }
        else {
            $r->push_handlers( 'PerlResponseHandler' => sub { SERVER_ERROR } );
        }
    }
    else {
        if ( $class->globalConfUpdate($r) == OK ) {
            $r->push_handlers(
                'PerlHandler' => sub { my $r = shift; $r->send_http_header; OK }
            );
        }
        else {
            $r->push_handlers( 'PerlHandler' => sub { SERVER_ERROR } );
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

=head3 getConf

Call Lemonldap::NG::Manager::Conf with the configStorage parameter.

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
