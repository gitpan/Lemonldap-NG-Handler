package Lemonldap::NG::Handler::SharedConf;

use 5.008004;
use strict;
use warnings;

use Lemonldap::NG::Handler qw(:all);
use Lemonldap::NG::Handler::Vhost;
use Cache::Cache qw($EXPIRES_NEVER);

our @ISA = qw(Lemonldap::NG::Handler::Vhost Lemonldap::NG::Handler);

our $VERSION    = '0.2';
our $cfgNum    = 0;
our $lastReload = 0;
our $reloadTime;
our $childLock = 0;

*EXPORT_TAGS = *Lemonldap::NG::Handler::EXPORT_TAGS;
*EXPORT_OK   = *Lemonldap::NG::Handler::EXPORT_OK;

BEGIN {
    if (MP() == 2) {
	Apache2::compat->import();
	threads::shared::share($childLock)
    }
}

push( @{ $EXPORT_TAGS{$_} }, qw($reloadTime $lastReload) )
  foreach (qw(variables localStorage));

push @EXPORT_OK, qw($reloadTime $lastReload);

# INIT PROCESS

# init is overloaded to call only localInit. globalInit is called later
sub init($$) {
    my($class,$args) = @_;
    $reloadTime = $args->{reloadTime} || 600;
    $class->localInit($args);
}

# Each $reloadTime, the Apache child verify if its configuration is the same
# as the configuration stored in the local storage.
sub run($$) {
    my ($class, $r) = @_;
    if ( time() - $lastReload > $reloadTime ) {
        unless ( $class->localConfUpdate($r) == OK ) {
            $class->lmLog( "$class: No configuration found", 'error' );
            return SERVER_ERROR;
        }
    }
    return $class->SUPER::run($r);
}

sub confTest($$) {
    my ( $class, $args ) = @_;
    if ( $args->{_n_conf} ) {
        return 1 if($args->{_n_conf} == $cfgNum or $childLock);
	$childLock = 1;
        $class->globalInit($args);
	$childLock = 0;
        return 1;
    }
    return 0;
}

sub localConfUpdate($$) {
    my ($class,$r) = @_;
    my $args;
    return SERVER_ERROR unless ( $refLocalStorage );
    unless ( $args = $refLocalStorage->get("conf") and $class->confTest($args) ) {

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
    return $tmp unless (%$tmp);
    $class->setConf($tmp);
    OK;
}

sub setConf {
    my ( $class, $args ) = @_;
    $cfgNum++;
    $args->{_n_conf} = $cfgNum;
    $refLocalStorage->set( "conf", $args, $EXPIRES_NEVER );
    $class->globalInit($args);
}

sub getConf {

    # MUST BE OVERLOADED
    return {};
}

sub refresh($$) {
    my ( $class, $r ) = @_;
    $class->lmLog( "$class: request for configuration reload", 'info' );
    $r->handler ( "perl-script" );
    if ( $class->globalConfUpdate($r) == OK ) {
        $r->push_handlers ( PerlHandler => sub { OK } );
    }
    else {
        $r->push_handlers ( PerlHandler => sub { SERVER_ERROR } );
    }
    return DONE;
}

1;
__END__

=head1 NAME

Lemonldap::NG::Handler::SharedConf - Perl extension for adding dynamic
configuration to Lemonldap::NG::Handler. To use for inheritance.

See L<Lemonldap::NG::Handler::SharedConf::DBI> for a complete example.

=head1 SYNOPSIS

  package My::Package;
  use Lemonldap::NG::Handler::SharedConf;
  @ISA = qw(Lemonldap::NG::Handler::SharedConf);
  
  sub getConf {
    # Write here your configuration download system
    # It has to return a hash reference containing
    # global configuration variables:
    # {
    #  locationRules => { '^/.*$' => '$ou =~ /brh/'},
    #  globalStorage        => 'Apache::Session::MySQL',
    #  globalStorageOptions => {
    #    ...
    #  }
    #  portal               => 'https://portal/',
    # }
    # See L<Lemonldap::NG::Handler> for more
  }
  
  __PACKAGE__->init ( {
    localStorage        => "Cache::DBFile",
    localStorageOptions => {},
    reloadTime          => 1200, # Default: 600
  } );

The configuration is loaded only at Apache start. Create an URI to force
configuration reload, so you don't need to restart Apache at each change :

  # <apache>/conf/httpd.conf
  <Location /location/that/I/ve/choosed>
    Order deny,allow
    Deny from all
    Allow from my.manager.com
    PerlInitHandler My::Package->refresh
  </Location>

=head1 DESCRIPTION

Lemonldap is a simple Web-SSO based on Apache::Session modules. It simplifies
the build of a protected area with a few changes in the application (they just
have to read some headers for accounting).

It manages both authentication and authorization and provides headers for
accounting. So you can have a full AAA protection for your web space.

This library splits L<Lemonldap::NG::Handler> initialization into 2 phases:
local initialization and global configuration set. It can be used if you want
to write a module that can change its global configuration without restarting
Apache.

=head2 OVERLOADED SUBROUTINES

=head3 init

Like L<Lemonldap::NG::Handler>::init() but read only localStorage related options.
You may change default time between two configuration checks with the
C<reloadTime> parameter (default 600s).

=head2 SUBROUTINE TO WRITE

=head3 getConf

Does nothing by default. You've to overload it to write your own configuration
download system.

=head2 EXPORT

Same as L<Lemonldap::NG::Handler>.

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

L<Lemonldap::NG::Handler>, L<Lemonldap::NG::Handler::SharedConf::DBI>

=back

=head1 AUTHOR

Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Xavier Guimard E<lt>x.guimard@free.frE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.

Lemonldap was originaly written by Eric german who decided to publish him in
2003 under the terms of the GNU General Public License version 2.
Lemonldap::NG is a complete rewrite of Lemonldap and is able to have different
policies in a same Apache virtual host.

=cut
