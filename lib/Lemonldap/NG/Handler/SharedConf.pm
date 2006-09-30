package Lemonldap::NG::Handler::SharedConf;

use 5.008004;
use strict;
use warnings;

use Lemonldap::NG::Handler qw(:all);
use Cache::Cache qw($EXPIRES_NEVER);
use Apache::Constants qw(:common);
use Apache::Log;

our @ISA = qw(Lemonldap::NG::Handler);

our $VERSION    = '0.05';
our $numConf    = 0;
our $lastReload = 0;
our $reloadTime;

push( @{ $EXPORT_TAGS{$_} }, qw($reloadTime $lastReload) )
  foreach (qw(variables localStorage));

push @EXPORT_OK, qw($reloadTime $lastReload);

# INIT PROCESS

# init is overloaded to call only localInit. globalInit is called later
sub init {
    my $class = shift;
    $class->localInit(@_);
}

# localInit is overloaded to call confVerif() on Apache child initialization
sub localInit($$) {
    my $class = shift;
    $reloadTime = $_[0]->{reloadTime} || 600;
    if ( $ENV{MOD_PERL} ) {

        # Update configuration for each new Apache's process
        my $tmp = sub { return $class->confVerif };
        Apache->push_handlers( PerlChildInitHandler => $tmp );
    }
    $class->SUPER::localInit(@_);
}

# Each $reloadTime, the Apache child verify if its configuration is the same
# as the configuration stored in the local storage.
sub handler($$) {
    my ($class) = shift;
    if ( time() - $lastReload > $reloadTime ) {
        unless ( $class->confVerif == OK ) {
            $_[0]->log_error( __PACKAGE__ . ": No configuration found" );
            return SERVER_ERROR;
        }
    }
    return $class->SUPER::handler(@_);
}

sub confTest {
    my ( $class, $args ) = @_;
    if ( $args->{_n_conf} ) {
        return 1 if $args->{_n_conf} == $numConf;
        $class->globalInit($args);
        return 1;
    }
    return 0;
}

sub confVerif {
    my $class = shift;
    my ( $r, $args );
    return SERVER_ERROR
      unless ( $refLocalStorage and $args = $refLocalStorage->get("conf") );
    unless ( $class->confTest($args) ) {

        # TODO: LOCK
        #unless ( $class->confTest($args) ) {
        $class->confUpdate;

        #}
        # TODO: UNLOCK;
    }
    OK;
}

sub confUpdate {
    my $class = shift;
    my $tmp   = $class->getConf;

    # getConf can return an Apache constant in case of error
    return $tmp unless (%$tmp);
    $class->setConf($tmp);
    OK;
}

sub setConf {
    my ( $class, $args ) = @_;
    $numConf++;
    $args->{_n_conf} = $numConf;
    $refLocalStorage->set( "conf", $args, $EXPIRES_NEVER );
    $class->globalInit($args);
}

sub getConf {

    # MUST BE OVERLOADED
    return {};
}

sub refresh($$) {
    my ( $class, $r ) = @_;
    Apache->server->log->debug(
        __PACKAGE__ . ": request for configuration reload" );
    $class->confUpdate;
    DONE;
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
    PerlInitHandler My::Package::refresh
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
