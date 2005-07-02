package Lemonldap::NG::Handler::SharedConf;

use 5.008004;
use strict;
use warnings;

use Lemonldap::NG::Handler qw(:all);
use Cache::Cache qw($EXPIRES_NEVER);
use Apache::Constants qw(:common);
use Apache::Log;

our @ISA = qw(Lemonldap::NG::Handler);

our $VERSION    = '0.02';
our $numConf    = 0;
our $lastReload = 0;
our $reloadTime;

push( @{ $EXPORT_TAGS{$_} }, qw($reloadTime $lastReload) )
  foreach (qw(variables localStorage));

push @EXPORT_OK, qw($reloadTime $lastReload);

sub init {
    my $class = shift;
    $class->localInit(@_);
}

sub localInit($$) {
    my $class = shift;
    $reloadTime = $_[0]->{reloadTime} || 600;
    if ( $ENV{MOD_PERL} ) {

        # Update configuration for each new Apache's process
        my $tmp = sub { return $class->reload };
        Apache->push_handlers( PerlChildInitHandler => $tmp );
    }
    $class->SUPER::localInit(@_);

}

sub setConf {
    my ( $class, $args ) = @_;
    $numConf++;
    $args->{_n_conf} = $numConf;
    $refLocalStorage->set( "conf", $args, $EXPIRES_NEVER );
    $class->globalInit($args);
}

sub reload ($$) {
    my ($class) = shift;
    Apache->server->log->debug(
        __PACKAGE__ . ": child (re)load configuration" );
    my $args;
    return 0
      unless ( $refLocalStorage and $args = $refLocalStorage->get("conf") );
    $class->setconf($args) if $args->{_n_conf} != $numConf;
    $lastReload = time();
    1;
}

sub handler($$) {
    my ($class) = shift;
    if ( time() - $lastReload > $reloadTime ) {
        unless ( $class->reload ) {
            $_[0]->log_error( __PACKAGE__ . ": No configuration found" );
            return SERVER_ERROR;
        }
    }
    return $class->SUPER::handler(@_);
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Lemonldap::NG::Handler::SharedConf - Perl extension for adding dynamic
configuration to Lemonldap::NG::Handler

=head1 SYNOPSIS

  package My::Package;
  use Lemonldap::NG::Handler::SharedConf;
  @ISA = qw(Lemonldap::NG::Handler::SharedConf);

  __PACKAGE__->init ( {
    localStorage        => "Cache::DBFile",
    localStorageOptions => {},
    reloadTime          => 1200, # Default: 600
  } );

Change configuration :

  # In a childInitHandler method or another method called after Apache's fork
  __PACKAGE__->setConf ( {
      locationRules => { '^/.*$' => '$ou =~ /brh/'},
      globalStorage        => 'Apache::Session::MySQL',
      globalStorageOptions => {
        ...
      }
      portal               => 'https://portal/',
    }
  );

=head1 DESCRIPTION

Lemonldap is a simple Web-SSO based on Apache::Session modules. It simplifies
the build of a protected area with a few changes in the application (they just
have to read some headers for accounting).

It manages both authentication and authorization and provides headers for
accounting. So you can have a full AAA protection for your web space. There are
two ways to build a cross domain authentication:

=over

=item * Cross domain authentication itself (L<Lemonldap::Portal::Cda> I<(not yet implemented in Lemonldap::NG)>)

=item * "Liberty Alliance" (see L<Lemonldap::ServiceProvider> and
L<Lemonldap::IdentityProvider>)

=back

This library splits L<Lemonldap::NG::Handler> initialization into 2 phases: local
initialization and global configuration set. It can be used if you want to be
able to change the handler configuration without restarting Apache. See also
L<Lemonldap::Manager::Handler> to see an example of use.

=head2 SUBROUTINES

=head3 init

Like L<Lemonldap::NG::Handler>::init() but read only localStorage related options.
You may change default time between two configuration checks with the
C<reloadTime> parameter (default 600s).

=head3 setConf

Like L<Lemonldap::NG::Handler>::init() but does not read localStorage related
options. This method has to be used at PerlChildInitHandler stage else, the
server will return an error 500 (internal server error) until it obtains a
valid configuration.

=head2 EXPORT

Same as L<Lemonldap::NG::Handler>.

=head1 SEE ALSO

=over

=item * L<Lemonldap::NG::Handler>

=item * L<http://lemonldap.sourceforge.net/>

=back

=head1 AUTHOR

Xavier Guimard, E<lt>guimard@E<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Xavier Guimard

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.

Lemonldap was originaly written by Eric german who decided to publish him in
2003 under the terms of the GNU General Public License version 2.

=cut
