package Lemonldap::NG::Handler::SharedConf::DBI;

use strict;

use UNIVERSAL qw(can);
use Apache::Constants qw(:common :response);
use Lemonldap::NG::Handler::Vhost;
use Lemonldap::NG::Handler::SharedConf qw(:all);
use DBI;
use Storable qw(thaw);
use MIME::Base64;

our $VERSION = '0.1';

our @ISA = qw(Lemonldap::NG::Handler::Vhosts Lemonldap::NG::Handler::SharedConf);

*EXPORT_TAGS = *Lemonldap::NG::Handler::SharedConf::EXPORT_TAGS;
*EXPORT_OK   = *Lemonldap::NG::Handler::SharedConf::EXPORT_OK;

our ( $dbiChain, $dbiUser, $dbiPassword );

my ( $dbh, $cfgNum ) = ( undef, 0 );

sub localInit($$) {
    my($class,$args) = @_;
    $dbiChain = $args->{dbiChain} or die "No dbiChain found";
    $dbiUser = $args->{dbiUser} or Apache->server->log->warn("No dbiUser found");
    $dbiPassword = $args->{dbiPassword} or Apache->server->log->warn("No dbiPassword found");
    $class->SUPER::localInit($args);
}

sub getConf {
    my $class = shift;
    $dbh = DBI->connect_cached( $dbiChain, $dbiUser, $dbiPassword );
    my $sth = $dbh->prepare("SELECT max(cfgNum) from config");
    $sth->execute();
    my @row = $sth->fetchrow_array;
    unless ( $row[0] ) {
        Apache->server->log->error( __PACKAGE__ . ": getConf: No configuration found" );
        return undef;
    }
    Apache->server->log->notice( __PACKAGE__
          . ": configuration found: "
          . $row[0]
          . ", previous was: $cfgNum" );
    $cfgNum = $row[0];
    $sth =
      $dbh->prepare( "select locationRules, globalStorage, "
          . "globalStorageOptions, exportedHeaders, portal "
          . "from config where(cfgNum=$cfgNum)" );
    $sth->execute();
    @row = $sth->fetchrow_array;
    return {
        locationRules        => thaw( decode_base64( $row[0] ) ),
        globalStorage        => $row[1],
        globalStorageOptions => thaw( decode_base64( $row[2] ) ),
        exportedHeaders      => thaw( decode_base64( $row[3] ) ),
        portal               => $row[4],
    };
}

1;
__END__

=head1 NAME

Lemonldap::NG::Handler::SharedConf::DBI - Module to share Lemonldap::NG
configuration using DBI.

=head1 SYNOPSIS

  package My::Package;
  use Lemonldap::NG::Handler::SharedConf::DBI;
  @ISA = qw(Lemonldap::NG::Handler::SharedConf::DBI);
  
  __PACKAGE__->init ( {
    localStorage        => "Cache::DBFile",
    localStorageOptions => {},
    reloadTime          => 1200, # Default: 600
    dbiChain            => "DBI:mysql:database=$database;host=$hostname;port=$port",
    dbiUser             => "lemonldap",
    dbiassword          => "password",
  } );

Call your package in /apache-dir/conf/httpd.conf :

  PerlRequire MyFile
  # TOTAL PROTECTION
  PerlInitHandler My::Package
  # OR SELECTED AREA
  <Location /protected-area>
    PerlInitHandler My::Package
  </Location>

The configuration is loaded only at Apache start. Create an URI to force
configuration reload, so you don't need to restart Apache at each change :

  # /apache-dir/conf/httpd.conf
  <Location /location/that/I/ve/choosed>
    Order deny,allow
    Deny from all
    Allow from my.manager.com
    PerlInitHandler My::Package::refresh
  </Location>

=head1 DESCRIPTION

Lemonldap::NG is a simple Web-SSO based on Apache::Session modules. It
simplifies the build of a protected area with a few changes in the application
(they just have to read some headers for accounting).

It manages both authentication and authorization and provides headers for
accounting. So you can have a full AAA protection for your web space.

This library inherit from L<Lemonldap::NG::Handler::SharedConf> to build a
complete SSO Handler System: a central database contains the policy of your
domain. People that want to access to a protected applications are redirected
to the portal that run L<Lemonldap::NG::Portal::SharedConf::DBI>. After reading
configuration from the database and authenticating the user, it stores a key
word for each application the user is granted to access to.
Then the user is redirected to the application he wanted to access and the
Apache handler build with L<Lemonldap::NG::Handler::SharedConf::DBI> has just
to verify that the keyword corresponding to the protected area is stored in
the database.

=head2 EXPORT

Same as L<Lemonldap::NG::Handler::SharedConf>.

=head1 OPERATION

Each new Apache child checks if there's a configuration stored in the local
store. If not, it calls getConf to get one and store it in the local store by
calling setconf.

Every 600 seconds (or $reload seconds), each Apache child checks if the local
stored configuration has changed and reload it if it has.

=head1 DIAGRAM OF THE CONFIGURATION DATABASE

  CREATE TABLE lemonconfig (
    cfgNum int,
    locationRules text,
    globalStorage text,
    globalStorageOptions text,
    exportedHeaders text,
    portal text,
    PRIMARY KEY (cfgNum)
    );

=over

=item * cfgNum indicates the number of each configuration. Lemonldap::NG use
always the highest.

=item * locationRules, globalStorageOptions and exportedHeaders are hash
references serialized by Storage::freeze. See L<Lemonldap::NG::Manager> for
more about this.

=item * portal indicates the URL of the Lemonldap portal used to authenticate
users.

=item * globalStorage indicates the Apache::Session::* module used to store
sessions.

=back

=head1 SEE ALSO

L<Lemonldap::Manager>, L<Lemonldap::NG::Portal::SharedConf::DBI>,
L<Lemonldap::NG::Handler>, L<Lemonldap::NG::Handler::SharedConf>

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

