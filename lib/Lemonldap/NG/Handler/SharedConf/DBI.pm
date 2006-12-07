package Lemonldap::NG::Handler::SharedConf::DBI;

use strict;

use UNIVERSAL qw(can);
use Lemonldap::NG::Handler::SharedConf qw(:all);
use DBI;
use Storable qw(thaw);
use MIME::Base64;

BEGIN {
    if ( MP() == 2 ) {
        Apache2::compat->import();
    }
}

our $VERSION = '0.4';

our @ISA = qw(Lemonldap::NG::Handler::SharedConf);

*EXPORT_TAGS = *Lemonldap::NG::Handler::SharedConf::EXPORT_TAGS;
*EXPORT_OK   = *Lemonldap::NG::Handler::SharedConf::EXPORT_OK;

our ( $dbiChain, $dbiUser, $dbiPassword );

my ( $dbh, $cfgNum ) = ( undef, 0 );

sub localInit($$) {
    my ( $class, $args ) = @_;
    $dbiChain    = $args->{dbiChain}    or die "No dbiChain found";
    $dbiUser     = $args->{dbiUser}     or $class->lmLog( "No dbiUser found", 'warn' );
    $dbiPassword = $args->{dbiPassword} or $class->lmLog( "No dbiPassword found", 'warn' );
    $class->SUPER::localInit($args);
}

sub getConf {
    my $class = shift;
    $dbh = DBI->connect_cached( $dbiChain, $dbiUser, $dbiPassword );
    my $sth = $dbh->prepare("SELECT max(cfgNum) from lmConfig");
    $sth->execute();
    my @row = $sth->fetchrow_array;
    unless ( $row[0] ) {
        $class->lmLog( "$class: getConf: No configuration found", 'error' );
        return undef;
    }
    $class->lmLog( "$class: configuration found: " . $row[0] . ", previous was: $cfgNum", 'notice' );
    $cfgNum = $row[0];
    $sth =
      $dbh->prepare( "select locationRules, globalStorage, "
          . "globalStorageOptions, exportedHeaders, portal "
          . "from lmConfig where(cfgNum=$cfgNum)" );
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
    localStorage        => "Cache::FileCache",
    localStorageOptions => {
        'namespace' => 'MyNamespace',
        'default_expires_in' => 600,
      },
    reloadTime          => 1200, # Default: 600
    dbiChain            => "DBI:mysql:database=$database;host=$hostname;port=$port",
    dbiUser             => "lemonldap",
    dbiPassword          => "password",
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
    PerlInitHandler My::Package->refresh
  </Location>

=head1 DESCRIPTION

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
store. If not, it calls C<getConf> to get one and store it in the local store by
calling setconf.

Every 600 seconds (or $reload seconds), each Apache child checks if the local
stored configuration has changed and reload it if it has.

=head1 SCHEME OF THE CONFIGURATION DATABASE

  CREATE TABLE lmConfig (
    cfgNum int,
    locationRules text,
    globalStorage text,
    globalStorageOptions text,
    exportedHeaders text,
    portal text,
    domain text,
    ldapServer text,
    ldapPort int,
    ldapBase text,
    securedCookie int,
    cookiename text,
    authentication text,
    exportedvars text,
    managerDn text,
    managerPassword text,
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

=cut

