##@file
# Cross-domain mechanism for handler

##@class
# Cross-domain mechanism for handler
package Lemonldap::NG::Handler::CDA;

use strict;

use Lemonldap::NG::Handler::SharedConf qw(:all);

our $VERSION = '1.2.2';

use base qw(Lemonldap::NG::Handler::SharedConf);

## @rmethod int run(Apache2::RequestRec apacheRequest)
# overload run subroutine to implement cross-domain mechanism.
# @param $apacheRequest
# @return Apache constant
sub run ($$) {
    my $class;
    ( $class, $apacheRequest ) = splice @_;
    $cda = 1;
    return $class->SUPER::run($apacheRequest);
}

1;
__END__

=head1 NAME

=encoding utf8

Lemonldap::NG::Handler::CDA - Module to use Lemonldap::NG::Handler
mechanisms with Cross-Domain-Authentication.

=head1 SYNOPSIS

New usage:

  package My::Package;
  use Lemonldap::NG::Handler;
  @ISA = qw(Lemonldap::NG::Handler);
  __PACKAGE__->init ( {
    cda                 => 1,
    localStorage        => "Cache::FileCache",
    localStorageOptions => {
        'namespace' => 'lemonldap-ng',
        'default_expires_in' => 600,
      },
    reloadTime          => 1200, # Default: 600
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

This library inherit from L<Lemonldap::NG::Handler::SharedConf> and add the
capability to control users that are authenticated with a
L<Lemonldap::NG::Portal::CDA> CGI in another domain.

=head2 EXPORT

Same as L<Lemonldap::NG::Handler::SharedConf>.

=head1 SEE ALSO

L<Lemonldap::NG::Manager>, L<Lemonldap::NG::Handler>,
L<Lemonldap::NG::Handler::SharedConf>,
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

=item Copyright (C) 2007, 2008, 2009, 2010, 2012 by Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=item Copyright (C) 2012 by Fran�ois-Xavier Deltombe, E<lt>fxdeltombe@gmail.com.E<gt>

=item Copyright (C) 2010, 2012 by Clement Oudot, E<lt>clem.oudot@gmail.comE<gt>

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

