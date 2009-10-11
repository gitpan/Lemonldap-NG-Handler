## @file
# Alias for Lemonldap::NG::Handler::SharedConf

## @class
# Alias for Lemonldap::NG::Handler::SharedConf
package Lemonldap::NG::Handler;

our $VERSION = "0.92";
use Lemonldap::NG::Handler::SharedConf;
use base qw(Lemonldap::NG::Handler::SharedConf);

1;

__END__

=pod

=head1 NAME

Lemonldap::NG::Handler - The Apache protection module part of
Lemonldap::NG Web-SSO system.

=head1 SYNOPSIS

=head2 Create your Apache module

Create your own package (example using a central configuration database):

  package My::Package;
  use Lemonldap::NG::Handler::SharedConf;
  @ISA = qw(Lemonldap::NG::Handler::SharedConf);
  
  __PACKAGE__->init ( {
    # Local storage used for sessions and configuration
    localStorage        => "Cache::DBFile",
    localStorageOptions => {...},
    # How to get my configuration
    configStorage       => {
        type                => "DBI",
        dbiChain            => "DBI:mysql:database=lemondb;host=$hostname",
        dbiUser             => "lemonldap",
        dbiPassword         => "password",
    }
    # Uncomment this to activate status module
    # status                => 1,
  } );

=head2 Configure Apache

Call your package in /apache-dir/conf/httpd.conf:

  # Load your package
  PerlRequire /My/File
  # TOTAL PROTECTION
  PerlHeaderParserHandler My::Package
  # OR SELECTED AREA
  <Location /protected-area>
    PerlHeaderParserHandler My::Package
  </Location>

The configuration is loaded only at Apache start. Create an URI to force
configuration reload, so you don't need to restart Apache at each change:

  # /apache-dir/conf/httpd.conf
  <Location /location/that/I/ve/choosed>
    Order deny,allow
    Deny from all
    Allow from my.manager.com
    PerlHeaderParserHandler My::Package->refresh
  </Location>
  
You can also unprotect an URI

  <Files "*.gif">
    PerlHeaderParserHandler My::Package->unprotect
  </Files>

To display the status page, add something like this :

  <Location /status>
    Order deny,allow
    Allow from 10.1.1.0/24
    Deny from all
    PerlHeaderParserHandler My::Package->status
  </Location>

If your application has a "logout" URL, you can configure it directly in Apache
configuration file (or in the manager interface). THIS IS DEPRECATED, use the
manager :

  <Location /logout>
    PerlHeaderParserHandler My::Package->logout
  </Location>

=head1 DESCRIPTION

Lemonldap::NG is a modular Web-SSO based on Apache::Session modules. It
simplifies the build of a protected area with a few changes in the application.

It manages both authentication and authorization and provides headers for
accounting. So you can have a full AAA protection for your web space as
described below.

The Apache module part works both with Apache 1.3.x and 2.x ie mod_perl 1 and 2
but B<not with mod_perl 1.99>.

=head2 Authentication, Authorization, Accounting

=head3 B<Authentication>

If a user isn't authenticated and attemps to connect to an area protected by a
Lemonldap::NG compatible handler, he is redirected to a portal. The portal
authenticates user with a ldap bind by default, but you can also use another
authentication sheme like using x509 user certificates (see
L<Lemonldap::NG::Portal::AuthSSL> for more).

Lemonldap::NG use session cookies generated by L<Apache::Session> so as secure
as a 128-bit random cookie. You may use the C<securedCookie> options of
L<Lemonldap::NG::Portal> to avoid session hijacking.

You have to manage life of sessions by yourself since Lemonldap::NG knows
nothing about the L<Apache::Session> module you've choosed, but it's very easy
using a simple cron script because L<Lemonldap::NG::Portal> stores the start
time in the C<_utime> field.
By default, a session stay 10 minutes in the local storage, so in the worth
case, a user is authorized 10 minutes after he lost his rights.

=head3 B<Authorization>

Authorization is controled only by handlers because the portal knows nothing
about the way the user will choose. When configuring your Web-SSO, you have to:

=over

=item * choose the ldap attributes you want to use to manage accounting and
authorization (see C<exportedHeaders> parameter in L<Lemonldap::NG::Portal>
documentation).

=item * create Perl expressions to define user groups (using ldap attributes)

=item * create an array foreach virtual host associating URI regular
expressions and Perl expressions to use to grant access.

=back

=head4 Example (See L<Lemonldap::NG::Manager> to see how configuration is
stored)

Exported variables (values will be stored in session database by
L<Lemonldap::NG::Portal>):

  exportedVars => {
      cn            => "cn",
      departmentUID => "departmentUID",
      login         => "uid",
  },

User groups (values will be stored in session database by
L<Lemonldap::NG::Portal>):

  groups => {
      group1 => '{ $departmentUID eq "unit1" or $login = "xavier.guimard" }',
      ...
  },

Area protection:

  locationRules => {
      www1.domain.com => {
          '^/protected/.*$' => '$groups =~ /\bgroup1\b/',
          default           => 'accept',
      },
      www2.domain.com => {
          '^/site/.*$' => '$uid eq "xavier.guimard" or $groups =~ /\bgroup2\b/',
          '^/(js|css)' => 'accept',
          default      => 'deny',
      },
  },

=head4 Performance

You can use Perl expressions as complicated as you want and you can use all
the exported LDAP attributes (and create your own attributes: with 'macros'
mechanism. See L<Lemonldap::NG::Manager>) in groups evaluations, area
protections or custom HTTP headers (you just have to call them with a "$").

You have to be careful when choosing your expressions:

=over

=item * C<groups> and C<macros> are evaluated each time a user is redirected to
the portal,

=item * C<locationRules> and C<exportedheaders> are evaluated for each request
on a protected area.

=back

It is also recommanded to use the C<groups> mechanism to avoid having to
evaluate a long expression at each HTTP request:

  locationRules => {
      www1.domain.com => {
          '^/protected/.*$' => '$groups =~ /\bgroup1\b/',
      },
  },

You can also use LDAP filters, or Perl expression or mixed expressions in
C<groups> parameter. Perl expressions has to be enclosed with C<{}>:

=over

=item * C<group1 =E<gt> '(|(uid=xavier.guimard)(ou=unit1))'>

=item * C<group1 =E<gt> '{$uid eq "xavier.guimard" or $ou eq "unit1"}'>

=item * C<group1 =E<gt> '(|(uid=xavier.guimard){$ou eq "unit1"})'>

=back

It is also recommanded to use Perl expressions to avoid requiering the LDAP
server more than 2 times per authentication.

=head3 B<Accounting>

=head4 I<Logging portal access>

L<Lemonldap::NG::Portal> doesn't log anything by default, but it's easy to overload
C<log> method for normal portal access or using C<error> method to know what
was wrong if C<process> method has failed.

=head4 I<Logging application access>

Because an handler knows nothing about the protected application, it can't do
more than logging URL. As Apache does this fine, L<Lemonldap::NG::Handler>
gives it the name to used in logs. The C<whatToTrace> parameters indicates
which variable Apache has to use (C<$uid> by default).

The real accounting has to be done by the application itself which knows the
result of SQL transaction for example.

Lemonldap::NG can export HTTP headers either using a proxy or protecting
directly the application. By default, the C<Auth-User> field is used but you
can change it using the C<exportedHeaders> parameters (stored in the
configuration database). This parameters contains an associative array per
virtual host:

=over

=item * B<keys> are the names of the choosen headers

=item * B<values> are Perl expressions where you can use user datas stored in
the global store by calling them C<$E<lt>varnameE<gt>>.

=back

Example:

  exportedHeaders => {
      www1.domain.com => {
          'Auth-User' => '$uid',
          'Unit'      => '$ou',
      },
      www2.domain.com => {
          'Authorization' => '"Basic ".encode_base64($employeeNumber.":dummy")',
          'Remote-IP'     => '$ip',
      },
  }

=head2 Session storage systems

Lemonldap::NG use 3 levels of cache for authenticated users:

=over

=item * an Apache::Session::* module choosed with the C<globalStorage>
parameter (completed with C<globalStorageOptions>) and used by
L<lemonldap::NG::Portal> to store authenticated user parameters,

=item * a L<Cache::Cache> module choosed with the C<localStorage> parameter
(completed with C<localStorageOptions>) and used to share authenticated users
between Apache's threads or processus and of course between virtual hosts,

=item * Lemonldap::NG::Handler variables: if the same user use the same thread
or processus a second time, no request are needed to grant or refuse access.
This is very efficient with HTTP/1.1 Keep-Alive system.

=back

So the number of request to the central storage is limited to 1 per active
user each 10 minutes.

Lemonldap::NG is very fast, but you can increase performance using a
L<Cache::Cache> module that does not use disk access.

=head2 Logout system

Lemonldap::NG provides a single logout system: you can use it by adding a link
to the portal with "logout=1" parameter in the portal (See
L<Lemonldap::NG::Portal>) and/or by configuring handler to intercept some URL
(See Sinopsys). The logout system:

=over

=item * delete session in the global session storage,

=item * replace Lemonldap::NG cookie by '',

=item * delete handler caches only if logout action was started from a
protected application and only in the current Apache server. So in other
servers, session is still in cache for 10 minutes maximum if the user was
connected on it in the last 10 minutes.

=back

You can also configure rules in the Manager interface to intercept logout URL.
See L<Lemonldap::NG::Manager> and L<Lemonldap::NG::Handler> for more.

=head1 USING LEMONLDAP::NG::HANDLER FOR DEVELOPMENT

Lemonldap::NG::Handler provides different modules:

=over

=item * L<Lemonldap::NG::Handler::Simple>: base module. It can be used
directly to protect a single host.

=item * L<Lemonldap::NG::Handler::Vhost>: module used to managed virtual hosts.

=item * L<Lemonldap::NG::Handler::SharedConf>: with this module, the
configuration can be centralized. Inherits from
L<Lemonldap::NG::Handler::Vhost> and L<Lemonldap::NG::Handler::Simple>.

=item * L<Lemonldap::NG::Handler::CGI>: if you have only a few Perl CGI to
protect, you can use this module in your CGI instead of protecting it under
L<Lemonldap::NG::Handler::SharedConf>.

=item * L<Lemonldap::NG::Handler::Proxy>: this module isn't used to manage
security but is written to create a reverse-proxy without using mod_proxy. In
some case, mod_proxy does not manage correctly some redirections, that is why
this module still exists.

=back

All those modules are compatible both with Apache and mod_perl version 1 and 2,
but NOT with mod_perl 1.99. If you use Linux distributions like Debian Sarge
who provide mod_perl 1.99 for Apache2, you have to use Apache-1.3 or to
download a mod_perl2 backport.

=head1 SEE ALSO

L<Lemonldap::NG::Handler::SharedConf>,
L<Lemonldap::NG::Portal>, L<Lemonldap::NG::Manager>,
L<http://wiki.lemonldap.objectweb.org/xwiki/bin/view/NG/Presentation>

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

Lemonldap was originaly written by Eric German who decided to publish him in
2003 under the terms of the GNU General Public License version 2.
Lemonldap::NG is a complete rewrite of Lemonldap and is able to have different
policies in a same Apache virtual host.

=cut
