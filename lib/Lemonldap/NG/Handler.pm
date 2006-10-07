package Lemonldap::NG::Handler;

use 5.008004;
use strict;

use Apache;
use Apache::Log;
use Apache::Constants qw(:common :response);
use MIME::Base64;
use Exporter 'import';

our $VERSION = '0.11';

our %EXPORT_TAGS = (
    localStorage => [
        qw(
          $localStorage $localStorageOptions $refLocalStorage
          )
    ],
    globalStorage => [
        qw(
          $globalStorage $globalStorageOptions
          )
    ],
    locationRules => [
        qw(
          $locationCondition $defaultCondition $locationCount
          $locationRegexp $apacheRequest $datas
          )
    ],
    import => [
        qw(
          import @EXPORT_OK @EXPORT %EXPORT_TAGS
          )
    ],
    headers => [
        qw(
          $forgeHeaders
          )
    ],
    traces => [
        qw(
          $whatToTrace
          )
    ],
);

our @EXPORT_OK = ();
push( @EXPORT_OK, @{ $EXPORT_TAGS{$_} } ) foreach (
    qw(
    localStorage globalStorage locationRules import headers traces
    )
);
$EXPORT_TAGS{all} = \@EXPORT_OK;

our @EXPORT = ();

# Shared variables
our (
    $locationRegexp,      $locationCondition,    $defaultCondition,
    $forgeHeaders,        $apacheRequest,        $locationCount,
    $cookieName,          $portal,               $datas,
    $globalStorage,       $globalStorageOptions, $localStorage,
    $localStorageOptions, $whatToTrace,          $https,
    $refLocalStorage,
);

##############################
# Initialization subroutines #
##############################

# init() : by default, it calls localInit and globalInit, but with
#          a shared configuration, init() is overloaded to call only
#          localInit; globalInit is called later when the configuration
#          is loaded.
sub init($$) {
    my $class = shift;
    $class->localInit(@_);
    $class->globalInit(@_);
}

# Local storage initialization
sub localInit($$) {
    my ( $class, $args ) = @_;
    if ( $localStorage = $args->{localStorage} ) {
        $localStorageOptions = $args->{localStorageOptions};
        $localStorageOptions->{namespace}          ||= "lemonldap";
        $localStorageOptions->{default_expires_in} ||= 600;

        eval "use $localStorage;";
        die("Unable to load $localStorage") if ($@);
	# At each Apache (re)start, we've to clear the cache to avoid living
	# with old datas
	eval '$refLocalStorage = new '
	  . $localStorage
	  . '($localStorageOptions);';
	if ( defined $refLocalStorage ) {
	    $refLocalStorage->clear();
	}
	else {
	    Apache->server->log->error("Unable to clear local cache: $@");
	}
        # We don't initialise local storage in the "init" subroutine because it can
        # be used at the starting of Apache and so with the "root" privileges. Local
        # Storage is also initialized just after Apache's fork and privilege lost.
	no strict;
	Apache->push_handlers( PerlChildInitHandler => sub { return $class->initLocalStorage(@_); } );
    
        # Local storage is cleaned after giving the content of the page to increase
        # performances.
        Apache->push_handlers( PerlCleanupHandler => sub { return $class->cleanLocalStorage(@_); } );
    }
}

# Global initialization process :
sub globalInit {
    my $class = shift;
    $class->locationRulesInit(@_);
    $class->defaultValuesInit(@_);
    $class->portalInit(@_);
    $class->globalStorageInit(@_);
    $class->forgeHeadersInit(@_);
}

# locationRulesInit : used to pre-compile rules :
#   - rules are stored in a hash containing regexp=>test expressions where :
#       - regexp is used to test URIs
#       - test contains an expression used to grant the user

sub locationRulesInit {
    my ( $class, $args ) = @_;
    $locationCount = 0;

    # Pre compilation : both regexp and conditions
    foreach ( keys %{ $args->{locationRules} } ) {
        if ( $_ eq 'default' ) {
            $defaultCondition =
              $class->conditionSub( $args->{locationRules}->{$_} );
        }
        else {
            $locationCondition->[$locationCount] =
              $class->conditionSub( $args->{locationRules}->{$_} );
            $locationRegexp->[$locationCount] = qr/$_/;
            $locationCount++;
        }
    }

    # Default police: all authenticated users are accepted
    $defaultCondition = $class->conditionSub('accept')
      unless ($defaultCondition);
}

# conditionSub returns a pre-compiled subroutine used to grant users (used by
# locationRulesInit().
sub conditionSub {
    my ( $class, $cond ) = @_;
    return sub { 1 }
      if ( $cond =~ /^accept$/i );
    return sub { 0 }
      if ( $cond =~ /^deny$/i );
    $cond =~ s/\$(\w+)/\$datas->{$1}/g;
    my $sub;
    eval '$sub = sub {return (' . $cond . ')}';
    return $sub;
}

# defaultValuesInit : set default values for non-customized variables
sub defaultValuesInit {
    my ( $class, $args ) = @_;

    # Other values
    $cookieName  = $args->{cookieName}  || 'lemon';
    $whatToTrace = $args->{whatToTrace} || '$uid';
    $whatToTrace =~ s/\$//g;
    $https = $args->{https};
    $https = 1 unless defined($https);
}

# portalInit : verify that portal variable exists
sub portalInit {
    my ( $class, $args ) = @_;
    $portal = $args->{portal} or die("portal parameter required");
}

# globalStorageInit : initialize the Apache::Session::* package used to
# share user's variables
sub globalStorageInit {
    my ( $class, $args ) = @_;
    $globalStorage = $args->{globalStorage} or die "globalStorage required";
    eval "use $globalStorage;";
    die($@) if ($@);
    $globalStorageOptions = $args->{globalStorageOptions};
}

# forgeHeadersInit : create the &$forgeHeaders subroutine used to insert
# headers into the HTTP request (which are used for accounting by the
# application)
sub forgeHeadersInit {
    my ( $class, $args ) = @_;

    # Creation of the subroutine who will generate headers
    my %tmp;
    if ( $args->{exportedHeaders} ) {
        %tmp = %{ $args->{exportedHeaders} };
    }
    else {
        %tmp = ( 'User-Auth' => '$uid' );
    }
    foreach ( keys %tmp ) {
        $tmp{$_} =~ s/\$(\w+)/\$datas->{$1}/g;
        $tmp{$_} =~ s/\$datas->\{ip\}/\$apacheRequest->connection->remote_ip/g;
    }

    my $sub;
    foreach ( keys %tmp ) {
        $sub .=
          "\$apacheRequest->header_in('$_' => join('',split(/[\\r\\n]+/,"
          . $tmp{$_} . ")));";
    }
    $sub = "\$forgeHeaders = sub {$sub};";
    eval "$sub";
    Apache->server->log->error(
        __PACKAGE__ . ": Unable to forge headers: $@ $sub" )
      if ($@);
}

################
# MAIN PROCESS #
################

# grant : grant or refuse client
sub grant {
    my ( $class, $uri ) = @_;
    for ( my $i = 0 ; $i < $locationCount ; $i++ ) {
        return &{ $locationCondition->[$i] }($datas)
          if ( $uri =~ $locationRegexp->[$i] );
    }
    return &$defaultCondition;
}

# forbidden : used to reject non authorizated requests
sub forbidden {

    # We use Apache::Log here
    $apacheRequest->log->notice( 'The user "'
          . $datas->{$whatToTrace}
          . '" was reject when he tried to access to '
          . $_[1] );
    return FORBIDDEN;
}

# hideCookie : hide Lemonldap cookie to the protected application
sub hideCookie {
    my $tmp = $apacheRequest->header_in('Cookie');
    $tmp =~ s/$cookieName[^;]*;?//o;
    $apacheRequest->header_in( 'Cookie', $tmp );
}

# Redirect non-authenticated users to the portal
sub goToPortal() {
    my ( $class, $url ) = @_;
    my $urlc_init =
      encode_base64( "http"
          . ( $https ? "s" : "" ) . "://"
          . $apacheRequest->get_server_name()
          . $url );
    $urlc_init =~ s/[\n\s]//g;
    $apacheRequest->header_out( location => "$portal?url=$urlc_init" );
    $apacheRequest->log->debug( "Redirect "
          . $apacheRequest->connection->remote_ip
          . " to portal (url was $url)" );
    return REDIRECT;
}

# MAIN SUBROUTINE called by Apache (using PerlInitHandler option)
sub handler ($$) {
    my $class;
    ( $class, $apacheRequest ) = @_;

    my $uri =
      $apacheRequest->uri
      . ( $apacheRequest->args ? "?" . $apacheRequest->args : "" );

    # AUTHENTICATION
    # I - recover the cookie
    my $id;
    unless ( ($id) =
        ( $apacheRequest->header_in('Cookie') =~ /$cookieName=([^; ]+);?/o ) )
    {
        Apache->server->log->info(
            "No cookie found" . $apacheRequest->header_in('Cookie') );
        return $class->goToPortal($uri);
    }

    # II - recover the user datas
    #  2.1 search if the user was the same as previous (very efficient in
    #      persistent connection).
    unless ( $id eq $datas->{_session_id} ) {

        # 2.2 search in the local cache if exists
        unless ( $refLocalStorage and $datas = $refLocalStorage->get($id) ) {

            # 2.3 search in the central cache
            my %h;
            eval { tie %h, $globalStorage, $id, $globalStorageOptions; };
            if ($@) {

                # The cookie isn't yet available
                Apache->server->log->info(
                    "The cookie $id isn't yet available: $@");
                return $class->goToPortal($uri);
            }
            $datas->{$_} = $h{$_} foreach ( keys %h );

            # Store now the user in the local storage
            if ($refLocalStorage) {
                $refLocalStorage->set( $id, $datas, "10 minutes" );
            }
            untie %h;
        }
    }

    # AUTHORIZATION
    return $class->forbidden($uri) unless ( $class->grant($uri) );
    Apache->server->log->debug( "User "
          . $datas->{$whatToTrace}
          . " was authorizated to access to $uri" );

    # ACCOUNTING
    # 1 - Inform Apache
    $apacheRequest->connection->user( $datas->{$whatToTrace} );

    # 2 - Inform remote application
    $class->sendHeaders;

    # SECURITY
    # Hide Lemonldap cookie
    hideCookie;
    OK;
}

sub sendHeaders {
    &$forgeHeaders;
}

sub initLocalStorage {
    my($class,$r) = @_;
    if ( $localStorage and not $refLocalStorage ) {
        eval '$refLocalStorage = new '
          . $localStorage
          . '($localStorageOptions);';
    }
    $r->log_error("Local cache initialization failed: $@")
      unless ( defined $refLocalStorage );
    return DECLINED;
}

sub cleanLocalStorage {
    $refLocalStorage->purge() if ($refLocalStorage);
    return DECLINED;
}

1;
__END__

=head1 NAME

Lemonldap::NG::Handler - Perl extension for building a Lemonldap compatible handler

=head1 SYNOPSIS

Create your own package:

  package My::Package;
  use Lemonldap::NG::Handler;

  our @ISA = qw(Lemonldap::NG::Handler);

  __PACKAGE__->init ({locationRules => { 'default' => '$ou =~ /brh/'},
	 globalStorage        => 'Apache::Session::MySQL',
	 globalStorageOptions => {
               DataSource       => 'dbi:mysql:database=dbname;host=127.0.0.1',
               UserName         => 'db_user',
               Password         => 'db_password',
               TableName        => 'sessions',
               LockDataSource   => 'dbi:mysql:database=dbname;host=127.0.0.1',
               LockUserName     => 'db_user',
               LockPassword     => 'db_password',
           },
	 localStorage         => 'Cache::DBFile',
	 localStorageOptions  => {},
	 portal               => 'https://portal/',
       });

More complete example

  package My::Package;
  use Lemonldap::NG::Handler;

  our @ISA = qw(Lemonldap::NG::Handler);

  __PACKAGE__->init ( { locationRules => {
	     '^/pj/.*$'       => q($qualif="opj"),
	     '^/rh/.*$'       => q($ou=~/brh/),
	     '^/rh_or_opj.*$' => q($qualif="opj or $ou=~/brh/),
             default => 'accept', # means that all authenticated users are greanted
	   },
           globalStorage        => 'Apache::Session::MySQL',
           globalStorageOptions => {
               DataSource       => 'dbi:mysql:database=dbname;host=127.0.0.1',
               UserName         => 'db_user',
               Password         => 'db_password',
               TableName        => 'sessions',
               LockDataSource   => 'dbi:mysql:database=dbname;host=127.0.0.1',
               LockUserName     => 'db_user',
               LockPassword     => 'db_password',
           },
	   localStorage         => 'Cache::DBFile',
	   localStorageOptions  => {},
	   cookieName           => 'lemon',
	   portal               => 'https://portal/',
	   whatToTrace          => '$uid',
	   exportedHeaders      => {
	       'Auth-User'      => '$uid',
	       'Unit'           => '$ou',
	   https                => 1,
	 }
       );

Call your package in <apache-directory>/conf/httpd.conf

  PerlRequire MyFile
  # TOTAL PROTECTION
  PerlInitHandler My::Package
  # OR SELECTED AREA
  <Location /protected-area>
    PerlInitHandler My::Package
  </Location>

=head1 DESCRIPTION

Lemonldap::NG::Handler is designed to be overloaded. See
L<Lemonldap::NG::Handler::SharedConf::DBI> for a complete system.

Lemonldap::NG is a simple Web-SSO based on Apache::Session modules. It
simplifies the build of a protected area with a few changes in the application
(they just have to read some headers for accounting).

It manages both authentication and authorization and provides headers for
accounting. So you can have a full AAA protection for your web space. There are
two ways to build a cross domain authentication:

=over

=item * Cross domain authentication itself (L<Lemonldap::Portal::Cda>) I<(not
yet implemented in Lemonldap::NG)>

=item * "Liberty Alliance" (see L<Lemonldap::NG::ServiceProvider> and
L<Lemonldap::NG::IdentityProvider>)

=back

This library provides a simple agent (Apache handler) to protect a web area.
It can be extended with other Lemonldap::NG::Handler::* modules to add various
functionalities. For example :

=over

=item * L<Lemonldap::NG::Handler::Vhost> to be able to manage different
Apache virtual hosts with the same module

=item * L<Lemonldap::NG::Handler::SharedConf> to be able to change handler
configuration without restarting Apache

=item * L<Lemonldap::NG::Handler::Proxy> to replace Apache mod_proxy if you
have some problems (for example, managing redirections,...)

=item * L<Lemonldap::NG::Handler::SharedConf::DBI> is a complete system that
can be used to protect different hosts using a central database to manage
configurations.

=back

=head2 INITIALISATION PARAMETERS

This section presents the C<init> method parameters.

=over

=item B<locationRules> (required)

Reference to a hash that contains "url-regexp => perl-expression" entries to
manage authorizations.

=over

=item * "url-regexp" can be a perl regexp or the keyword 'default' which
corresponds to the default police (accept by default).

=item * "perl-expression" can be a perl condition or the keyword "accept" or the
keyword "deny". All the variables announced by $<name of the variable> are
replaced by the values resulting from the global session store.

=back

=item B<globalStorage> E<amp> B<globalStorageOptions> (required)

Name and parameters of the Apache::Session::* module used by the portal to
store user's datas. See L<Lemonldap::NG::Portal(3)> for more explanations.

=item B<localStorage> E<amp> B<localStorageOptions>

Name and parameters of the optional but recommanded Cache::* module used to
share user's datas between Apache processes. There is no need to set expires
options since L<Lemonldap::NG::Handler> call the Cache::*::purge method itself.

=item B<cookieName> (default: lemon)

Name of the cookie used by the Lemonldap infrastructure.

=item B<portal> (required)

Url of the portal used to authenticate users.

=item B<whatToTrace> (default: uid)

Stored user variable to use in Apache logs.

=item B<exportedHeaders>

Reference to a hash that contains "Name => value" entries. Those headers are
calculated for each user by replacing the variables announced by "$" by their
values resulting from the global session store.

=item B<https> (default: 1)

Indicates if the protected server is protected by SSL. It is used to build
redirections, so you have to set it to avoid bad redirections after
authentication.

=back

=head2 EXPORT

None by default. You can import the following tags for inheritance:

=over

=item * B<:variables> : all global variables

=item * B<:localStorage> : variables used to manage local storage

=item * B<:import> : import function inherited from L<Exporter> and related
variables

=back

=head2 AUTHENTICATION-AUTHORIZATION-ACCOUNTING

This section presents Lemonldap characteristics from the point-of-vue of
AAA.

=head3 B<Authentication>

If a user isn't authenticated and attemps to connect to an area protected by a
Lemonldap compatible handler, he is redirected to the portal. The portal
authenticates user with a ldap bind by default, but you can also use another
authentication sheme like using x509 user certificates (see
L<Lemonldap::NG::Portal::AuthSSL> for more).

Lemonldap use session cookies generated by L<Apache::Session> so as secure as a
128-bit random cookie. You may use the C<cookie_secure> options of
L<Lemonldap::NG::Portal> to avoid session hijacking.

You have to manage life of sessions by yourself since Lemonldap knows nothing
about the L<Apache::Session> module you've choose, but it's very easy using a
simple cron script because L<Lemonldap::NG::Portal> stores the start time in the
C<_utime> field.

=head3 B<Authorization>

Authorization is controled only by handlers because the portal knows nothing
about the way the user will choose. L<Lemonldap::NG::Portal> is designed to help
you to store all the user datas you wants to use to manage authorization.

When initializing an handler, you have to describe what you want to protect and
who can connect to. This is done by the C<locationRules> parameters of C<init>
method. It is a reference to a hash who contains entries where:

=over 4

=item * B<keys> are regular expression who are compiled by C<init> using
C<qr()> B<or> the keyword C<default> who points to the default police.

=item * B<values> are conditional expressions B<or> the keyword C<accept> B<or>
the keyword C<deny>:

=over

=item * Conditional expressions are converted into subroutines. You can use the
variables stored in the global store by calling them C<$E<lt>varnameE<gt>>.

Exemple:

  '^/rh/.*$' => '$ou =~ /brh/'

=item * Keyword B<deny> denies any access while keyword B<accept> allows all
authenticated users.

Exemple:

  'default'  => 'accept'

=back

=back

=head3 B<Accounting>

=head4 I<Logging portal access>

L<Lemonldap::NG::Portal> doesn't log anything by default, but it's easy to overload
C<log> method for normal portal access or using C<error> method to know what
was wrong if C<process> method has failed.

=head4 I<Logging application access>

Because an handler knows nothing about the protected application, it can't do
more than logging URL. As Apache does this fine, L<Lemonldap::NG::Handler> gives it
the name to used in logs. The C<whatToTrace> parameters indicates which
variable Apache has to use (C<$uid> by default).

The real accounting has to be done by the application itself which knows the
result of SQL transaction for example.

Lemonldap can export http headers either using a proxy or protecting directly
the application. By default, the C<User-Auth> field is used but you can change
it using the C<exportedHeaders> parameters of the C<init> method. It is a
reference to a hash where:

=over

=item * B<keys> are the names of the choosen headers

=item * B<values> are perl expressions where you can use user datas stored in
the global store by calling them C<$E<lt>varnameE<gt>>.

=back

=head1 SEE ALSO

=over

L<Lemonldap::NG::Handler::SharedConf::DBI>,
L<Lemonldap::NG::Portal(3)>, L<Lemonldap::NG::Handler::Proxy(3)>,

=head1 AUTHOR

Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Xavier Guimard E<lt>x.guimard@free.frE<gt>

Lemonldap was originaly written by Eric german who decided to publish him in
2003 under the terms of the GNU General Public License version 2.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.

Lemonldap was originaly written by Eric german who decided to publish him in
2003 under the terms of the GNU General Public License version 2.
Lemonldap::NG is a complete rewrite of Lemonldap and is able to have different
policies in a same Apache virtual host.

=cut
