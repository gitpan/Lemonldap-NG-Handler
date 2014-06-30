## @file
# Base file for Lemonldap::NG handlers

## @class
# Base class for Lemonldap::NG handlers.
# All methods in handler are class methods: in ModPerl environment, handlers
# are always launched without object created.
#
# The main method is run() who is called by Apache for each requests (using
# handler() wrapper).
#
# The main initialization subroutine is init() who launch localInit() and
# globalInit().
package Lemonldap::NG::Handler::Initialization::LocalInit;

use Mouse;

use Lemonldap::NG::Handler::SharedConf;    # Needed to get VERSION
use Lemonldap::NG::Handler::Main::Logger;

our $VERSION = '1.3.0';

# Mouse attributes
##################

# default attributes from constructor
has localStorage => ( is => 'rw', isa => 'Maybe[Str]', required => 1 );

has refLocalStorage => ( is => 'rw', required => 1 );

has localStorageOptions =>
  ( is => 'rw', isa => 'Maybe[HashRef]', required => 1 );

has childInitDone => ( is => 'rw' );

# attributes built and returned
has [ 'statusPipe', 'statusOut' ] => ( is => 'rw' );

BEGIN {
    if ( exists $ENV{MOD_PERL} ) {
        if ( $ENV{MOD_PERL_API_VERSION} and $ENV{MOD_PERL_API_VERSION} >= 2 ) {
            eval 'use constant MP => 2;';
        }
        else {
            eval 'use constant MP => 1;';
        }
    }
    else {
        eval 'use constant MP => 0;';
    }
    if ( MP() == 2 ) {
        require Apache2::Log;
        require Apache2::RequestUtil;
        Apache2::RequestUtil->import();
        require Apache2::RequestRec;
        Apache2::RequestRec->import();
        require Apache2::ServerUtil;
        Apache2::ServerUtil->import();
        require Apache2::Connection;
        Apache2::Connection->import();
        require Apache2::RequestIO;
        Apache2::RequestIO->import();
        require APR::Table;
        APR::Table->import();
        require Apache2::URI;
        Apache2::URI->import();
        require Apache2::Const;
        Apache2::Const->import( '-compile', qw(:common :log) );
        eval '
        use constant FORBIDDEN    => Apache2::Const::FORBIDDEN;
        use constant REDIRECT     => Apache2::Const::REDIRECT;
        use constant OK           => Apache2::Const::OK;
        use constant DECLINED     => Apache2::Const::DECLINED;
        use constant DONE         => Apache2::Const::DONE;
        use constant SERVER_ERROR => Apache2::Const::SERVER_ERROR;
        ';
    }
    elsif ( MP() == 1 ) {
        require Apache;
        require Apache::Log;
        require Apache::Constants;
        Apache::Constants->import(':common');
        Apache::Constants->import(':response');
    }
    else {    # For Test or CGI
        eval '
        use constant FORBIDDEN    => 1;
        use constant REDIRECT     => 1;
        use constant OK           => 1;
        use constant DECLINED     => 1;
        use constant DONE         => 1;
        use constant SERVER_ERROR => 1;
        ';
    }
}

# Mouse methods
###############

## @imethod void localInit(hashRef args)
# Call purgeCache() to purge the local cache, launch the status process
# (statusProcess()) in wanted and launch childInit().
# @param $args reference to the initialization hash
sub localInit($$) {
    my ( $self, $args ) = splice @_;
    if ( $self->{localStorage} = $args->{localStorage} ) {
        $self->{localStorageOptions} = $args->{localStorageOptions};
        $self->{localStorageOptions}->{default_expires_in} ||= 600;
        $self->purgeCache();
    }
    if ( $args->{status} ) {
        if ( defined $self->{localStorage} ) {
            $self->statusProcess();
        }
        else {

            # localStorage is mandatory for status module
            Lemonldap::NG::Handler::Main::Logger->lmLog(
"Status module can not be loaded without localStorage parameter",
                'warn'
            );
        }
    }
    $self->childInit($args);
    return (
        $self->{localStorage},        $self->{refLocalStorage},
        $self->{localStorageOptions}, $self->{statusPipe},
        $self->{statusOut},           $self->{childInitDone}
    );
}

## @imethod protected void purgeCache()
# Purge the local cache.
# Launched at Apache startup.
sub purgeCache {
    my $self = shift;
    eval "use $self->{localStorage};";
    die("Unable to load $self->{localStorage}: $@") if ($@);

    # At each Apache (re)start, we've to clear the cache to avoid living
    # with old datas
    eval '$self->{refLocalStorage} = new '
      . $self->{localStorage}
      . '($self->{localStorageOptions});';
    if ( defined $self->{refLocalStorage} ) {
        $self->{refLocalStorage}->clear();
    }
    else {
        Lemonldap::NG::Handler::Main::Logger->lmLog(
            "Unable to clear local cache: $@", 'error' );
    }
}

# Status daemon creation

## @ifn protected void statusProcess()
# Launch the status processus.
sub statusProcess {
    my $self = shift;
    require IO::Pipe;
    $self->{statusPipe} = IO::Pipe->new;
    $self->{statusOut}  = IO::Pipe->new;
    if ( my $pid = fork() ) {
        $self->{statusPipe}->writer();
        $self->{statusOut}->reader();
        $self->{statusPipe}->autoflush(1);
    }
    else {
        require Data::Dumper;
        $self->{statusPipe}->reader();
        $self->{statusOut}->writer();
        my $fdin  = $self->{statusPipe}->fileno;
        my $fdout = $self->{statusOut}->fileno;
        open STDIN,  "<&$fdin";
        open STDOUT, ">&$fdout";
        my @tmp = ();
        push @tmp, "-I$_" foreach (@INC);
        exec 'perl', '-MLemonldap::NG::Handler::Status',
          @tmp,
          '-e',
          '&Lemonldap::NG::Handler::Status::run('
          . $self->{localStorage} . ','
          . Data::Dumper->new( [ $self->{localStorageOptions} ] )->Terse(1)
          ->Dump . ');';
    }
}

## @imethod protected boolean childInit()
# Indicates to Apache that it has to launch:
# - initLocalStorage() for each child process (after fork and uid change)
# - cleanLocalStorage() after each requests
# @return True
sub childInit {
    my ( $self, $args ) = splice @_;
    return 1 if ( $self->{childInitDone} );

    # We don't initialise local storage in the "init" subroutine because it can
    # be used at the starting of Apache and so with the "root" privileges. Local
    # Storage is also initialized just after Apache's fork and privilege lost.

    # Local storage is cleaned after giving the content of the page to increase
    # performances.
    no strict;
    if ( MP() == 2 ) {
        $s = Apache2::ServerUtil->server;
        $s->push_handlers( PerlChildInitHandler =>
              sub { return $self->initLocalStorage( $_[1], $_[0] ); } );
        $s->push_handlers(
            PerlPostConfigHandler => sub {
                my ( $c, $l, $t, $s ) = splice @_;
                $s->add_version_component( 'Lemonldap::NG::Handler/'
                      . $Lemonldap::NG::Handler::VERSION );
            }
        ) unless ( $args->{hideSignature} );
    }
    elsif ( MP() == 1 ) {
        Apache->push_handlers(
            PerlChildInitHandler => sub { return $self->initLocalStorage(@_); }
        );
    }
    $self->{childInitDone}++;
    1;
}

## @imethod protected int initLocalStorage()
# Prepare local cache (if not done before by Lemonldap::NG::Common::Conf)
# @return Apache2::Const::DECLINED
sub initLocalStorage {
    my ( $self, $r ) = splice @_;
    if ( $self->{localStorage} and not $self->{refLocalStorage} ) {
        eval
"use $self->{localStorage};\$self->{refLocalStorage} = new $self->{localStorage}(\$self->{localStorageOptions});";

        Lemonldap::NG::Handler::Main::Logger->lmLog(
            "Local cache initialization failed: $@", 'error' )
          unless ( defined $self->{refLocalStorage} );
    }
    return DECLINED;
}

1;
