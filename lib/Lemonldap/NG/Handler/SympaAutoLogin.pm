package Lemonldap::NG::Handler::SympaAutoLogin;

use strict;
use Lemonldap::NG::Handler::SharedConf qw(:all);
our @ISA = qw(Lemonldap::NG::Handler::SharedConf);
use Digest::MD5;

our $VERSION = '0.11';

open S, '/etc/lemonldap-ng/sympa.secret' or die "Unable to open /etc/lemonldap-ng/sympa.secret";
our $sympaSecret = join('',<S>);
close S;
$sympaSecret =~ s/[\r\n]//g;

sub run {
	my $class = shift;
	my $r = $_[0];
	my $ret = $class->SUPER::run(@_);

    # Building Sympa cookie
	my $tmp = new Digest::MD5;
	$tmp->reset;
	$tmp->add($datas->{mail}.$sympaSecret);
	my $str = "sympauser=$datas->{mail}:".substr(unpack("H*",$tmp->digest), -8);

    # Get cookie header, removing Sympa cookie if exists (avoid security
    # problems) and set the new value
	$tmp = lmHeaderIn( $r, 'Cookie' );
    $tmp =~ s/\bsympauser=[^,;]*[,;]?//;
	$tmp .= $tmp ? ";$str" : $str;
	lmSetHeaderIn( $r, 'Cookie' => $tmp );

    # Return SUPER::run() result
	return $ret;
}

1;
__END__

=head1 NAME

Lemonldap::NG::Handler::SympaAutoLogin - Perl extension to generate Sympa cookie
for users authenticated by Lemonldap::NG

=head1 SYNOPSIS

  package My::Package;
  use Lemonldap::NG::Handler::SympaAutoLogin;
  @ISA = qw(Lemonldap::NG::Handler::SharedConf);

  __PACKAGE__->init ( {
    # See Lemonldap::NG::Handler for more
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

=head1 DESCRIPTION

Lemonldap::NG::Handler::SympaAutoLogin is a special Lemonldap::NG handler that
generates Sympa cookie for authenticated users. Use it instead of classic
Lemonldap::NG::Handler to protect your Sympa web server. You have to set a
header called "mail" in the Lemonldap::NG manager for this virtul host and to
store Sympa secret (cookie parameter on Sympa configuration file) ina file
called /etc/lemonldap-ng/sympa.secret. It has just to be readable by root (the
owner that launch Apache).

=head2 EXPORT

See L<Lemonldap::NG::Handler>

=head1 SEE ALSO

L<Lemonldap::NG::Handler>

=head1 AUTHOR

Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Xavier Guimard

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
