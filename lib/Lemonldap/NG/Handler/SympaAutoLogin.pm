package Lemonldap::NG::Handler::SympaAutoLogin;

use strict;
use Lemonldap::NG::Handler::SharedConf qw(:all);
our @ISA = qw(Lemonldap::NG::Handler::SharedConf);
use Digest::MD5;

our $VERSION = '0.1';

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

