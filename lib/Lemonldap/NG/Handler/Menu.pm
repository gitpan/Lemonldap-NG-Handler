##@file
# Menu

##@class
# Menu
#
# Display a menu on protected applications
package Lemonldap::NG::Handler::Menu;

use strict;
use Lemonldap::NG::Handler::SharedConf qw(:all);
use base qw(Lemonldap::NG::Handler::SharedConf);
use Apache2::Filter ();
use constant BUFF_LEN => 1024;

## @rmethod Apache2::Const run(Apache2::Filter f)
# Overload main run method
# @param f Apache2 Filter
# @return Apache2::Const::OK
sub run {
    my $class = shift;
    my $f     = $_[0];

    unless ( $f->ctx ) {
        $f->r->headers_out->unset('Content-Length');
        $f->ctx(1);
    }

    # CSS parameters
    my $background  = "#ccc";
    my $border      = "#aaa";
    my $width       = "30%";
    my $marginleft  = "35%";
    my $marginright = "35%";
    my $height      = "20px";

    my $menudiv = "
<style>
#lemonldap-ng-menu {
    background-color: $background;
    border-color: $border;
    border-width: 2px 2px 0 2px;
    border-style: solid;
    border-top-left-radius: 10px;
    border-top-right-radius: 10px;
    width: $width;
    height: $height;
    margin-right: $marginright;
    margin-left: $marginleft;
    position: absolute;
    bottom: 0px;
    text-align: center;
    padding: 3px;
    z-index: 2;
}
html>body #lemonldap-ng-menu {
    position: fixed;
}
</style>
<div id=\"lemonldap-ng-menu\">
<a href=\"" . $class->portal() . "\">☖ Home</a>
<span>  </span>
<a href=\"/logout\">☒ Logout</a>
</div>";

    while ( $f->read( my $buffer, BUFF_LEN ) ) {
        $buffer =~ s/<\/body>/$menudiv<\/body>/g;
        $f->print($buffer);
    }

    return OK;

}

1;
