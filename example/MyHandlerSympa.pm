# Handler for Sympa autologin

package My::Sympa;

# Load Sympa Handler
use Lemonldap::NG::Handler::SympaAutoLogin;
@ISA = qw(Lemonldap::NG::Handler::SympaAutoLogin);

__PACKAGE__->init(
    {

        # See Lemonldap::NG::Handler
    }
);

1;
