# Handler for Secure Token

package My::SecureToken;

# Load Secure Token Handler
use Lemonldap::NG::Handler::SecureToken;
@ISA = qw(Lemonldap::NG::Handler::SecureToken);

__PACKAGE__->init(
    {

        # See Lemonldap::NG::Handler
    }
);

1;
