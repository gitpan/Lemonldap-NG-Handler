# Handler for Zimbra preauthentication

package My::Zimbra;

# Load Zimbra Handler
use Lemonldap::NG::Handler::ZimbraPreAuth;
@ISA = qw(Lemonldap::NG::Handler::ZimbraPreAuth);

__PACKAGE__->init(
    {

        # See Lemonldap::NG::Handler
    }
);

1;
