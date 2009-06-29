package My::Package;
use Lemonldap::NG::Handler::SharedConf;
@ISA = qw(Lemonldap::NG::Handler::SharedConf);

__PACKAGE__->init(
    {

        # ACCESS TO CONFIGURATION

        # By default, Lemonldap::NG uses the default storage.conf file to know
        # where to find is configuration
        # (generaly /etc/lemonldap-ng/storage.conf)
        # You can specify by yourself this file :
        #configStorage => { File => '/path/to/my/file' },

        # You can also specify directly the configuration
        # (see Lemonldap::NG::Handler::SharedConf(3))
        #configStorage => {
        #      type => 'File',
        #      directory => '/usr/local/lemonlda-ng/conf/'
        #},

        # STATUS MODULE
        # Uncomment this to activate status module:
        #status => 1,

        # REDIRECTIONS
        # You have to set this to explain to the handler if runs under SSL
        # or not (for redirections after authentications). Default is true.
        https => 0,

        # You can also fix the port (for redirections after authentications)
        #port => 80,

        # CROSS-DOMAIN
        # If your handler is not on the same domain than the portal, uncomment
        # this (and don't forget to set "cda => 1" in the portal
        #cda => 1,

        # CUSTOM FUNCTION
        # If you want to create customFunctions in rules, declare them here:
        #customFunctions    => 'function1 function2',
        #customFunctions    => 'Package::func1 Package::func2',

        # OTHERS
        # You can also overload any parameter issued from manager
        # configuration. Example:
        #globalStorage => 'Lemonldap::NG::Common::Apache::Session::SOAP',
        #globalStorageOptions => {
        #    proxy => 'http://auth.example.com/index.pl/sessions',
        #    proxyOptions => {
        #        timeout => 5,
        #    },
        #    # If soapserver is protected by HTTP Basic:
        #    User     => 'http-user',
        #    Password => 'pass',
        #},
    }
);
1;
