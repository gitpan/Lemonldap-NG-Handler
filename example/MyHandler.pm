package My::Package;
use Lemonldap::NG::Handler::SharedConf;
@ISA = qw(Lemonldap::NG::Handler::SharedConf);

__PACKAGE__->init(
    {

        # WARNING:
        # all args inserted here must be the same for all handlers launched on
        # the same Apache server even if they inherits from different classes
        # (SympaAutoLogin,...)

        # ACCESS TO CONFIGURATION

        # By default, Lemonldap::NG uses the default lemonldap-ng.ini file to
        # know where to find is configuration
        # (generaly /etc/lemonldap-ng/lemonldap-ng.ini)
        # You can specify by yourself this file :
        #configStorage => { confFile => '/path/to/my/file' },
        # You can also specify directly the configuration
        # (see Lemonldap::NG::Handler::SharedConf(3))
        #configStorage => {
        #      type => 'File',
        #      dirName => '/usr/local/lemonldap-ng/data/conf/'
        #},

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
