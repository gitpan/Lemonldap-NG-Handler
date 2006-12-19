package My::Package;
use Lemonldap::NG::Handler::SharedConf;
@ISA = qw(Lemonldap::NG::Handler::SharedConf);

__PACKAGE__->init ( {
    localStorage        => "Cache::FileCache",
    localStorageOptions => {
              'namespace'          => 'MyNamespace',
              'default_expires_in' => 600,
    },

    configStorage       => {
              type                 => 'File',
              dirName              => '__DIR__/conf',
    },

    https               => 0,
} );

