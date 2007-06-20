package My::Package;
use Lemonldap::NG::Handler::SharedConf;
@ISA = qw(Lemonldap::NG::Handler::SharedConf);

__PACKAGE__->init ( {
    localStorage        => "Cache::FileCache",
    localStorageOptions => {
              'namespace'          => 'MyNamespace',
              'default_expires_in' => 600,
              'directory_umask'    => '007',
              'cache_root'         => '/tmp',
              'cache_depth'        => 5,
    },

    configStorage       => {
              type                 => 'File',
              dirName              => '__CONFDIR__',
    },

    https               => 0,
} );

