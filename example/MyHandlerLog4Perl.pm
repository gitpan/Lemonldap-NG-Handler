package My::Package;
use Lemonldap::NG::Handler::SharedConf;
@ISA = qw(Lemonldap::NG::Handler::SharedConf);

__PACKAGE__->init(
    {
        localStorage        => "Cache::FileCache",
        localStorageOptions => {
            'namespace'          => 'MyNamespace',
            'default_expires_in' => 600,
            'directory_umask'    => '007',
            'cache_root'         => '/tmp',
            'cache_depth'        => 5,
        },

        configStorage => {
            type    => 'File',
            dirName => '__CONFDIR__',
        },

        https   => 0,
        # Uncomment this to activate status module
        # status => 1,
    }
);

use Log::Log4perl;

sub logForbidden {
    my $class = shift;
    my $log   = Log::Log4perl->get_logger("My::Package");
    $log->warn(
            'The user "'
          . $datas->{$whatToTrace}
          . '" was reject when he tried to access to '
          . shift,
    );
}
1;
