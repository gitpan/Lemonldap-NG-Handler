use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Lemonldap::NG::Handler',
    VERSION_FROM      => 'lib/Lemonldap/NG/Handler.pm',
    PMLIBDIRS         => [ 'lib' ],
    PREREQ_PM         => {
        'Apache::Session'        => 0,
        'LWP::UserAgent'         => 0,
        'Cache::Cache'           => 0,
        'Lemonldap::NG::Manager' => 0.4,
        'IO::Pipe'               => 0,
        }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Lemonldap/NG/Handler.pm', # retrieve abstract from module
       AUTHOR         => 'Xavier Guimard <x.guimard@free.fr>') : ()),
);
