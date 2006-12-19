use 5.006000;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Lemonldap::NG::Handler',
    VERSION_FROM      => 'lib/Lemonldap/NG/Handler.pm',
    PREREQ_PM         => {
		'Apache::Session'        => 0,
		'LWP::UserAgent'         => 0,
		'Cache::Cache'           => 0,
		'MIME::Base64'           => 0,
		'DBI'                    => 0,
		'Exporter'               => 0,
		'Lemonldap::NG::Manager' => 0.03,
		}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Lemonldap/NG/Handler.pm', # retrieve abstract from module
       AUTHOR         => 'x.guimard <x.guimard@free.fr>') : ()),
);
