use 5.006000;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Lemonldap::NG::Handler',
    VERSION           => '0.61', # finds $VERSION
    PREREQ_PM         => {
		'Apache::Constants' => 0,
		'Apache::Session'   => 0,
		'LWP::UserAgent'    => 0,
		'Cache::Cache'      => 0,
		'MIME::Base64'      => 0,
		'DBI'               => 0,
		'Exporter'          => 0,
		}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Lemonldap/NG/Handler.pod', # retrieve abstract from module
       AUTHOR         => 'x.guimard <x.guimard@free.fr>') : ()),
);
