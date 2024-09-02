use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME         => 'Net::PrivateBin',
    VERSION_FROM => 'lib/Net/PrivateBin.pm',
    ABSTRACT_FROM => 'lib/Net/PrivateBin.pm',
    AUTHOR       => '84456263+wetzf@users.noreply.github.com',
    LICENSE      => 'perl',
    PREREQ_PM    => {},
    META_MERGE   => {
        resources => {
            repository => 'https://github.com/Freicon/perl-net-privatebin',
        },
    },
);
