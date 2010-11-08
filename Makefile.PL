
use strict;
use warnings;



use ExtUtils::MakeMaker 6.31;



my %WriteMakefileArgs = (
  'ABSTRACT' => 'Library for consumers of OpenID identities',
  'AUTHOR' => 'Robert Norris <rob@eatenbyagrue.org>',
  'BUILD_REQUIRES' => {
    'Test::More' => '0'
  },
  'CONFIGURE_REQUIRES' => {
    'ExtUtils::MakeMaker' => '6.31'
  },
  'DISTNAME' => 'Net-OpenID-Consumer',
  'EXE_FILES' => [],
  'LICENSE' => 'perl',
  'NAME' => 'Net::OpenID::Consumer',
  'PREREQ_PM' => {
    'Digest::SHA' => '0',
    'HTTP::Request' => '0',
    'LWP::UserAgent' => '0',
    'MIME::Base64' => '0',
    'Net::OpenID::Common' => '1.030099_001',
    'Storable' => '0',
    'Time::Local' => '0',
    'URI' => '0'
  },
  'VERSION' => '1.030099_003',
  'test' => {
    'TESTS' => 't/*.t'
  }
);


unless ( eval { ExtUtils::MakeMaker->VERSION(6.56) } ) {
  my $br = delete $WriteMakefileArgs{BUILD_REQUIRES};
  my $pp = $WriteMakefileArgs{PREREQ_PM};
  for my $mod ( keys %$br ) {
    if ( exists $pp->{$mod} ) {
      $pp->{$mod} = $br->{$mod} if $br->{$mod} > $pp->{$mod};
    }
    else {
      $pp->{$mod} = $br->{$mod};
    }
  }
}

delete $WriteMakefileArgs{CONFIGURE_REQUIRES}
  unless eval { ExtUtils::MakeMaker->VERSION(6.52) };

WriteMakefile(%WriteMakefileArgs);



