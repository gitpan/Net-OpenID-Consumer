#!/usr/bin/perl

use strict;
use Test::More tests => 19;
use Data::Dumper;
use Net::OpenID::Consumer;

my ($query_string, %get_vars);

my $csr = Net::OpenID::Consumer->new(
                                     args => \%get_vars,
                                     );

print "csr = $csr\n";

# $csr->nonce_generator(sub { rand(5000); });
# $csr->nonce_checker(sub { return 1; });
# $csr->identity_cache(sub { return 1; });
# $csr->web_cache(sub { return 1; });

my $ident = $csr->claimed_identity(" sdlkj lskdj 3");
ok(! $ident);
ok( $csr->json_err =~ /url_fetch_error/);


$ident = $csr->claimed_identity("bradfitz.com")
    or die $csr->err . ": " . $csr->errtext;

ok($ident->claimed_url eq "http://bradfitz.com/");
ok(($ident->identity_servers)[0] eq "http://www.livejournal.com/misc/openid.bml?ljuser_sha1=9233b6f5388d6867a2a7be14d8b4ba53c86cfde2");

my $check_url = $ident->check_url(
                                  return_to => "http://www.danga.com/sdf/openid/demo/classic-helper.bml",
                                  trust_root => "http://*.danga.com/sdf",
                                  delayed_return => 1,
                                  );


ok($check_url =~ /openid\.bml\?/);
ok($check_url =~ /openid\.mode=checkid_setup/);

$query_string = "openid.mode=id_res&openid.user_setup_url=http://www.livejournal.com/misc/openid-approve.bml%3Ftrust_root%3Dhttp://%252A.danga.com/sdf%26return_to%3Dhttp://www.danga.com/sdf/openid/demo/classic-helper.bml%26post_grant%3Dreturn%26is_identity%3Dhttp://bradfitz.com/";
%get_vars = map { durl($_) } split(/[&=]/, $query_string);

if (my $setup_url = $csr->user_setup_url) {
    ok($setup_url =~ /openid-approve/);
} else {
    die;
}

$query_string = "openid.mode=id_res&openid.assert_identity=http://bradfitz.com/fake-identity/&openid.sig=MCwCFCi%2BYw3vVwjujVVO%2Bh2KIlFs0hr1AhRhNl%2BQJfu685Cs7BxmDwH050ShNQ%3D%3D&openid.timestamp=2005-05-21T21:32:46Z&openid.return_to=http://www.danga.com/openid/demo/helper.bml";
%get_vars = map { durl($_) } split(/[&=]/, $query_string);

ok(! $csr->user_setup_url);

my $vident = $csr->verified_identity
    or die $csr->err . ": " . $csr->errtext;
ok($vident);

# see if it found the profile info
ok(! $vident->foaf);  # wasn't under the root
ok(  $vident->declared_foaf eq "http://brad.livejournal.com/data/foaf");
ok(  $vident->foafmaker    eq "foaf:mbox_sha1sum '4caa1d6f6203d21705a00a7aca86203e82a9cf7a'");

ok($vident->rss  eq "http://bradfitz.com/fake-identity/rss.xml");
ok($vident->atom eq "http://bradfitz.com/fake-identity/dir/atom.xml");

# get a display URL
ok($vident->display eq "http://bradfitz.com/fake-identity/");
ok(Net::OpenID::VerifiedIdentity::DisplayOfURL("http://bradfitz.com/") eq "bradfitz.com");
ok(Net::OpenID::VerifiedIdentity::DisplayOfURL("http://bradfitz.com/users/bob/") eq "bob [bradfitz.com]");
ok(Net::OpenID::VerifiedIdentity::DisplayOfURL("http://www.foo.com/~hacker") eq "hacker [foo.com]");
ok(Net::OpenID::VerifiedIdentity::DisplayOfURL("http://aol.com/members/mary/") eq "mary [aol.com]");



sub durl
{
    my ($a) = @_;
    $a =~ tr/+/ /;
    $a =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
    return $a;
}
