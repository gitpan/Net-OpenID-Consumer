# LICENSE: You're free to distribute this under the same terms as Perl itself.

use strict;
use Carp ();
use LWP::UserAgent;

############################################################################
package Net::OpenID::Consumer;

use vars qw($VERSION $HAS_CRYPT_DSA $HAS_CRYPT_OPENSSL $HAS_OPENSSL);
$VERSION = "0.03";

use fields (
            'cacher',         # the Net::OpenID::Cacher::* class to remember mapping of OpenID -> Identity Server
            'ua',             # LWP::UserAgent instance to use
            'args',           # how to get at your args
            'server_selector',# optional subref that will pick which identity server to use, if multiple 
            'last_errcode',   # last error code we got
            'last_errtext',   # last error code we got
            );

use Net::OpenID::ClaimedIdentity;
use Net::OpenID::VerifiedIdentity;
use MIME::Base64 ();
use Digest::SHA1 ();

BEGIN {
    unless ($HAS_CRYPT_OPENSSL = eval "use Crypt::OpenSSL::DSA 0.12; 1;") {
        unless ($HAS_CRYPT_DSA = eval "die 'FIXME_BELOW'; use Crypt::DSA (); use Convert::PEM; 1;") {
            unless ($HAS_OPENSSL = `which openssl`) {
                die "Net::OpenID::Consumer failed to load, due to missing dependencies.  You to have Crypt::OpenSSL::DSA -or- the binary 'openssl' in your path.";
            }
        }
    }
}

sub new {
    my Net::OpenID::Consumer $self = shift;
    $self = fields::new( $self ) unless ref $self;
    my %opts = @_;

    $self->{cacher} = undef;
    $self->{ua} = delete $opts{ua};
    $self->args(delete $opts{args});

    $self->{last_errcode} = undef;
    $self->{last_errtext} = undef;

    Carp::croak("Unknown options: " . join(", ", keys %opts)) if %opts;
    return $self;
}

sub cacher {
    my Net::OpenID::Consumer $self = shift;
    $self->{cacher} = shift if @_;
    $self->{cacher};
}

# given something that can have GET arguments, returns a subref to get them:
#   Apache
#   Apache::Request
#   CGI
#   HASH of get args
#   CODE returning get arg, given key

#   ...

sub args {
    my Net::OpenID::Consumer $self = shift;

    if (my $what = shift) {
        Carp::croak("Too many parameters") if @_;
        my $getter;
        if (! ref $what){
            Carp::croak("No args defined") unless $self->{args};
            return $self->{args}->($what);
        } elsif (ref $what eq "HASH") {
            $getter = sub { $what->{$_[0]}; };
        } elsif (ref $what eq "CGI") {
            $getter = sub { scalar $what->param($_[0]); };
        } elsif (ref $what eq "Apache") {
            my %get = $what->args;
            $getter = sub { $get{$_[0]}; };
        } elsif (ref $what eq "Apache::Request") {
            $getter = sub { scalar $what->param($_[0]); };
        } elsif (ref $what eq "CODE") {
            $getter = $what;
        } else {
            Carp::croak("Unknown parameter type ($what)");
        }
        if ($getter) {
            $self->{args} = $getter;
        }
    }
    $self->{args};
}

sub server_selector {
    my Net::OpenID::Consumer $self = shift;
    if (@_) {
        my $code = shift;
        Carp::croak("Too many parameters") if @_;
        Carp::croak("Not a CODE ref") unless ref $code eq "CODE";
        $self->{server_selector} = $code;
    }
    $self->{server_selector};
}

sub ua {
    my Net::OpenID::Consumer $self = shift;
    $self->{ua} = shift if @_;
    Carp::croak("Too many parameters") if @_;

    # make default one on first access
    unless ($self->{ua}) {
        my $ua = $self->{ua} = LWP::UserAgent->new;
        $ua->timeout(10);
    }

    $self->{ua};
}

sub _fail {
    my Net::OpenID::Consumer $self = shift;
    $self->{last_errcode} = shift;
    $self->{last_errtext} = shift;
    wantarray ? () : undef;
}

sub json_err {
    my Net::OpenID::Consumer $self = shift;
    return OpenID::util::js_dumper({
        err_code => $self->{last_errcode},
        err_text => $self->{last_errtext},
    });
}

sub err {
    my Net::OpenID::Consumer $self = shift;
    $self->{last_errcode} . ": " . $self->{last_errtext};
}

sub errcode {
    my Net::OpenID::Consumer $self = shift;
    $self->{last_errcode};
}

sub errtext {
    my Net::OpenID::Consumer $self = shift;
    $self->{last_errtext};
}

sub _get_url_contents {
    my Net::OpenID::Consumer $self = shift;
    my $url = shift;
    my $final_url_ref = shift;

    # FIXME: use cacher

    my $res = $self->ua->get($url);
    if ($res->is_success) {
        $$final_url_ref = $res->request->uri->as_string;
        return $res->content;
    }
    return $self->_fail("url_fetch_error", "Error fetching URL: " . $res->status_line);
}

sub _pick_identity_server {
    my Net::OpenID::Consumer $self = shift;
    my $id_server_list = shift;

    if (my $hook = $self->{server_selector}) {
        return $hook->($self, $id_server_list);
    }

    # default just picks first one.
    return $id_server_list->[0];
}

sub _find_openid_servers {
    my Net::OpenID::Consumer $self = shift;
    my $url = shift;
    my $final_url_ref = shift;

    my $doc = $self->_get_url_contents($url, $final_url_ref) or
        return;

    # find <head> content of document (notably: the first head, if
    # there are multiple from attackers)
    return $self->_fail("no_head_tag", "Couldn't find OpenID servers due to no head tag")
        unless $doc =~ m!<head[^>]*>(.*)</head>!is;
    my $head = $1;

    my @id_servers;
    while ($head =~ m!<link([^>]+)>!g) {
        my $link = $1;
        if ($link =~ /rel=.openid\.server./i &&
            $link =~ m!href=[\"\']([^\"\']+)[\"\']!i) {
            push @id_servers, $1;
        }
    }

    return $self->_fail("no_identity_servers") unless @id_servers;
    @id_servers;
}

# returns Net::OpenID::ClaimedIdentity
sub claimed_identity {
    my Net::OpenID::Consumer $self = shift;
    my $url = shift;
    Carp::croak("Too many parameters") if @_;

    # trim whitespace
    $url =~ s/^\s+//;
    $url =~ s/\s+$//;
    return helper_error("empty_url", "Empty URL") unless $url;

    # do basic canonicalization
    $url = "http://$url" if $url && $url !~ m!^\w+://!;
    return helper_error("bogus_url", "Invalid URL") unless $url =~ m!^http://!;
    # add a slash, if none exists
    $url .= "/" unless $url =~ m!^http://.+/!;

    my $final_url;
    my @id_servers = $self->_find_openid_servers($url, \$final_url)
        or return;

    return Net::OpenID::ClaimedIdentity->new(
                                             identity => $final_url,
                                             servers => \@id_servers,
                                             consumer => $self,
                                             );
}


sub user_setup_url {
    my Net::OpenID::Consumer $self = shift;
    Carp::croak("Too many parameters") if @_;

    return $self->_fail("bad_mode") unless $self->args("openid.mode") eq "id_res";
    return $self->args("openid.user_setup_url");
}

sub verified_identity {
    my Net::OpenID::Consumer $self = shift;
    Carp::croak("Too many parameters") if @_;

    return $self->_fail("bad_mode") unless $self->args("openid.mode") eq "id_res";

    my $sig64 = $self->args("openid.sig")             or return $self->_fail("no_sig");
    my $url   = $self->args("openid.assert_identity") or return $self->_fail("no_identity");
    my $retto = $self->args("openid.return_to")       or return $self->_fail("no_return_to");

    # present and valid
    my $ts  = $self->args("openid.timestamp");
    $ts =~ /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/ or return $self->_fail("malformed_timestamp");

    # make the raw string that we're going to check the signature against
    my $msg_plain = join("::",
                         $ts,
                         "assert_identity",
                         $url,
                         $retto);

    # to verify the signature, we need to fetch the public key, which
    # means we need to figure out what identity server to get the public
    # key from.  because there might be multiple, we'd previously
    # passed to ourselves the index that we chose.  so first go
    # re-fetch (possibly from cache) the page, re-find the acceptable
    # identity servers for this user, and get the public key
    my $final_url;
    my @id_servers = $self->_find_openid_servers($url, \$final_url)
        or return undef;

    return $self->_fail("identity_changed_on_fetch")
        if $url ne $final_url;

    my $used_idx = int($self->args("oicsr.idx") || 0);
    return $self->_fail("bad_idx")
        if $used_idx < 0 || $used_idx > 50;

    my $id_server = $id_servers[$used_idx]
        or return $self->_fail("identity_server_idx_empty");

    my $pem_url = $id_server;
    $pem_url .= ($id_server =~ /\?/) ? "&" : "?";
    $pem_url .= "openid.mode=getpubkey";

    my $msg = Digest::SHA1::sha1($msg_plain);
    my $sig = MIME::Base64::decode_base64($sig64);

    # TODO: foreach my $mode ("cached", "no_cache")
    my $public_pem = $self->_get_url_contents($pem_url)
        or return $self->_fail("public_key_fetch_error", "Details: " . $self->err);

    $self->_dsa_verify($public_pem, $sig, $msg, $msg_plain)
        or return undef;

    # FIXME: nonce callback
    return Net::OpenID::VerifiedIdentity->new(
                                              identity => $url,
                                              );
}

sub _dsa_verify {
    my ($self, $public_pem, $sig, $msg, $msg_plain) = @_;

    if ($HAS_CRYPT_OPENSSL) {
        my $dsa_pub  = Crypt::OpenSSL::DSA->read_pub_key_str($public_pem)
            or $self->_fail("pubkey_parse_error", "Couldn't parse public key");
        $dsa_pub->verify($msg, $sig)
            or return $self->_fail("verify_failed", "DSA signature verification failed");
        return 1;
    }

    if ($HAS_CRYPT_DSA) {
        my $cd = Crypt::DSA->new;

        my ($len, $len_r, $len_s, $r, $s);
        unless ($sig =~ /^\x30/ &&
                ($len = ord(substr($sig,1,1))) &&
                substr($sig,2,1) eq "\x02" &&
                ($len_r =  ord(substr($sig,3,1))) &&
                ($r = substr($sig,4,$len_r)) &&
                substr($sig,4+$len_r,1) eq "\x02" &&
                ($len_s =  ord(substr($sig,5+$len_r,1))) &&
                ($s = substr($sig,6+$len_r,$len_s))) {
            return $self->_fail("asn1_parse_error", "Failed to parse ASN.1 signature");
        }

        my $sigobj = Crypt::DSA::Signature->new;
        $sigobj->r("0x" . unpack("H40", $r));
        $sigobj->s("0x" . unpack("H40", $s));


        die "#### FIXME: Crypt::DSA::Key only parses private keys.  Need to fix it.";

        my $key =  Crypt::DSA::Key->new(
                                        Type => "PEM",
                                        Content => $public_pem,
                                        )
            or return $self->_fail("pubkey_parse_error", "Couldn't generate Crypt::DSA::Key from PEM");

        $cd->verify(
                    Digest    => $msg,
                    Signature => $sigobj,
                    Key       => $key,
                    )
            or return $self->_fail("verify_failed", "DSA signature verification failed");
        return 1;
    }

    if ($HAS_OPENSSL) {
        require File::Temp;
        my $sig_temp = new File::Temp(TEMPLATE => "tmp.signatureXXXX") or die;
        my $pub_temp = new File::Temp(TEMPLATE => "tmp.pubkeyXXXX") or die;
        my $msg_temp = new File::Temp(TEMPLATE => "tmp.msgXXXX") or die;
        syswrite($sig_temp,$sig);
        syswrite($pub_temp,$public_pem);
        syswrite($msg_temp,$msg_plain);

        my $pid = open(my $fh, '-|', "openssl", "dgst", "-dss1", "-verify", "$pub_temp", "-signature", "$sig_temp", "$msg_temp");
        return $self->_fail("no_openssl", "OpenSSL not available") unless defined $pid;
        my $line = <$fh>;
        close($fh);
        return $self->_fail("verify_failed", "DSA signature verification failed") if $line =~ /Verification OK/;
        return 1;

        # More portable form, but spews to stdout:
        #my $rv = system("openssl", "dgst", "-dss1", "-verify", "$pub_temp", "-signature", "$sig_temp", "$msg_temp");
        #return $self->_fail("verify_failed", "DSA signature verification failed") if $rv;
        #return 1;
    }

    return 0;
}

package OpenID::util;

sub ejs
{
    my $a = $_[0];
    $a =~ s/[\"\'\\]/\\$&/g;
    $a =~ s/\r?\n/\\n/gs;
    $a =~ s/\r//;
    return $a;
}

# Data::Dumper for JavaScript
sub js_dumper {
    my $obj = shift;
    if (ref $obj eq "HASH") {
        my $ret = "{";
        foreach my $k (keys %$obj) {
            $ret .= "$k: " . js_dumper($obj->{$k}) . ",";
        }
        chop $ret;
        $ret .= "}";
        return $ret;
    } elsif (ref $obj eq "ARRAY") {
        my $ret = "[" . join(", ", map { js_dumper($_) } @$obj) . "]";
        return $ret;
    } else {
        return $obj if $obj =~ /^\d+$/;
        return "\"" . ejs($obj) . "\"";
    }
}

sub eurl
{
    my $a = $_[0];
    $a =~ s/([^a-zA-Z0-9_\,\-.\/\\\: ])/uc sprintf("%%%02x",ord($1))/eg;
    $a =~ tr/ /+/;
    return $a;
}

__END__

=head1 NAME

Net::OpenID::Consumer - library for consumers of OpenID identities

=head1 SYNOPSIS

  use Net::OpenID::Consumer;

  my $csr = Net::OpenID::Consumer->new;

  # set the user-agent (defaults to LWP::UserAgent, which isn't safe)
  $csr->ua(LWPx::ParanoidAgent->new);

  # set how the consumer gets to your web environment's GET arguments
  $csr->args(\%hash);   # hashref of get args/values
  $csr->args($r);       # Apache
  $csr->args($aprreq);  # Apache::Request
  $csr->args($cgi);     # CGI.pm
  $csr->args(sub {});   # subref that returns value, given arg

  # a user entered, say, "bradfitz.com" as their identity.  The first
  # step is to fetch that page, parse it, and get a
  # Net::OpenID::ClaimedIdentity object:

  my $claimed_identity = $csr->claimed_identity("bradfitz.com");

  # now your app has to send them at their identity server's endpoint
  # to get redirected to either a positive assertion that they own
  # that identity, or where they need to go to login/setup trust/etc.

  my $check_url = $claimed_identity->check_url(
    return_to  => "http://example.com/openid-check.app?yourarg=val",
    post_grant => "close",
    trust_root => "http://example.com/",
  );

  # so you send the user off there, and then they come back to
  # openid-check.app, then you see what the identity server said;

  if (my $setup_url = $csr->user_setup_url) {
       # redirect/link/popup user to $setup_url
  } elsif (my $vident = $csr->verified_identity) {
       my $verified_url = $vident->url;
       print "You are $verified_url !";
  } else {
       die "Error validating identity: " . $csr->err;
  }


=head1 DESCRIPTION

This is the Perl API for (the consumer half of) OpenID, a distributed
identity system based on proving you own a URL, which is then your
identity.  More information is available at:

  http://www.danga.com/openid/

=head1 CONSTRUCTOR

=over 4

=item C<new>

my $csr = Net::OpenID::Consumer->new([ %opts ]);

You can set the C<ua> and C<args> in the constructor.

=back

=head1 METHODS

=over 4

=item $csr->B<ua>($user_agent)

=item $csr->B<ua>

Getter/setter for the LWP::UserAgent (or subclass) instance which will
be used when web donwloads are needed.  It's highly recommended that
you use LWPx::ParanoidAgent, or at least read its documentation so
you're aware of why you should care.

=item $csr->B<args>($ref)

=item $csr->B<args>($param)

=item $csr->B<args>

Can be used in 1 of 3 ways:

1. Setting the way which the Consumer instances obtains GET parameters:

$csr->args( $reference )

Where $reference is either a HASH ref, CODE ref, Apache $r,
Apache::Request $apreq, or CGI.pm $cgi.  If a CODE ref, the subref
must return the value given one argument (the parameter to retrieve)

2. Get a paramater:

my $foo = $csr->args("foo");

When given an unblessed scalar, it retrieves the value.  It croaks if
you haven't defined a way to get at the parameters.

3. Get the getter:

my $code = $csr->args;

Without arguments, returns a subref that returns the value given a
parameter name.

=item $csr->B<claimed_identity>($url)

Given a user-entered $url (which could be missing http://, or have
extra whitespace, etc), returns either a Net::OpenID::ClaimedIdentity
object, or undef on failure.

Note that this identity is NOT verified yet.  It's only who the user
claims they are, but they could be lying.

=item $csr->B<user_setup_url>

Returns the URL the user must return to in order to login, setup trust,
or do whatever the identity server needs them to do in order to make
the identity assertion which they previously initiated by entering
their claimed identity URL.  Returns undef if this setup URL isn't
required, in which case you should ask for the verified_identity

=item $csr->B<verified_identity>

Returns a Net::OpenID::VerifiedIdentity object, or undef.
Verification includes double-checking the reported identity URL
declares the identity server, getting the DSA public key, verifying
the signature, etc.

=item $csr->B<server_selector>

Get/set the optional subref that selects which openid server to check
against, if the user has declared multiple.  By default, if no
server_selector is declared, the first is always chosen.

=item $csr->B<err>

Returns the last error, in form "errcode: errtext";

=item $csr->B<errcode>

Returns the last error code.

=item $csr->B<errtext>

Returns the last error text.

=item $csr->B<json_err>

Returns the last error code/text in JSON format.

=item $csr->B<json_err>

Returns the last error code/text in JSON format.

=back

=head1 COPYRIGHT

This module is Copyright (c) 2005 Brad Fitzpatrick.
All rights reserved.

You may distribute under the terms of either the GNU General Public
License or the Artistic License, as specified in the Perl README file.
If you need more liberal licensing terms, please contact the
maintainer.

=head1 WARRANTY

This is free software. IT COMES WITHOUT WARRANTY OF ANY KIND.

=head1 SEE ALSO

OpenID website:  http://www.danga.com/openid/

=head1 AUTHORS

Brad Fitzpatrick <brad@danga.com>

