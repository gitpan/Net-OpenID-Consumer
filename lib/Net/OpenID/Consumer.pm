# LICENSE: You're free to distribute this under the same terms as Perl itself.

use strict;
use Carp ();

############################################################################
package Net::OpenID::Consumer;
BEGIN {
  $Net::OpenID::Consumer::VERSION = '1.100099_001';
}


use fields (
    'cache',           # a Cache object to store HTTP responses and associations
    'ua',              # LWP::UserAgent instance to use
    'args',            # how to get at your args
    'message',         # args interpreted as an IndirectMessage, if possible
    'consumer_secret', # scalar/subref
    'required_root',   # the default required_root value, or undef
    'last_errcode',    # last error code we got
    'last_errtext',    # last error code we got
    'debug',           # debug flag or codeblock
    'minimum_version', # The minimum protocol version to support
    'assoc_options',   # options for establishing server associations
);

use Net::OpenID::ClaimedIdentity;
use Net::OpenID::VerifiedIdentity;
use Net::OpenID::Association;
use Net::OpenID::Yadis;
use Net::OpenID::IndirectMessage;
use Net::OpenID::URIFetch;
use Net::OpenID::Common; # To get the OpenID::util package

use MIME::Base64 ();
use Digest::SHA qw(hmac_sha1_hex);
use Time::Local;
use HTTP::Request;
use LWP::UserAgent;
use Storable;
use JSON qw(encode_json);
use URI::Escape qw(uri_escape);
use HTML::Parser;

sub new {
    my Net::OpenID::Consumer $self = shift;
    $self = fields::new( $self ) unless ref $self;
    my %opts = @_;

    $self->{ua}            = delete $opts{ua};
    $self->args            ( delete $opts{args}            );
    $self->cache           ( delete $opts{cache}           );
    $self->consumer_secret ( delete $opts{consumer_secret} );
    $self->required_root   ( delete $opts{required_root}   );
    $self->minimum_version ( delete $opts{minimum_version} );
    $self->assoc_options   ( delete $opts{assoc_options}   );

    $self->{debug} = delete $opts{debug};

    Carp::croak("Unknown options: " . join(", ", keys %opts)) if %opts;
    return $self;
}

# NOTE: This method is here only to support the openid-test library.
# Don't call it from anywhere else, or you'll break when it gets
# removed. Instead, call minimum_version(2).
# FIXME: Can we just make openid-test do that and get rid of this?
sub disable_version_1 {
    $_[0]->minimum_version(2);
}

sub cache           { &_getset; }
sub consumer_secret { &_getset; }
sub required_root   { &_getset; }

sub _getset {
    my Net::OpenID::Consumer $self = shift;
    my $param = (caller(1))[3];
    $param =~ s/.+:://;

    if (@_) {
        my $val = shift;
        Carp::croak("Too many parameters") if @_;
        $self->{$param} = $val;
    }
    return $self->{$param};
}

sub minimum_version {
    my Net::OpenID::Consumer $self = shift;

    if (@_) {
        my $minv = shift;
        Carp::croak("Too many parameters") if @_;
        $minv = 1 unless $minv && $minv > 1;
        $self->{minimum_version} = $minv;
    }
    return $self->{minimum_version};
}

sub assoc_options {
    my Net::OpenID::Consumer $self = shift;
    my $v;
    if (scalar(@_) == 1) {
        $v = shift;
        unless ($v) {
            $v = {};
        }
        elsif (ref $v eq 'ARRAY') {
            $v = {@$v};
        }
        elsif (ref $v) {
            # assume it's a hash and hope for the best
            $v = {%$v};
        }
        else {
            Carp::croak("single argument must be HASH or ARRAY reference");
        }
        $self->{assoc_options} = $v;
    }
    elsif (@_) {
        Carp::croak("odd number of parameters?")
            if scalar(@_)%2;
        $self->{assoc_options} = {@_};
    }
    return $self->{assoc_options};
}

sub _debug {
    my Net::OpenID::Consumer $self = shift;
    return unless $self->{debug};

    if (ref $self->{debug} eq "CODE") {
        $self->{debug}->($_[0]);
    } else {
        print STDERR "[DEBUG Net::OpenID::Consumer] $_[0]\n";
    }
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
        unless (ref $what) {
            return $self->{args} ? $self->{args}->($what) : Carp::croak("No args defined");
        }
        Carp::croak("Too many parameters") if @_;

        # since we do not require field setters to be called in any particular order,
        # we cannot pass minimum_version here as it might change later.
        my $message = Net::OpenID::IndirectMessage->new($what);
        $self->{message} = $message;
        if ($message) {
            $self->{args} = $message->getter;

            # handle OpenID 2.0 'error' mode
            # (may as well do this here; we may not get another chance
            # since handle_server_response is not a required part of the API)
            if ($message->protocol_version >= 2 && $message->mode eq 'error') {
                $self->_fail('provider_error',$message->get('error'));
            }
        }
        else {
            $self->{args} = sub { undef };
        }
    }
    $self->{args};
}

sub message {
    my Net::OpenID::Consumer $self = shift;
    my $message = $self->{message};
    return undef
      unless $message &&
        ($self->{minimum_version} <= $message->protocol_version);

    if (@_) {
        return $message->get($_[0]);
    }
    else {
        return $message;
    }
}

sub _message_mode_is {
    return (($_[0]->message('mode')||' ') eq $_[1]);
}

sub _message_version {
    my $message = $_[0]->message;
    return $message ? $message->protocol_version : 0;
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

our %Error_text =
   (
    'bad_mode'                    => "The openid.mode argument is not correct",
    'bogus_return_to'             => "Return URL does not match required_root.",
    'bogus_url'                   => "URL scheme must be http: or https:",
    'empty_url'                   => "No URL entered.",
    'expired_association'         => "Association between ID provider and relying party has expired.",
    'naive_verify_failed_network' => "Could not contact ID provider to verify response.",
    'naive_verify_failed_return'  => "Direct contact invalidated ID provider response.",
    'no_head_tag'                 => "Could not determine ID provider; URL document has no <head>.",
    'no_identity'                 => "Identity is missing from ID provider response.",
    'no_identity_server'          => "Could not determine ID provider from URL.",
    'no_return_to'                => "Return URL is missing from ID provider response.",
    'no_sig'                      => "Signature is missing from ID provider response.",
    'protocol_version_incorrect'  => "ID provider does not support minimum protocol version",
    'provider_error'              => "ID provider-specific error",
    'signature_mismatch'          => "Prior association invalidated ID provider response.",
    'time_bad_sig'                => "Return_to signature is not valid.",
    'time_expired'                => "Return_to signature is stale.",
    'time_in_future'              => "Return_to signature is from the future.",
    'unsigned_field'              => sub { "Field(s) must be signed: " . join(", ", @_) },
    'url_fetch_err'               => "Error fetching the provided URL.",
   );

sub _fail {
    my Net::OpenID::Consumer $self = shift;
    my ($code, $text, @params) = @_;

    # 'bad_mode' is only an error if we survive to the end of
    # .mode dispatch without having figured out what to do;
    # it should not overwrite other errors.
    unless ($self->{last_errcode} && $code eq 'bad_mode') {
        $text ||= $Error_text{$code};
        $text = $text->(@params) if ref($text) && ref($text) eq 'CODE';
        $self->{last_errcode} = $code;
        $self->{last_errtext} = $text;
        $self->_debug("fail($code) $text");
    }
    wantarray ? () : undef;
}

sub json_err {
    my Net::OpenID::Consumer $self = shift;
    return encode_json({
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

# make sure you change the $prefix every time you change the $hook format
# so that when user installs a new version and the old cache server is
# still running the old cache entries won't confuse things.
sub _get_url_contents {
    my Net::OpenID::Consumer $self = shift;
    my ($url, $final_url_ref, $hook, $prefix) = @_;
    $final_url_ref ||= do { my $dummy; \$dummy; };

    my $res = Net::OpenID::URIFetch->fetch($url, $self, $hook, $prefix);

    $$final_url_ref = $res->final_uri;

    return $res ? $res->content : undef;
}


# List of head elements that matter for HTTP discovery.
# Each entry defines a key+value that will appear in the
# _find_semantic_info hash if the specified element exists
#  [
#    FSI_KEY    -- key name
#    TAG_NAME   -- must be 'link' or 'meta'
#
#    ELT_VALUES -- string (default = FSI_KEY)
#            what join(';',values of ELT_KEYS) has to match
#            in order for a given html element to provide
#            the value for FSI_KEY
#
#    ELT_KEYS   -- list-ref of html attribute names
#            default = ['rel']  for <link...>
#            default = ['name'] for <meta...>
#
#    FSI_VALUE  -- name of html attribute where value lives
#            default = 'href'    for <link...>
#            default = 'content' for <meta...>
#  ]
#
our @HTTP_discovery_link_meta_tags =
  map {
      my ($fsi_key, $tag, $elt_value, $elt_keys, $fsi_value) = @{$_};
      [$fsi_key, $tag,
       $elt_value || $fsi_key,
       $elt_keys  || [$tag eq 'link' ? 'rel'  : 'name'],
       $fsi_value || ($tag eq 'link' ? 'href' : 'content'),
      ]
  }
   # OpenID servers / delegated identities
   # <link rel="openid.server"
   #       href="http://www.livejournal.com/misc/openid.bml" />
   # <link rel="openid.delegate"
   #       href="whatever" />
   #
   [qw(openid.server    link)], # 'openid.server' => ['rel'], 'href'
   [qw(openid.delegate  link)],

   # OpenID2 providers / local identifiers
   # <link rel="openid2.provider"
   #       href="http://www.livejournal.com/misc/openid.bml" />
   # <link rel="openid2.local_id" href="whatever" />
   #
   [qw(openid2.provider  link)],
   [qw(openid2.local_id  link)],

   # FOAF maker info
   # <meta name="foaf:maker"
   #  content="foaf:mbox_sha1sum '4caa1d6f6203d21705a00a7aca86203e82a9cf7a'"/>
   #
   [qw(foaf.maker  meta  foaf:maker)], # == .name

   # FOAF documents
   # <link rel="meta" type="application/rdf+xml" title="FOAF"
   #       href="http://brad.livejournal.com/data/foaf" />
   #
   [qw(foaf link), 'meta;foaf;application/rdf+xml' => [qw(rel title type)]],

   # RSS
   # <link rel="alternate" type="application/rss+xml" title="RSS"
   #       href="http://www.livejournal.com/~brad/data/rss" />
   #
   [qw(rss link), 'alternate;application/rss+xml' => [qw(rel type)]],

   # Atom
   # <link rel="alternate" type="application/atom+xml" title="Atom"
   #       href="http://www.livejournal.com/~brad/data/rss" />
   #
   [qw(atom link), 'alternate;application/atom+xml' => [qw(rel type)]],
  ;

sub _document_to_semantic_info {
    my $doc = shift;
    my $info = {};

    my $elts = OpenID::util::html_extract_linkmetas($doc);
    for (@HTTP_discovery_link_meta_tags) {
        my ($key, $tag, $string, $attribs, $vattrib) = @$_;
        for my $lm (@{$elts->{$tag}}) {
            $info->{$key} = $lm->{$vattrib}
              if $string eq join ';', map {lc($lm->{$_})} @$attribs;
        }
    }
    return $info;
}

sub _find_semantic_info {
    my Net::OpenID::Consumer $self = shift;
    my $url = shift;
    my $final_url_ref = shift;

    my $doc = $self->_get_url_contents($url, $final_url_ref);
    my $info = _document_to_semantic_info($doc);
    $self->_debug("semantic info ($url) = " . join(", ", map { $_.' => '.$info->{$_} } keys %$info)) if $self->{debug};

    return $info;
}

sub _find_openid_server {
    my Net::OpenID::Consumer $self = shift;
    my $url = shift;
    my $final_url_ref = shift;

    my $sem_info = $self->_find_semantic_info($url, $final_url_ref) or
        return;

    return $self->_fail("no_identity_server") unless $sem_info->{"openid.server"};
    $sem_info->{"openid.server"};
}

sub is_server_response {
    my Net::OpenID::Consumer $self = shift;
    return $self->message ? 1 : 0;
}

my $_warned_about_setup_required = 0;
sub handle_server_response {
    my Net::OpenID::Consumer $self = shift;
    my %callbacks_in = @_;
    my %callbacks = ();

    foreach my $cb (qw(not_openid cancelled verified error)) {
        $callbacks{$cb} = delete($callbacks_in{$cb}) || sub { Carp::croak("No ".$cb." callback") };
    }

    # backwards compatibility:
    #   'setup_needed' is expected as of 1.04
    #   'setup_required' is deprecated but allowed in its place,
    my $found_setup_callback = 0;
    foreach my $cb (qw(setup_needed setup_required)) {
        $callbacks{$cb} = delete($callbacks_in{$cb}) and $found_setup_callback++;
    }
    Carp::croak($found_setup_callback > 1
                ? "Cannot have both setup_needed and setup_required"
                : "No setup_needed callback")
        unless $found_setup_callback == 1;

    if (warnings::enabled('deprecated') &&
        $callbacks{setup_required} &&
        !$_warned_about_setup_required++
       ) {
        warnings::warn
            ("deprecated",
             "'setup_required' callback is deprecated, use 'setup_needed'");
    }

    Carp::croak("Unknown callbacks:  ".join(',', keys %callbacks_in))
        if %callbacks_in;

    unless ($self->is_server_response) {
        return $callbacks{not_openid}->();
    }

    if ($self->setup_needed) {
        return $callbacks{setup_needed}->()
          unless ($callbacks{setup_required});

        my $setup_url = $self->user_setup_url;
        return $callbacks{setup_required}->($setup_url)
          if $setup_url;
        # otherwise FALL THROUGH to preserve prior behavior,
        # Even though this is broken, old clients could have
        # put a workaround into the 'error' callback to handle
        # the setup_needed+(setup_url=undef) case
    }

    if ($self->user_cancel) {
        return $callbacks{cancelled}->();
    }
    elsif (my $vident = $self->verified_identity) {
        return $callbacks{verified}->($vident);
    }
    else {
        return $callbacks{error}->($self->errcode, $self->errtext);
    }

}

sub _discover_acceptable_endpoints {
    my Net::OpenID::Consumer $self = shift;
    my $url = shift;
    my %opts = @_;

    # if return_early is set, we'll return as soon as we have enough
    # information to determine the "primary" endpoint, and return
    # that as the first (and possibly only) item in our response.
    my $primary_only = delete $opts{primary_only} ? 1 : 0;

    my $force_version = delete $opts{force_version};

    Carp::croak("Unknown option(s) ".join(', ', keys(%opts))) if %opts;

    # trim whitespace
    $url =~ s/^\s+//;
    $url =~ s/\s+$//;
    return $self->_fail("empty_url") unless $url;

    # do basic canonicalization
    $url = "http://$url" if $url && $url !~ m!^\w+://!;
    return $self->_fail("bogus_url") unless $url =~ m!^https?://!i;
    # add a slash, if none exists
    $url .= "/" unless $url =~ m!^https?://.+/!i;

    my @discovered_endpoints = ();
    my $result = sub {
        # We always prefer 2.0 endpoints to 1.1 ones, regardless of
        # the priority chosen by the identifier.
        return [
            (grep { $_->{version} == 2 } @discovered_endpoints),
            (grep { $_->{version} == 1 } @discovered_endpoints),
        ];
    };

    # TODO: Support XRI too?

    # First we Yadis service discovery
    my $yadis = Net::OpenID::Yadis->new(consumer => $self);
    if ($yadis->discover($url)) {
        # FIXME: Currently we don't ever do _find_semantic_info in the Yadis
        # code path, so an extra redundant HTTP request is done later
        # when the semantic info is accessed.

        my $final_url = $yadis->identity_url;
        my @services = $yadis->services(
            OpenID::util::version_2_xrds_service_url(),
            OpenID::util::version_2_xrds_directed_service_url(),
            OpenID::util::version_1_xrds_service_url(),
        );
        my $version2 = OpenID::util::version_2_xrds_service_url();
        my $version1 = OpenID::util::version_1_xrds_service_url();
        my $version2_directed = OpenID::util::version_2_xrds_directed_service_url();

        foreach my $service (@services) {
            my $service_uris = $service->URI;

            # Service->URI seems to return all sorts of bizarre things, so let's
            # normalize it to always be an arrayref.
            if (ref($service_uris) eq 'ARRAY') {
                my @sorted_id_servers = sort {
                    my $pa = $a->{priority};
                    my $pb = $b->{priority};
                    return 0 unless defined($pa) || defined($pb);
                    return -1 unless defined ($pb);
                    return 1 unless defined ($pa);
                    return $a->{priority} <=> $b->{priority}
                } @$service_uris;
                $service_uris = \@sorted_id_servers;
            }
            if (ref($service_uris) eq 'HASH') {
                $service_uris = [ $service_uris->{content} ];
            }
            unless (ref($service_uris)) {
                $service_uris = [ $service_uris ];
            }

            my $delegate = undef;
            my @versions = ();

            if (grep(/^${version2}$/, $service->Type)) {
                # We have an OpenID 2.0 end-user identifier
                $delegate = $service->extra_field("LocalID");
                push @versions, 2;
            }
            if (grep(/^${version1}$/, $service->Type)) {
                # We have an OpenID 1.1 end-user identifier
                $delegate = $service->extra_field("Delegate", "http://openid.net/xmlns/1.0");
                push @versions, 1;
            }

            if (@versions) {
                foreach my $version (@versions) {
                    next if defined($force_version) && $force_version != $version;
                    foreach my $uri (@$service_uris) {
                        push @discovered_endpoints, {
                            uri => $uri,
                            version => $version,
                            final_url => $final_url,
                            delegate => $delegate,
                            sem_info => undef,
                            mechanism => "Yadis",
                        };
                    }
                }
            }

            if (grep(/^${version2_directed}$/, $service->Type)) {
                # We have an OpenID 2.0 OP identifier (i.e. we're doing directed identity)
                my $version = 2;
                # In this case, the user's claimed identifier is a magic value
                # and the actual identifier will be determined by the provider.
                my $final_url = OpenID::util::version_2_identifier_select_url();
                my $delegate = OpenID::util::version_2_identifier_select_url();

                foreach my $uri (@$service_uris) {
                    push @discovered_endpoints, {
                        uri => $uri,
                        version => $version,
                        final_url => $final_url,
                        delegate => $delegate,
                        sem_info => undef,
                        mechanism => "Yadis",
                    };
                }
            }

            if ($primary_only && scalar(@discovered_endpoints)) {
                # We've got at least one endpoint now, so return early
                return $result->();
            }
        }
    }

    # Now HTML-based discovery, both 2.0- and 1.1-style.
    {
        my $final_url = undef;
        my $sem_info = $self->_find_semantic_info($url, \$final_url);

        if ($sem_info) {
            if ($sem_info->{"openid2.provider"}) {
                unless (defined($force_version) && $force_version != 2) {
                    push @discovered_endpoints, {
                        uri => $sem_info->{"openid2.provider"},
                        version => 2,
                        final_url => $final_url,
                        delegate => $sem_info->{"openid2.local_id"},
                        sem_info => $sem_info,
                        mechanism => "HTML",
                    };
                }
            }
            if ($sem_info->{"openid.server"}) {
                unless (defined($force_version) && $force_version != 1) {
                    push @discovered_endpoints, {
                        uri => $sem_info->{"openid.server"},
                        version => 1,
                        final_url => $final_url,
                        delegate => $sem_info->{"openid.delegate"},
                        sem_info => $sem_info,
                        mechanism => "HTML",
                    };
                }
            }
        }
    }

    return $result->();

}

# returns Net::OpenID::ClaimedIdentity
sub claimed_identity {
    my Net::OpenID::Consumer $self = shift;
    my $url = shift;
    Carp::croak("Too many parameters") if @_;

    # trim whitespace
    $url =~ s/^\s+//;
    $url =~ s/\s+$//;
    return $self->_fail("empty_url") unless $url;

    # do basic canonicalization
    $url = "http://$url" if $url && $url !~ m!^\w+://!;
    return $self->_fail("bogus_url") unless $url =~ m!^https?://!i;
    # add a slash, if none exists
    $url .= "/" unless $url =~ m!^https?://.+/!i;

    my $endpoints = $self->_discover_acceptable_endpoints($url, primary_only => 1);

    if (ref($endpoints) && @$endpoints) {
        foreach my $endpoint (@$endpoints) {

            next unless $endpoint->{version} >= $self->minimum_version;

            $self->_debug("Discovered version $endpoint->{version} endpoint at $endpoint->{uri} via $endpoint->{mechanism}");
            $self->_debug("Delegate is $endpoint->{delegate}") if $endpoint->{delegate};

            return Net::OpenID::ClaimedIdentity->new(
                identity         => $endpoint->{final_url},
                server           => $endpoint->{uri},
                consumer         => $self,
                delegate         => $endpoint->{delegate},
                protocol_version => $endpoint->{version},
                semantic_info    => $endpoint->{sem_info},
            );

        }

        # If we've fallen out here, then none of the available services are of the required version.
        return $self->_fail("protocol_version_incorrect");

    }
    else {
        return $self->_fail("no_identity_server");
    }

}

sub user_cancel {
    my Net::OpenID::Consumer $self = shift;
    return $self->_message_mode_is("cancel");
}

sub setup_needed {
    my Net::OpenID::Consumer $self = shift;
    if ($self->_message_version == 1) {
        return $self->_message_mode_is("id_res") && $self->message("user_setup_url");
    }
    else {
        return $self->_message_mode_is('setup_needed');
    }
}

sub user_setup_url {
    my Net::OpenID::Consumer $self = shift;
    my %opts = @_;
    my $post_grant = delete $opts{'post_grant'};
    Carp::croak("Unknown options: " . join(", ", keys %opts)) if %opts;

    if ($self->_message_version == 1) {
        return $self->_fail("bad_mode") unless $self->_message_mode_is("id_res");
    }
    else {
        return undef unless $self->_message_mode_is('setup_needed');
    }
    my $setup_url = $self->message("user_setup_url");

    OpenID::util::push_url_arg(\$setup_url, "openid.post_grant", $post_grant)
        if $setup_url && $post_grant;

    return $setup_url;
}

sub verified_identity {
    my Net::OpenID::Consumer $self = shift;
    my %opts = @_;

    my $rr = delete $opts{'required_root'} || $self->{required_root};
    Carp::croak("Unknown options: " . join(", ", keys %opts)) if %opts;

    return $self->_fail("bad_mode") unless $self->_message_mode_is("id_res");

    # the asserted identity (the delegated one, if there is one, since the protocol
    # knows nothing of the original URL)
    my $a_ident  = $self->message("identity")     or return $self->_fail("no_identity");

    my $sig64    = $self->message("sig")          or return $self->_fail("no_sig");

    # fix sig if the OpenID auth server failed to properly escape pluses (+) in the sig
    $sig64 =~ s/ /+/g;

    my $returnto = $self->message("return_to")    or return $self->_fail("no_return_to");
    my $signed   = $self->message("signed");

    my $possible_endpoints;
    my $server;
    my $claimed_identity;

    my $real_ident;
    if ($self->_message_version == 1) {
        $real_ident = $self->args("oic.identity") || $a_ident;

        # In version 1, we have to assume that the primary server
        # found during discovery is the one sending us this message.
        $possible_endpoints = $self->_discover_acceptable_endpoints($real_ident, force_version => 1);

        if ($possible_endpoints && @$possible_endpoints) {
            $possible_endpoints = [ $possible_endpoints->[0] ];
            $server = $possible_endpoints->[0]{uri};
        }
        else {
            # We just fall out of here and bail out below for having no endpoints.
        }
    }
    else {
        $real_ident = $self->message("claimed_id") || $a_ident;

        # In version 2, the OP tells us its URL.
        $server = $self->message("op_endpoint");
        $possible_endpoints = $self->_discover_acceptable_endpoints($real_ident, force_version => 2);

        # FIXME: It kinda sucks that the above will always do both Yadis and HTML discovery, even though
        # in most cases only one will be in use.
    }

    $self->_debug("Server is $server");

    unless ($possible_endpoints && @$possible_endpoints) {
        return $self->_fail("no_identity_server");
    }

    # check that returnto is for the right host
    return $self->_fail("bogus_return_to") if $rr && $returnto !~ /^\Q$rr\E/;

    # check age/signature of return_to
    my $now = time();
    {
        my ($sig_time, $sig) = split(/\-/, $self->args("oic.time") || "");
        # complain if more than an hour since we sent them off
        return $self->_fail("time_expired")   if $sig_time < $now - 3600;
        # also complain if the signature is from the future by more than 30 seconds,
        # which compensates for potential clock drift between nodes in a web farm.
        return $self->_fail("time_in_future") if $sig_time - 30 > $now;
        # and check that the time isn't faked
        my $c_secret = $self->_get_consumer_secret($sig_time);
        my $good_sig = substr(hmac_sha1_hex($sig_time, $c_secret), 0, 20);
        return $self->_fail("time_bad_sig") unless OpenID::util::timing_indep_eq($sig, $good_sig);
    }

    my $last_error = undef;

    foreach my $endpoint (@$possible_endpoints) {
        my $final_url = $endpoint->{final_url};
        my $endpoint_uri = $endpoint->{uri};
        my $delegate = $endpoint->{delegate};

        my $error = sub {
            $self->_debug("$endpoint_uri not acceptable: ".$_[0]);
            $last_error = $_[0];
        };

        # The endpoint_uri must match our $server
        if ($endpoint_uri ne $server) {
            $error->("server_not_allowed");
            next;
        }

        # OpenID 2.0 wants us to exclude the fragment part of the URL when doing equality checks
        my $a_ident_nofragment = $a_ident;
        my $real_ident_nofragment = $real_ident;
        my $final_url_nofragment = $final_url;
        if ($self->_message_version >= 2) {
            $a_ident_nofragment =~ s/\#.*$//x;
            $real_ident_nofragment =~ s/\#.*$//x;
            $final_url_nofragment =~ s/\#.*$//x;
        }
        unless ($final_url_nofragment eq $real_ident_nofragment) {
            $error->("unexpected_url_redirect");
            next;
        }

        # Protocol version must match
        unless ($endpoint->{version} == $self->_message_version) {
            $error->("protocol_version_incorrect");
            next;
        }

        # if openid.delegate was used, check that it was done correctly
        if ($a_ident_nofragment ne $real_ident_nofragment) {
            unless ($delegate eq $a_ident_nofragment) {
                $error->("bogus_delegation");
                next;
            }
        }

        # If we've got this far then we've found the right endpoint.

        $claimed_identity =  Net::OpenID::ClaimedIdentity->new(
            identity         => $endpoint->{final_url},
            server           => $endpoint->{uri},
            consumer         => $self,
            delegate         => $endpoint->{delegate},
            protocol_version => $endpoint->{version},
            semantic_info    => $endpoint->{sem_info},
        );
        last;

    }

    unless ($claimed_identity) {
        # We failed to find a good endpoint in the above loop, so
        # lets bail out.
        return $self->_fail($last_error);
    }

    my $assoc_handle = $self->message("assoc_handle");

    $self->_debug("verified_identity: assoc_handle: $assoc_handle");
    my $assoc = Net::OpenID::Association::handle_assoc($self, $server, $assoc_handle);

    my %signed_fields;   # key (without openid.) -> value

    # Auth 2.0 requires certain keys to be signed.
    if ($self->_message_version >= 2) {
        my %signed_fields = map {$_ => 1} split /,/, $signed;
        my %unsigned_fields;
        # these fields must be signed unconditionally
        foreach my $f (qw/op_endpoint return_to response_nonce assoc_handle/) {
            $unsigned_fields{$f}++ if !$signed_fields{$f};
        }
        # these fields must be signed if present
        foreach my $f (qw/claimed_id identity/) {
            next unless $self->args("openid.$f");
            $unsigned_fields{$f}++ if !$signed_fields{$f};
        }
        if (%unsigned_fields) {
            return $self->_fail("unsigned_field", undef, keys %unsigned_fields);
        }
    }

    if ($assoc) {
        $self->_debug("verified_identity: verifying with found association");

        return $self->_fail("expired_association")
            if $assoc->expired;

        # verify the token
        my $token = "";
        foreach my $param (split(/,/, $signed)) {
            my $val = $self->args("openid.$param");
            $token .= "$param:$val\n";
            $signed_fields{$param} = $val;
        }

        utf8::encode($token);
        my $good_sig = $assoc->generate_signature($token);
        return $self->_fail("signature_mismatch") unless OpenID::util::timing_indep_eq($sig64, $good_sig);

    } else {
        $self->_debug("verified_identity: verifying using HTTP (dumb mode)");
        # didn't find an association.  have to do dumb consumer mode
        # and check it with a POST
        my %post;
        my @mkeys;
        if ($self->_message_version >= 2
            && (@mkeys = $self->message->all_parameters)) {
            # OpenID 2.0: copy *EVERYTHING*, not just signed parameters.
            # (XXX:  Do we need to copy non "openid." parameters as well?
            #  For now, assume if provider is sending them, there is a reason)
            %post = map {$_ eq 'openid.mode' ? () : ($_, $self->args($_)) } @mkeys;
        }
        else {
            # OpenID 1.1 *OR* legacy client did not provide a proper
            # enumerator; in the latter case under 2.0 we have no
            # choice but to send a partial (1.1-style)
            # check_authentication request and hope for the best.

            %post = (
                     "openid.assoc_handle" => $assoc_handle,
                     "openid.signed"       => $signed,
                     "openid.sig"          => $sig64,
                    );

            if ($self->_message_version >= 2) {
                $post{'openid.ns'} = OpenID::util::VERSION_2_NAMESPACE();
            }

            # and copy in all signed parameters that we don't already have into %post
            foreach my $param (split(/,/, $signed)) {
                next unless $param =~ /^[\w\.]+$/;
                my $val = $self->args('openid.'.$param);
                $signed_fields{$param} = $val;
                next if $post{"openid.$param"};
                $post{"openid.$param"} = $val;
            }

            # if the server told us our handle as bogus, let's ask in our
            # check_authentication mode whether that's true
            if (my $ih = $self->message("invalidate_handle")) {
                $post{"openid.invalidate_handle"} = $ih;
            }
        }
        $post{"openid.mode"} = "check_authentication";

        my $req = HTTP::Request->new(POST => $server);
        $req->header("Content-Type" => "application/x-www-form-urlencoded");
        $req->content(join("&", map { "$_=" . uri_escape($post{$_}) } keys %post));

        my $ua  = $self->ua;
        my $res = $ua->request($req);

        return $self->_fail("naive_verify_failed_network")
          unless $res && $res->is_success;

        my $content = $res->content;
        my %args = OpenID::util::parse_keyvalue($content);

        # delete the handle from our cache
        if (my $ih = $args{'invalidate_handle'}) {
            Net::OpenID::Association::invalidate_handle($self, $server, $ih);
        }

        return $self->_fail("naive_verify_failed_return") unless
            $args{'is_valid'} eq "true" ||  # protocol 1.1
            $args{'lifetime'} > 0;          # DEPRECATED protocol 1.0
    }

    $self->_debug("verified identity! = $real_ident");

    # verified!
    return Net::OpenID::VerifiedIdentity->new(
        claimed_identity => $claimed_identity,
        consumer  => $self,
        signed_fields => \%signed_fields,
    );
}

sub supports_consumer_secret { 1; }

sub _get_consumer_secret {
    my Net::OpenID::Consumer $self = shift;
    my $time = shift;

    my $ss;
    if (ref $self->{consumer_secret} eq "CODE") {
        $ss = $self->{consumer_secret};
    } elsif ($self->{consumer_secret}) {
        $ss = sub { return $self->{consumer_secret}; };
    } else {
        Carp::croak("You haven't defined a consumer_secret value or subref.\n");
    }

    my $sec = $ss->($time);
    Carp::croak("Consumer secret too long") if length($sec) > 255;
    return $sec;
}

1;
__END__

=head1 NAME

Net::OpenID::Consumer - Library for consumers of OpenID identities

=head1 VERSION

version 1.100099_001

=head1 SYNOPSIS

  use Net::OpenID::Consumer;

  my $csr = Net::OpenID::Consumer->new(
    ua    => LWPx::ParanoidAgent->new,
    cache => Some::Cache->new,
    args  => $cgi,
    consumer_secret => ...,
    required_root => "http://site.example.com/",
  );

  # a user entered, say, "bradfitz.com" as their identity.  The first
  # step is to fetch that page, parse it, and get a
  # Net::OpenID::ClaimedIdentity object:

  my $claimed_identity = $csr->claimed_identity("bradfitz.com");

  # now your app has to send them at their identity server's endpoint
  # to get redirected to either a positive assertion that they own
  # that identity, or where they need to go to login/setup trust/etc.

  my $check_url = $claimed_identity->check_url(
    return_to  => "http://example.com/openid-check.app?yourarg=val",
    trust_root => "http://example.com/",
  );

  # so you send the user off there, and then they come back to
  # openid-check.app, then you see what the identity server said.

  # Either use callback-based API (recommended)...
  $csr->handle_server_response(
      not_openid => sub {
          die "Not an OpenID message";
      },
      setup_needed => sub {
          # (openID 1) redirect user to $csr->user_setup_url
          # (openID 2) retry request in checkid_setup mode
      },
      cancelled => sub {
          # Do something appropriate when the user hits "cancel" at the OP
      },
      verified => sub {
          my $vident = shift;
          # Do something with the VerifiedIdentity object $vident
      },
      error => sub {
          my $err = shift;
          die($err);
      },
  );

  # ... or handle the various cases yourself
  unless ($the_csr->is_server_response) {
      die "Not an OpenID message";
  } elsif ($csr->setup_needed) {
       # (openID 1) redirect/link/popup user to $self->user_setup_url
       # (openID 2) retry request in checkid_setup mode
  } elsif ($csr->user_cancel) {
       # restore web app state to prior to check_url
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

  http://openid.net/

=head1 CONSTRUCTOR

=over 4

=item C<new>

my $csr = Net::OpenID::Consumer->new([ %opts ]);

You can set the C<ua>, C<cache>, C<consumer_secret>, C<required_root>,
C<minimum_version> and C<args> in the constructor.  See the corresponding
method descriptions below.

=back

=head1 METHODS

=over 4

=item $csr->B<ua>($user_agent)

=item $csr->B<ua>

Getter/setter for the LWP::UserAgent (or subclass) instance which will
be used when web donwloads are needed.  It's highly recommended that
you use LWPx::ParanoidAgent, or at least read its documentation so
you're aware of why you should care.

=item $csr->B<cache>($cache)

=item $csr->B<cache>

Getter/setter for the optional (but recommended!) cache instance you
want to use for storing fetched parts of pages.  (identity server
public keys, and the E<lt>headE<gt> section of user's HTML pages)

The $cache object can be anything that has a -E<gt>get($key) and
-E<gt>set($key,$value) methods.  See L<URI::Fetch> for more
information.  This cache object is just passed to L<URI::Fetch>
directly.

=item $nos->B<consumer_secret>($scalar)

=item $nos->B<consumer_secret>($code)

=item $code = $nos->B<consumer_secret>; ($secret) = $code->($time);

The consumer secret is used to generate self-signed nonces for the
return_to URL, to prevent spoofing.

In the simplest (and least secure) form, you configure a static secret
value with a scalar.  If you use this method and change the scalar
value, any outstanding requests from the last 30 seconds or so will fail.

The more robust (but more complicated) form is to supply a subref that
returns a secret based on the provided I<$time>, a unix timestamp.
And if one doesn't exist for that time, create, store and return it
(with appropriate locking so you never return different secrets for
the same time.)

Your secret may not exceed 255 characters.

=item $csr->B<minimum_version>(2)

=item $csr->B<minimum_version>

Get or set the minimum OpenID protocol version supported. Currently
the only useful value you can set here is 2, which will cause
1.1 identifiers to fail discovery with the error C<protocol_version_incorrect>
and responses from version 1 providers to not be recognized.

In most cases you'll want to allow both 1.1 and 2.0 identifiers,
which is the default. If you want, you can set this property to 1
to make this behavior explicit.

=item $csr->assoc_options(...)

=item $csr->assoc_options

Get or sets the hash of parameters that determine how associations
with servers will be made.  Available options include

=over 4

=item assoc_type

Association type, (default 'HMAC-SHA1')

=item session_type

Association session type, (default 'DH-SHA1')

=item max_encrypt

(default FALSE) Use best encryption available for protocol version
for both session type and association type.
This overrides C<session_type> and C<assoc_type>

=item session_no_encrypt_https

(default FALSE) Use an unencrypted session type if server is https
This overrides C<max_encrypt> if both are set.

=item allow_eavesdropping

(default FALSE)  Because it is generally a bad idea, we abort
assocations where an unencrypted session over a non-SSL
connection is called for.  However the OpenID 1.1 specification
technically allows this, so if that is what you really want,
set this flag true.  Ignored under protocol version 2.

=back

=item $csr->B<message>($key)

Obtain a value from the message contained in the request arguments
with the given key. This can only be used to obtain core arguments,
not extension arguments.

Call this method without a C<$key> argument to get a L<Net::OpenID::IndirectMessage>
object representing the message.

=item $csr->B<args>($ref)

=item $csr->B<args>($param)

=item $csr->B<args>

Can be used in 1 of 3 ways:

1. Setting the way which the Consumer instances obtains GET parameters:

$csr->args( $reference )

Where $reference is either a HASH ref, a CODE ref, or a "request object".
Currently recognized request objects include Apache, Apache::Request,
Apache2::Request, Plack::Request, and CGI.

If you pass in a CODE ref, it must, if given a single URL parameter
name argument, return that parameter value B<and>, if given no arguments
at all, return the full list of parameter names from the request.

If you pass in an Apache (Apache 1 RequestRec) object, you must not
have already called $r->content as the consumer module will want to
get the request arguments out of here in the case of a POST request.

2. Get a parameter:

my $foo = $csr->args("foo");

When given an unblessed scalar, it retrieves the value.  It croaks if
you haven't defined a way to get at the parameters.

Most callers should instead use the C<message> method above, which
abstracts away the need to understand OpenID's message serialization.

3. Get the getter:

my $code = $csr->args;

Without arguments, returns a subref that returns the value given a
parameter name.

Most callers should instead use the C<message> method above with no
arguments, which returns an object from which extension attributes
can be obtained by their documented namespace URI.

=item $nos->B<required_root>($url_prefix)

=item $url_prefix = $nos->B<required_root>

If provided, this is the required string that all return_to URLs must
start with.  If it doesn't match, it'll be considered invalid (spoofed
from another site)

=item $csr->B<claimed_identity>($url)

Given a user-entered $url (which could be missing http://, or have
extra whitespace, etc), returns either a Net::OpenID::ClaimedIdentity
object, or undef on failure.

Note that this identity is NOT verified yet.  It's only who the user
claims they are, but they could be lying.

If this method returns undef, you can rely on the following errors
codes (from $csr->B<errcode>) to decide what to present to the user:

=over 8

=item no_identity_server

=item empty_url

=item bogus_url

=item no_head_tag

=item url_fetch_err

=back

=item $csr->B<handle_server_response>( %callbacks );

When a request comes in that contains a response from an OpenID provider,
figure out what it means and dispatch to an appropriate callback to handle
the request. This is the callback-based alternative to explicitly calling
the methods below in the correct sequence, and is recommended unless you
need to do something strange.

Anything you return from the selected callback function will be returned
by this method verbatim. This is useful if the caller needs to return
something different in each case.

The available callbacks are:

=over 8

=item B<not_openid> - the request isn't an OpenID response after all.

=item B<setup_needed>() - a checkid_immediate mode request was rejected, indicating that the provider requires user interaction.

=item B<cancelled> - the user cancelled the authentication request from the provider's UI.

=item B<verified>($verified_identity) - the user's identity has been successfully verified. A L<Net::OpenID::VerifiedIdentity> object is passed in.

=item B<error>($errcode, $errmsg) - an error has occured. An error code and message are provided.

=back

For the sake of legacy code we also allow

=over 8

=item B<setup_required>($setup_url) - [DEPRECATED] a checkid_immediate mode request was rejected AND $setup_url was provided.

=back

however clients using this callback should be updated to use B<setup_needed>
at the earliest opportunity.  Here $setup_url is the same as returned by
B<user_setup_url>.

=item $csr->B<setup_needed>

Returns true if a checkid_immediate request failed because the provider
requires user interaction.  The correct action to take at this point
depends on the OpenID protocol version

(Version 1) Redirect to or otherwise make available a link to
C<$csr>->C<user_setup_url>.

(Version 2) Retry the request in checkid_setup mode; the provider will
then issue redirects as needed.

=over

B<N.B.>: While some providers have been known to supply the C<user_setup_url>
parameter in Version 2 C<setup_needed> responses, you I<cannot> rely on this,
and, moreover, since the OpenID 2.0 specification has nothing to say about
the meaning of such a parameter, you cannot rely on it meaning anything
in particular even if it is supplied.

=back

=item $csr->B<user_setup_url>( [ %opts ] )

(Version 1 only) Returns the URL the user must return to in order to
login, setup trust, or do whatever the identity server needs them to
do in order to make the identity assertion which they previously
initiated by entering their claimed identity URL.

=over

B<N.B.>: Checking whether C<user_setup_url> is set in order to determine
whether a checkid_immediate request failed is DEPRECATED and will fail
under OpenID 2.0.  Use C<setup_needed()> instead.

=back

The base URL this this function returns can be modified by using the
following options in %opts:

=over

=item C<post_grant>

What you're asking the identity server to do with the user after they
setup trust.  Can be either C<return> or C<close> to return the user
back to the return_to URL, or close the browser window with
JavaScript.  If you don't specify, the behavior is undefined (probably
the user gets a dead-end page with a link back to the return_to URL).
In any case, the identity server can do whatever it wants, so don't
depend on this.

=back

=item $csr->B<user_cancel>

Returns true if the user declined to share their identity, false
otherwise.  (This function is literally one line: returns true if
"openid.mode" eq "cancel")

It's then your job to restore your app to where it was prior to
redirecting them off to the user_setup_url, using the other query
parameters that you'd sent along in your return_to URL.

=item $csr->B<verified_identity>( [ %opts ] )

Returns a Net::OpenID::VerifiedIdentity object, or undef.
Verification includes double-checking the reported identity URL
declares the identity server, verifying the signature, etc.

The options in %opts may contain:

=over

=item C<required_root>

Sets the required_root just for this request.  Values returns to its
previous value afterwards.

=back

=item $csr->B<err>

Returns the last error, in form "errcode: errtext"

=item $csr->B<errcode>

Returns the last error code.

=item $csr->B<errtext>

Returns the last error text.

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

=head1 MAILING LIST

The Net::OpenID family of modules has a mailing list powered
by Google Groups. For more information, see
http://groups.google.com/group/openid-perl .

=head1 SEE ALSO

OpenID website: http://openid.net/

L<Net::OpenID::ClaimedIdentity> -- part of this module

L<Net::OpenID::VerifiedIdentity> -- part of this module

L<Net::OpenID::Server> -- another module, for acting like an OpenID server

=head1 AUTHORS

Brad Fitzpatrick <brad@danga.com>

Tatsuhiko Miyagawa <miyagawa@sixapart.com>

Martin Atkins <mart@degeneration.co.uk>