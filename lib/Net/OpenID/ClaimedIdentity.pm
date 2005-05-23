# LICENSE: You're free to distribute this under the same terms as Perl itself.

use strict;
use Carp ();
use LWP::UserAgent;

############################################################################
package Net::OpenID::ClaimedIdentity;
use fields (
            'identity',  # the canonical URL that was found, following redirects
            'servers',   # arrayref of author-identity server endpoints, as found in order in file
            'consumer',  # ref up to the Net::OpenID::Consumer which generated us
            );

sub new {
    my Net::OpenID::ClaimedIdentity $self = shift;
    $self = fields::new( $self ) unless ref $self;
    my %opts = @_;
    $self->{identity} = delete $opts{identity};
    $self->{servers}  = delete $opts{servers};
    $self->{consumer} = delete $opts{consumer};
    Carp::croak("servers not arrayref") unless ref $self->{servers} eq "ARRAY";
    Carp::croak("unknown options: " . join(", ", keys %opts)) if %opts;
    return $self;
}

sub claimed_url {
    my Net::OpenID::ClaimedIdentity $self = shift;
    Carp::croak("Too many parameters") if @_;
    return $self->{'identity'};
}

sub identity_server {
    my Net::OpenID::ClaimedIdentity $self = shift;
    Carp::croak("Too many parameters") if @_;
    return $self->{consumer}->_pick_identity_server($self->{servers});
}

sub identity_servers {
    my Net::OpenID::ClaimedIdentity $self = shift;
    Carp::croak("Too many parameters") if @_;
    return @{ $self->{'servers'} };
}

sub check_url {
    my Net::OpenID::ClaimedIdentity $self = shift;
    my (%opts) = @_;

    my $return_to   = delete $opts{'return_to'};
    my $trust_root  = delete $opts{'trust_root'};
    my $post_grant  = delete $opts{'post_grant'};
    Carp::croak("unknown options: " . join(", ", keys %opts)) if %opts;
    Carp::croak("Invalid/missing return_to") unless $return_to =~ m!^https?://!;

    my $ident_server = $self->{consumer}->_pick_identity_server($self->{servers});
    Carp::croak("No identity server was chosen") unless $ident_server;

    # find to index of ident server chosen, so we can pass it back to ourselves
    # in the return_to URL.
    my $ident_server_idx = undef;
    for my $n (0 .. $#{ $self->{servers} }) {
        $ident_server_idx = $n if $self->{servers}[$n] eq $ident_server;
    }
    Carp::croak("Identity server chosen wasn't an option")
        unless defined $ident_server_idx;

    local *eurl = \&OpenID::util::eurl;
    my $curl = $ident_server;
    $curl =~ s/[?&]$//;
    $curl .= "&openid.return_to="   . eurl($return_to);
    $curl .= "&openid.is_identity=" . eurl($self->{identity});
    $curl .= "&openid.trust_root="  . eurl($trust_root) if $trust_root;
    $curl .= "&openid.post_grant="  . eurl($post_grant) if $post_grant;

    # non-spec attributes that this module uses:
    $curl .= "&oicsr.idx="  . eurl($ident_server_idx) if $ident_server_idx != 0;

    $curl =~ s/&/?/ unless $curl =~ /\?/;
    return $curl;
}

1;
