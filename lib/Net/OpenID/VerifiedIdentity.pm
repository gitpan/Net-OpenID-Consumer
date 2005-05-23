# LICENSE: You're free to distribute this under the same terms as Perl itself.

use strict;
use Carp ();

############################################################################
package Net::OpenID::VerifiedIdentity;
use fields (
            'identity',  # the verified identity URL
            # FIXME..... module not complete, more attributes needed
            );

sub new {
    my Net::OpenID::VerifiedIdentity $self = shift;
    $self = fields::new( $self ) unless ref $self;
    my %opts = @_;
    $self->{identity} = delete $opts{identity};
    Carp::croak("unknown options: " . join(", ", keys %opts)) if %opts;
    return $self;
}

sub url {
    my Net::OpenID::VerifiedIdentity $self = shift;
    return $self->{'identity'};
}

1;
