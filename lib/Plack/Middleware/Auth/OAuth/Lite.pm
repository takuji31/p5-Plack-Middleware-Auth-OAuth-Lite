package Plack::Middleware::Auth::OAuth::Lite;
use strict;
use warnings;
use OAuth::Lite;
use Carp();
use parent qw/Plack::Middleware/;

use Plack::Util();
use Plack::Util::Accessor qw/
    consumer_key
    consumer_secret
    agent
    validate_post
    unauthorized_cb
    check_timestamp_cb
    check_nonce_cb
/;


our $VERSION = '0.01';

sub prepare_app {
    my $self = shift;

    #check parameter
    Carp::confess('Parameter "consumer_key" is required')    unless $self->{consumer_key};
    Carp::confess('Parameter "consumer_secret" is required') unless $self->{consumer_secret};


    if($self->unauthorized_cb && ref($self->unauthorized_cb) ne 'CODE' ){
        Carp::confess('Parameter unauthorized_cb should be a code reference');
    }else{
        #default callback
        $self->{unauthorized_cb} ||= \&unauthorized;
    }

    #default Agent
    $self->{agent} ||= "AutoDetect";

    if($self->check_nonce_cb && ref($self->check_nonce_cb) ne 'CODE' ){
        Carp::confess('Parameter check_nonce_cb should be a code reference');
    }
    if($self->check_timestamp_cb && ref($self->check_timestamp_cb) ne 'CODE' ){
        Carp::confess('Parameter check_timestamp_cb should be a code reference');
    }
}

sub call {
    my ( $self, $env ) = @_;

    return $self->authorize($env) ? $self->app->($env) : $self->unauthorized_cb->($env);
}

sub authorize {
    my ( $self, $env ) = @_;
    my $agent_class = join '::','Plack::Authorizer::OAuth',$self->agent;
    Plack::Util::load_class($agent_class) or Carp::confess($@);
    my $auth = $agent_class->authorize($self,$env);
}

sub unauthorized {
    my $self = shift;

    my $body = 'Authorization failured';

    return [
        401,
        [
            'Content-Type' => 'text/plain',
            'Content-Length' => length $body,
        ],
        [
            $body
        ],
    ];
}

1;
__END__

=head1 NAME

Plack::Middleware::Auth::OAuth::Lite - Yet another OAuth authorization middleware for PSGI/Plack

=head1 SYNOPSIS

use strict;
use warnings;
use Plack::Builder;

my $app = sub { #PSGI app };

builder{
    enable 'Auth::OAuth::Lite', consumer_key => 'abcdefg', consumer_secret => 'hijklmn',validate_post => 0, agent => 'Mobile';
    $app;
}

=head1 DESCRIPTION

Plack::Middleware::Auth::OAuth::Lite is

=head1 AUTHOR

Nishibayashi Takuji E<lt>takuji {at} senchan.jpE<gt>

=head1 SEE ALSO

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
