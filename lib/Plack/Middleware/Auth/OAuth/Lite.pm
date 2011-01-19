package Plack::Middleware::Auth::OAuth::Lite;
use strict;
use warnings;
use OAuth::Lite;
use Carp();
use OAuth::Lite::Util ();
use OAuth::Lite::ServerUtil;
use Plack::Request;
use Plack::Session;
use Plack::Util();
use Plack::Util::Accessor qw/
    check_timestamp_callback
    check_nonce_callback
    consumer_key
    consumer_secret
    env
    get_params_from
    unauthorized_callback
/;

use parent qw/Plack::Middleware/;

our $VERSION = '0.01';

our $DEFAULT_GET_PARAMS_FROM = {
    post_body       => 0,
    session         => 0,
    oauth_header    => 1,
    query_parameter => 1,
};

our @REQUIRED_PARAMETERS = qw/
    oauth_consumer_key
    oauth_signature_method
    oauth_signature
    oauth_timestamp
    oauth_nonce
    oauth_version
    oauth_token
/;

our $SESSION_KEY = 'oauth_session_params';

sub prepare_app {
    my $self = shift;

    #check parameter
    Carp::confess('Parameter "consumer_key" is required')    unless $self->{consumer_key};
    Carp::confess('Parameter "consumer_secret" is required') unless $self->{consumer_secret};


    if($self->unauthorized_callback && ref($self->unauthorized_callback) ne 'CODE' ){
        Carp::confess('Parameter unauthorized_callback should be a code reference');
    }else{
        #default callback
        $self->{unauthorized_callback} ||= \&unauthorized;
    }

    if($self->check_nonce_callback && ref($self->check_nonce_callback) ne 'CODE' ){
        Carp::confess('Parameter check_nonce_callback should be a code reference');
    }
    if($self->check_timestamp_callback && ref($self->check_timestamp_callback) ne 'CODE' ){
        Carp::confess('Parameter check_timestamp_callback should be a code reference');
    }
    # merge default parameters
    $self->get_params_from(
        {
            %$DEFAULT_GET_PARAMS_FROM,
            %{$self->get_params_from || {}},
        }
    );
}

sub call {
    my ( $self, $env ) = @_;

    return $self->authorize($env) ? $self->app->($env) : $self->unauthorized_callback->($env);
}

sub authorize {
    my ( $self, $env ) = @_;

    $self->{env} = $env;

    my $req = $self->req;



    #XXX get only?
    my $params = $self->merge_params;

    return unless $self->check_parameters( $params );

    if ( $self->get_params_from->{session} ) {

        my $skip_auth = 1;
        #parameter check
        for my $param_name ( @REQUIRED_PARAMETERS ) {
            unless ( defined $params->get($param_name) ) {
                $skip_auth = 0;
            }
        }

        my $session = $self->session;
        if ($skip_auth) {

            #get session
            return $session->get($SESSION_KEY);
        }
    }


    my $result = $self->verify( $params->get('oauth_signature_method'),
        {
            method          => $req->method,
            url             => $req->uri,
            params          => $params->as_hashref_mixed,
            consumer_secret => $self->consumer_secret,
            token_secret    => $params->{oauth_token_secret},
        }
    );

    if ($result && $self->get_params_from->{session}) {

        my $session = $self->session;
        #regenerate session id
        $session->options->{change_id}++;

        #store session
        $session->set( $SESSION_KEY, $params );
    }
    return $result;
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

sub create_request {
    my ( $self, $env ) = @_;
    return Plack::Request->new($env);
}

sub verify_hmac_sha1 {
    my ( $self, $params ) = @_;
    return verify( 'HMAC-SHA1', $params );
}

sub verify_rsa_sha1 {
    my ( $self, $params ) = @_;
    return verify( 'RSA-SHA1', $params );
}

sub verify {
    my ( $self, $method, $params ) = @_;
    my $oauth = OAuth::Lite::ServerUtil->new( strict => 0 );
    $oauth->support_signature_method($method);
    return $oauth->verify_signature(%$params);
}

sub check_parameters {
    my ( $self, $params ) = @_;

    return unless $params->{oauth_consumer_key} && $params->{oauth_consumer_key} eq $self->consumer_key;
    return if $self->check_timestamp_callback && !$self->check_timestamp_callback->($params);
    return if $self->check_nonce_callback && !$self->check_nonce_callback->($params);

    return 1;
}

sub parse_auth_header {
    my $self = shift;
    my $header = $self->env->{HTTP_AUTHORIZATION};
    return unless $header;
    my ( $r, $params ) = OAuth::Lite::Util::parse_auth_header($header);
    return $params;
}

sub merge_params {
    my $self = shift;

    my $req = $self->req;

    my $auth_params = $self->parse_auth_header;

    return unless $auth_params || !$self->get_params_from->{oauth_header};

    my $req_params = $self->get_params_from->{post_body}
        ? $req->parameters->clone
        : $req->query_parameters->clone;

    while ( my ( $key, $value ) = each %$auth_params ) {
        $req_params->add( $key => ref($value) eq 'ARRAY' ? @$value : $value );
    }
    return $req_params;
}

sub session {
    my $self = shift;
    $self->{session} ||= Plack::Session->new($self->env);
}
sub req {
    my $self = shift;
    $self->{req} ||= Plack::Request->new($self->env);
}

1;
__END__

=head1 NAME

Plack::Middleware::Auth::OAuth::Lite - Yet another OAuth authorization middleware for Plack

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

Plack::Middleware::Auth::OAuth::Lite is Yet another OAuth authorization middleware for Plack

=head1 AUTHOR

Nishibayashi Takuji E<lt>takuji {at} senchan.jpE<gt>

=head1 SEE ALSO

L<Plack::Middleware::Auth::OAuth>,L<Plack::Session>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
