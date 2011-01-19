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
    get_params_from
    unauthorized_callback
    check_timestamp_callback
    check_nonce_callback
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
    $self->{agent} ||= "Mobile";

    if($self->check_nonce_callback && ref($self->check_nonce_callback) ne 'CODE' ){
        Carp::confess('Parameter check_nonce_callback should be a code reference');
    }
    if($self->check_timestamp_callback && ref($self->check_timestamp_callback) ne 'CODE' ){
        Carp::confess('Parameter check_timestamp_callback should be a code reference');
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
    $agent_class->authorize($self,$env);
}

sub authorize {
    my ( $class, $middleware, $env ) = @_;

    my $req = $class->create_request($env);

    my $do_auth = 1;

    #parameter check
    map { $do_auth = $do_auth && $req->param($_) } @REQUIRED_PARAMETERS;

    my $session = Plack::Session->new($env);
    unless ($do_auth) {

        #get session
        return $session->get($SESSION_KEY);
    }


    #XXX get only?
    my $params = $class->merge_params($env,$middleware->validate_post,1);

    return unless $class->check_parameters( $params, $middleware->consumer_key, $middleware->check_timestamp_callback, $middleware->check_nonce_callback );

    my $result = $class->verify_hmac_sha1(
        {
            method          => $req->method,
            url             => $req->uri,
            params          => $params->as_hashref_mixed,
            consumer_secret => $middleware->consumer_secret,
            token_secret    => $params->{oauth_token_secret},
        }
    );

    if ($result) {

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
    my ( $class, $env ) = @_;
    return Plack::Request->new($env);
}

sub verify_hmac_sha1 {
    my ( $class, $params ) = @_;
    return verify( 'HMAC-SHA1', $params );
}

sub verify_rsa_sha1 {
    my ( $class, $params ) = @_;
    return verify( 'RSA-SHA1', $params );
}

sub verify {
    my ( $method, $params ) = @_;
    my $oauth = OAuth::Lite::ServerUtil->new( strict => 0 );
    $oauth->support_signature_method($method);
    return $oauth->verify_signature(%$params);
}

sub check_parameters {
    my ( $class, $params, $consumer_key, $check_timestamp_callback, $check_nonce_callback ) = @_;

    return unless $params->{oauth_consumer_key} eq $consumer_key;
    return if $check_timestamp_callback && !$check_timestamp_callback->($params);
    return if $check_nonce_callback && !$check_nonce_callback->($params);

    return 1;
}

sub parse_auth_header {
    my ( $class, $env ) = @_;
    my $header = $env->{HTTP_AUTHORIZATION};
    return unless $header;
    my ( $r, $params ) = OAuth::Lite::Util::parse_auth_header($header);
    return $params;
}

sub merge_params {
    my ( $class, $env, $validate_post, $pass_header_check ) = @_;
    my $req = $class->create_request($env);

    my $auth_params = $class->parse_auth_header($env);

    return unless $auth_params || $pass_header_check;

    my $req_params = $validate_post
        ? $req->parameters->clone
        : $req->query_parameters->clone;

    while ( my ( $key, $value ) = each %$auth_params ) {
        $req_params->add( $key => ref($value) eq 'ARRAY' ? @$value : $value );
    }
    return $req_params;
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
