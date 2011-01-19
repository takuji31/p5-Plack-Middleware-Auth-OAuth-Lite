package  Plack::Authorizer::OAuth::Base;
use strict;
use warnings;

use Plack::Request;
use OAuth::Lite::ServerUtil;
use OAuth::Lite::Util ();

sub authorize { die 'This method is abstract!' }

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
    my ( $class, $params, $consumer_key, $check_timestamp_cb, $check_nonce_cb ) = @_;

    return unless $params->{oauth_consumer_key} eq $consumer_key;
    return if $check_timestamp_cb && !$check_timestamp_cb->($params);
    return if $check_nonce_cb && !$check_nonce_cb->($params);

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
