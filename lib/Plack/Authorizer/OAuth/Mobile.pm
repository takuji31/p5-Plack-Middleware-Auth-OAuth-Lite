package  Plack::Authorizer::OAuth::Mobile;
use strict;
use warnings;
use parent qw/Plack::Authorizer::OAuth::Base/;

sub authorize {
    my ($class, $middleware, $env) = @_;

    my $req = $class->create_request($env);

    my $params = $class->parse_auth_header($env);

    return unless $params;

    my $req_params = $middleware->validate_post ? $req->parameters : $req->query_parameters;

    map { $params->{$_} = $req_params->{$_} } $req_params->keys;

    return $class->verify_hmac_sha1(
        {
            method          => $req->method,
            url             => $req->uri,
            params          => $params,
            consumer_secret => $middleware->consumer_secret,
            token_secret    => $params->{oauth_token_secret},
        }
    );
}

1;
