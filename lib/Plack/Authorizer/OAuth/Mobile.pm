package  Plack::Authorizer::OAuth::Mobile;
use strict;
use warnings;
use parent qw/Plack::Authorizer::OAuth::Base/;

sub authorize {
    my ($class, $middleware, $env) = @_;

    my $params = $class->merge_params($env,$middleware->validate_post,0);

    return unless $params;

    return unless $class->check_parameters( $params, $middleware->consumer_key, $middleware->check_timestamp_cb, $middleware->check_nonce_cb );

    my $req = $class->create_request($env);

    return $class->verify_hmac_sha1(
        {
            method          => $req->method,
            url             => $req->uri,
            params          => $params->as_hashref_mixed,
            consumer_secret => $middleware->consumer_secret,
            token_secret    => $params->{oauth_token_secret},
        }
    );
}

1;
