package Plack::Authorizer::OAuth::Touch;
use strict;
use warnings;
use parent qw/Plack::Authorizer::OAuth::Base/;

use Plack::Session;

our @REQUIRED_PARAMETERS = qw/
    opensocial_app_id
    opensocial_viewer_id
    opensocial_owner_id
    oauth_consumer_key
    oauth_nonce
    oauth_signature
    oauth_signature_method
    oauth_timestamp
    oauth_token
    oauth_token_secret
    oauth_version
/;

our $SESSION_KEY = 'oauth_session_info';

sub authorize {
    my ($class, $middleware, $env) = @_;

    my $req = $class->create_request($env);

    my $do_auth = 1;

    #parameter check
    map { $do_auth = $do_auth && $req->param($_)} @REQUIRED_PARAMETERS;

    unless($do_auth) {
        #get session
        my $session = Plack::Session->new($env);
        return $session->get($SESSION_KEY);
    }

    my $params = $class->parse_auth_header($env);

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
