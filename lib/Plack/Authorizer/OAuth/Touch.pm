package Plack::Authorizer::OAuth::Touch;
use strict;
use warnings;
use parent qw/Plack::Authorizer::OAuth::Base/;

use Plack::Session;
use Hash::MultiValue;

our @REQUIRED_PARAMETERS = qw/
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

    return unless $class->check_parameters( $params, $middleware->consumer_key, $middleware->check_timestamp_cb, $middleware->check_nonce_cb );

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

1;
