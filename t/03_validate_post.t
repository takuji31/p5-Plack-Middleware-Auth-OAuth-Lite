use t::Utils;
use Test::More;
use Plack::Test;
use Plack::Builder;
use HTTP::Request::Common;

use OAuth::Lite::AuthMethod qw/
    AUTH_HEADER
    POST_BODY
    URL_QUERY
    /;
use OAuth::Lite::Consumer;
my $consumer_key    = 'correctconsumerkey';
my $consumer_secret = 'correctconsumersecret';
my $consumer = OAuth::Lite::Consumer->new(
    consumer_key    => $consumer_key,
    consumer_secret => $consumer_secret,
);
my $app             = create_app;
my $params          = {
    oauth_version          => '1.0',
    oauth_signature_method => 'HMAC-SHA1',
    oauth_token            => 'aaaaaaa',
    hoge                   => 'fuga',
};

test_psgi builder {
    enable 'Plack::Middleware::Auth::OAuth::Lite',
        validate_post => 1,
        consumer_key    => $consumer_key,
        consumer_secret => $consumer_secret;
    $app;
}, sub {
    my $cb  = shift;
    my $res = $cb->( POST "http://localhost/" );
    is $res->code, 401;
};

test_psgi builder {
    enable 'Plack::Middleware::Auth::OAuth::Lite',
        validate_post => 1,
        consumer_key    => $consumer_key,
        consumer_secret => $consumer_secret;
    $app;
}, sub {
    my $cb  = shift;
    my $req = $consumer->gen_oauth_request(
        method => 'POST',
        url    => 'http://localhost/',
        params => $params,
    );
    my $res = $cb->($req);
    is $res->code,    200;
    is $res->content, "Hello Plack World";
};

test_psgi builder {
    enable 'Plack::Middleware::Auth::OAuth::Lite',
        validate_post => 1,
        consumer_key    => 'wrongconsumerkey',
        consumer_secret => $consumer_secret;
    $app;
}, sub {
    my $cb  = shift;
    my $req = $consumer->gen_oauth_request(
        method => 'POST',
        url    => 'http://localhost/',
        params => $params,
    );
    my $res = $cb->($req);
    is $res->code, 401;
};

test_psgi builder {
    enable 'Plack::Middleware::Auth::OAuth::Lite',
        validate_post => 1,
        consumer_key    => $consumer_key,
        consumer_secret => 'wrongconsumersecret';
    $app;
}, sub {
    my $cb  = shift;
    my $req = $consumer->gen_oauth_request(
        method => 'POST',
        url    => 'http://localhost/',
        params => $params,
    );
    my $res = $cb->($req);
    is $res->code, 401;
};

done_testing;
