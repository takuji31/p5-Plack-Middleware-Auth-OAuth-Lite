package t::Utils;
use strict;
use warnings;
use lib './t';
use OAuth::Lite::Consumer;

sub import {
    my $class  = shift;
    my $caller = caller;
    strict->import;
    warnings->import;
    utf8->import;
    my @functions = qw/ create_consumer create_app /;
    for my $func (@functions) {
        no strict 'refs';
        *{"$caller\::$func"} = \&$func;
    }
}

sub create_consumer {
    my ( $consumer_key, $consumer_secret ) = @_;
    my $consumer = OAuth::Lite::Consumer->new(
        consumer_key    => $consumer_key,
        consumer_secret => $consumer_secret,
    );
    return $consumer;
}

sub create_app {
    return sub { [ 200, [ 'Content-Type' => 'text/plain' ], ['Hello Plack World'] ] };
}

1;
