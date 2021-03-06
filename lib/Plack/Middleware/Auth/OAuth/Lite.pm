package Plack::Middleware::Auth::OAuth::Lite;
use strict;
use warnings;
use OAuth::Lite;
use Carp();
use OAuth::Lite::Util ();
use OAuth::Lite::ServerUtil;
use Plack::Request;
use Plack::Util();
use Plack::Util::Accessor qw/
    check_timestamp_callback
    check_nonce_callback
    consumer_key
    consumer_secret
    env
    unauthorized_callback
    validate_post
    validate_header
/;

use parent qw/Plack::Middleware/;

our $VERSION = '0.01';

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

    #default value
    $self->validate_header(1) unless defined $self->validate_header;
}

sub call {
    my ( $self, $env ) = @_;

    return $self->authorize($env) ? $self->app->($env) : $self->unauthorized_callback->( $self, $env );
}

sub authorize {
    my ( $self, $env ) = @_;

    $self->env($env);

    my $req = $self->req;

    #XXX get only?
    my $params = $self->merge_params;

    return unless $self->check_parameters($params);

    my $signature_method = $params->get('oauth_signature_method');
    return unless $signature_method;

    my $result = $self->verify( $signature_method,
        {
            method          => $req->method,
            url             => $req->uri,
            params          => $params->as_hashref_mixed,
            consumer_secret => $self->consumer_secret,
            token_secret    => $params->{oauth_token_secret},
        }
    );

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

sub verify {
    my ( $self, $method, $params ) = @_;
    my $oauth = OAuth::Lite::ServerUtil->new( strict => 0 );
    $oauth->support_signature_method($method);
    return $oauth->verify_signature(%$params);
}

sub check_parameters {
    my ( $self, $params ) = @_;

    return unless $params;
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

    return unless $auth_params || !$self->validate_header;

    my $req_params = $self->validate_post
        ? $req->parameters->clone
        : $req->query_parameters->clone;

    while ( my ( $key, $value ) = each %$auth_params ) {
        $req_params->add( $key => ref($value) eq 'ARRAY' ? @$value : $value );
    }
    return $req_params;
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
  
  #Basic OAuth
  builder{
      enable 'Auth::OAuth::Lite', consumer_key => 'abcdefg', consumer_secret => 'hijklmn';
      $app;
  }
  #Get all authentication parameters from the query parameter.
  builder{
      enable 'Auth::OAuth::Lite', consumer_key => 'abcdefg', consumer_secret => 'hijklmn', validate_header => 0;
      $app;
  }

  #Validate post body.
  builder{
      enable 'Auth::OAuth::Lite', consumer_key => 'abcdefg', consumer_secret => 'hijklmn', validate_post => 1;
      $app;
  }

=head1 DESCRIPTION

Plack::Middleware::Auth::OAuth::Lite is Yet another OAuth authorization middleware for Plack

=head1 AUTHOR

Nishibayashi Takuji E<lt>takuji {at} senchan.jpE<gt>

=head1 SEE ALSO

L<Plack::Middleware::Auth::OAuth>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
