use inc::Module::Install;
name 'Plack-Middleware-Auth-OAuth-Lite';
all_from 'lib/Plack/Middleware/Auth/OAuth/Lite.pm';
readme_pod_from 'lib/Plack/Middleware/Auth/OAuth/Lite.pm';
githubmeta;

# requires '';
requires 'Plack';
requires 'OAuth::Lite';

tests 't/*.t';
author_tests 'xt';

build_requires 'Test::More';
auto_set_repository;
auto_include;
WriteAll;
