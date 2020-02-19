# Cerner OAuth 1.0a Consumer and Service Provider Library

[![Build Status](https://api.travis-ci.com/cerner/cerner-oauth1a.svg)](https://travis-ci.com/cerner/cerner-oauth1a)
[![Gem Version](http://img.shields.io/gem/v/cerner-oauth1a.svg)](https://rubygems.org/gems/cerner-oauth1a)
[![AwesomeCode Status](https://awesomecode.io/projects/48ece237-ac9c-49c9-859a-3a825968339b/status)](https://awesomecode.io/repos/cerner/cerner-oauth1a)

A minimal dependency library for interacting with a Cerner OAuth 1.0a Access Token Service for
invoking Cerner OAuth 1.0a protected services or implementing Cerner OAuth 1.0a authentication.
Cerner's OAuth 1.0a Access Token Service provides a means for facilitating two-legged (B2B)
authentication via a variant of OAuth 1.0a.

# Usage

There are two use cases for working with this library: Consumer and Service Provider. The Consumer
Use Case is for invoking services protected by Cerner OAuth 1.0a. The Service Provider Use Case is
for implementing a Ruby-based service.

## Consumer Use Case

    require 'cerner/oauth1a'
    require 'net/http'

    # Setup the AccessTokenAgent with an Access Token Service's URL, a Key and a Secret
    agent = Cerner::OAuth1a::AccessTokenAgent.new(
      access_token_url: 'https://oauth-api.cerner.com/oauth/access',
      consumer_key: 'CONSUMER_KEY',
      consumer_secret: 'CONSUMER_SECRET'
    )

    # Retrieve an AccessToken instance
    access_token = agent.retrieve

    # Setup the HTTP library to access the protected API you want to invoke
    uri = URI('https://authz-demo-api.cerner.com/me')
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true if uri.scheme == 'https'

    # Invoke the API's HTTP endpoint and use the AccessToken to generate an Authorization header
    response = http.request_get(uri.path, Authorization: access_token.authorization_header)

### Consumer HMAC-SHA1 Signature Method

The preferred and default signature method is PLAINTEXT, as all communication SHOULD be via TLS. However, if HMAC-SHA1 signatures are necessary, then this can be achieved by constructing AccessTokenAgent as follows:

    agent = Cerner::OAuth1a::AccessTokenAgent.new(
      access_token_url: 'https://oauth-api.cerner.com/oauth/access',
      consumer_key: 'CONSUMER_KEY',
      consumer_secret: 'CONSUMER_SECRET',
      signature_method: 'HMAC-SHA1'
    )

To use the AccessToken requires additional parameters to be passed when constructing the Authorization header. The HTTP method, the URL being invoked and all request parameters. The request parameters should include all parameters passed in the query string and those passed in the body if the Content-Type of the body is `application/x-www-form-urlencoded`. See the specification for more details.

#### Consumer HMAC-SHA1 Signature Method Examples

GET with no request parameters

    uri = URI('https://authz-demo-api.cerner.com/me')
    # ...
    authz_header = access_token.authorization_header(fully_qualified_url: uri)

GET with request parameters in URL

    uri = URI('https://authz-demo-api.cerner.com/me?name=value')
    # ...
    authz_header = access_token.authorization_header(fully_qualified_url: uri)

POST with request parameters (form post)

    authz_header = access_token.authorization_header(
      http_method: 'POST'
      fully_qualified_url: 'https://example/path',
      request_params: {
        sort: 'asc',
        field: ['name', 'desc'] # sending the field multiple times
      }
    )

PUT with no request parameters (entity body)

    authz_header = access_token.authorization_header(
      http_method: 'PUT'
      fully_qualified_url: 'https://example/path'
    )

### Access Token Reuse

Generally, you'll want to use an Access Token more than once. Access Tokens can be reused, but
they do expire, so you'll need to acquire new tokens after one expires. All of the expiration
information is contained in the AccessToken class and you can easily determine if a token is
expired or about to by using the AccessToken#expired? method. Below is an example of you might
implement that:

    uri = URI('https://authz-demo-api.cerner.com/me')
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true if uri.scheme == 'https'

    access_token = agent.retrieve if access_token.expired?

    response = http.request_get(uri.path, Authorization: access_token.authorization_header)

## Service Provider Use Case

    # Acquire Authorization header value from HTTP server's request
    authz_header = request['Authorization']

    # Parse the header value
    access_token = Cerner::OAuth1a::AccessToken.from_authorization_header(authz_header)

    # Authenticate the Access Token
    # Note: An AccessTokenAgent, configured with a System Account that has been granted privileges
    # to Acquire Tokens and Process Tokens.
    begin
      results = access_token.authenticate(agent)
    rescue OAuthError => e
      # respond with a 401
    end

    # Use Consumer Key (i.e. the System Account) to do further authorization, as appropriate
    system_account_id = access_token.consumer_key

    # Optionally, extract additional parameters sent with the token, such as Consumer.Principal
    # (xoauth_principal)
    consumer_principal = access_token.consumer_principal

### Service Provider HMAC-SHA1 Signature Method

The preferred and default signature method is PLAINTEXT, as all communication SHOULD be via TLS. However, if HMAC-SHA1 signatures are necessary, then this can be achieved by passing additional informational to the `authenticate` method.

    begin
      results = access_token.authenticate(
        agent,
        http_method: request.method,
        fully_qualified_url: request.original_url,
        request_params: request.parameters
      )
    rescue OAuthError => e
      # respond with a 401
    end

## Caching

The AccessTokenAgent class provides built-in memory caching. AccessTokens and Keys are cached
behind their respective retrieve methods. The caching can be disabled via parameters passed to the
constructor. See the class-level documentation for details.

### Caching in Rails

When the gem is loaded within a Rails application, it will attach a Railtie for initializing the
cache to use an implementation that stores the AccessTokens and Keys within Rails.cache.

## References
* https://wiki.ucern.com/display/public/reference/Cerner%27s+OAuth+Specification
  * https://tools.ietf.org/html/rfc5849
  * http://oauth.net/core/1.0a
  * http://oauth.pbwiki.com/ProblemReporting
* https://wiki.ucern.com/display/public/reference/Accessing+Cerner%27s+Web+Services+Using+OAuth+1.0a

# Installing
This library can be installed using the `gem` command or added to a Gemfile for use with Bundler.

## `gem` command

    $ gem install cerner-oauth1a

## Gemfile

    gem 'cerner-oauth1a', '~> 2.0'

# Building

This project is built using Ruby 2.4+, Rake and Bundler. RSpec is used for unit tests and SimpleCov
is utilized for test coverage. RuboCop is used to monitor the lint and style.

## Setup

To setup the development workspace, run the following after checkout:

    gem install bundler
    bundle install

## Tests

To run the RSpec tests, run the following:

    bin/rspec

## Lint

To analyze the project's style and lint, run the following:

    bin/rubocop

## Bundler Audit

To analyze the project's dependency vulnerabilities, run the following:

    bin/bundle audit

# Availability

This RubyGem will be available on https://rubygems.org/.

# Communication

All questions, bugs, enhancements and pull requests can be submitted here, on GitHub via Issues.

# Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

# LICENSE

Copyright 2020 Cerner Innovation, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

&nbsp;&nbsp;&nbsp;&nbsp;http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
