# Cerner OAuth 1.0a Client Library

[![Build Status](https://api.travis-ci.org/cerner/cerner-oauth1a.svg)][https://travis-ci.org/cerner/cerner-oauth1a]

This RubyGem is a client library for interacting with the Cerner OAuth 1.0a provider to
participate in two-legged (B2B) authentication. The goal of this project is to provide a zero-dependency Ruby library that simply and compactly implements the client aspects of
Cerner OAuth 1.0a variant of the OAuth 1.0a B2B workflow.

# Usage

## Install
This library can be installed using the `gem` command or added to a Gemfile for use with Bundler.

### `gem` command

    $ gem install cerner-oauth1a

### Gemfile

    gem 'cerner-oauth1a', '~> 1.0'

## Basic Use

    require 'cerner/oauth1a'
    require 'net/http'

    # Setup the AccessTokenAgent with an Access Token URL, Key and Secret
    agent = Cerner::OAuth1a::AccessTokenAgent.new(
              access_token_url: 'https://api.cernercare.com/oauth/access',
              consumer_key: 'CONSUMER_KEY',
              consumer_secret: 'CONSUMER_SECRET')

    # Retrieve an AccessToken instance
    access_token = agent.retrieve

    # Setup the HTTP library to access the protected API you want to invoke
    uri = URI('https://authz-demo-api.cerner.com/me')
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true if uri.scheme == 'https'

    # Invoke the API's HTTP endpoint and use the AccessToken to generate an Authorization header
    response = http.request_get(uri.path, Authorization: access_token.authorization_header)

## Access Token Reuse
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

## References
* https://wiki.ucern.com/display/public/reference/Cerner%27s+OAuth+Specification
  * http://oauth.net/core/1.0a
  * http://oauth.pbwiki.com/ProblemReporting
* https://wiki.ucern.com/display/public/reference/Accessing+Cerner%27s+Web+Services+Using+OAuth+1.0a

# Building

This project is built using Ruby 2.2+, Rake and Bundler. RSpec is used for unit tests and SimpleCov
is utilized for test coverage.

# Availability

This RubyGem will be available on https://rubygems.org/.

# Communication

All questions, bugs, enhancements and pull requests can be submitted here, on GitHub via Issues.

# Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

# LICENSE

Copyright 2017 Cerner Innovation, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

&nbsp;&nbsp;&nbsp;&nbsp;http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
