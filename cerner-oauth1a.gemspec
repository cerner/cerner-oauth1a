$LOAD_PATH.push File.expand_path('../lib', __FILE__)

require 'cerner/oauth1a/version'

Gem::Specification.new do |s|
  s.name = 'cerner-oauth1a'
  s.version = Cerner::OAuth1a::VERSION
  s.homepage = 'http://github.com/cerner/cerner-oauth1a'
  s.summary = 'Cerner OAuth 1.0a Consumer and Service Provider Library.'
  s.description = 'A minimal dependency library for interacting with a Cerner OAuth 1.0a Access ' \
                  'Token Service for invoking Cerner OAuth 1.0a protected services or ' \
                  'implementing Cerner OAuth 1.0a authentication.'
  s.licenses = ['Apache-2.0']
  s.authors = ['Nathan Beyer']
  s.email = ['nbeyer@gmail.com']

  s.files = Dir['lib/**/*.rb', 'CHANGELOG.md', 'CONTRIBUTORS.md', 'LICENSE', 'NOTICE', 'README.md']
  s.require_paths = ['lib']

  s.required_ruby_version = '>= 2.3'
end
