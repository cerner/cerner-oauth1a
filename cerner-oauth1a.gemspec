$LOAD_PATH.push File.expand_path('../lib', __FILE__)

require 'cerner/oauth1a/version'

Gem::Specification.new do |s|
  s.name = 'cerner-oauth1a'
  s.version = Cerner::OAuth1a::VERSION
  s.homepage = 'http://github.com/cerner/cerner-oauth1a'
  s.summary = 'B2B/two-legged OAuth 1.0a service client.'
  s.description = 'A minimal dependency client library for two-legged OAuth'\
                  '1.0a service providers, such as Cerner\'s OAuth 1.0a'\
                  'provider.'
  s.authors = ['Nathan Beyer']
  s.email = ['nbeyer@gmail.com']

  s.files = Dir['lib/**/*.rb', 'README.md']
  s.require_paths = ['lib']

  s.required_ruby_version = '>= 2.2'
end
