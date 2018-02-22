# frozen_string_literal: true

require 'spec_helper'

require 'cerner/oauth1a/protocol'

# rubocop:disable Metrics/BlockLength
RSpec.describe Cerner::OAuth1a::Protocol do
  describe '.parse_url_query_string' do
    it 'raises ArgumentError with nil input' do
      expect { Cerner::OAuth1a::Protocol.parse_url_query_string(nil) }.to raise_error ArgumentError
    end

    it 'returns Hash with unreserved chars input' do
      expect(Cerner::OAuth1a::Protocol.parse_url_query_string('a=1&b=2')).to eq(a: '1', b: '2')
    end

    it 'returns Hash with reserved chars input' do
      expect(Cerner::OAuth1a::Protocol.parse_url_query_string('a=1+1&b=2')).to eq(a: '1 1', b: '2')
    end

    it 'returns empty Hash with empty input' do
      expect(Cerner::OAuth1a::Protocol.parse_url_query_string('')).to eq({})
    end
  end

  describe '.parse_authorization_header' do
    it 'returns empty Hash with nil input' do
      expect(Cerner::OAuth1a::Protocol.parse_authorization_header(nil)).to eq({})
    end

    it 'returns empty Hash with empty input' do
      expect(Cerner::OAuth1a::Protocol.parse_authorization_header('')).to eq({})
    end

    it 'returns empty Hash with invalid prefix' do
      expect(
        Cerner::OAuth1a::Protocol.parse_authorization_header('oauth oauth_version="1.0"')
      ).to eq({})
    end

    it 'returns Hash with one parameter' do
      expect(
        Cerner::OAuth1a::Protocol.parse_authorization_header('OAuth oauth_version="1.0"')
      ).to eq(oauth_version: '1.0')
    end

    it 'returns Hash with two parameters' do
      expect(
        Cerner::OAuth1a::Protocol.parse_authorization_header('OAuth oauth_version="1.0",oauth_token="token"')
      ).to eq(oauth_version: '1.0', oauth_token: 'token')
    end

    it 'returns Hash with spaces between parameters' do
      expect(
        Cerner::OAuth1a::Protocol.parse_authorization_header('OAuth oauth_version="1.0", oauth_token="token"')
      ).to eq(oauth_version: '1.0', oauth_token: 'token')
    end

    it 'returns Hash with encoded keys' do
      expect(
        Cerner::OAuth1a::Protocol.parse_authorization_header('OAuth oauth+token="token"')
      ).to eq('oauth token': 'token')
    end

    it 'returns Hash with encoded values' do
      expect(
        Cerner::OAuth1a::Protocol.parse_authorization_header('OAuth oauth_token="token%23token"')
      ).to eq(oauth_token: 'token#token')
    end
  end
end
# rubocop:enable Metrics/BlockLength
