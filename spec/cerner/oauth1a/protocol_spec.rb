# frozen_string_literal: true

require 'spec_helper'

require 'cerner/oauth1a/protocol'

RSpec.describe(Cerner::OAuth1a::Protocol) do
  describe '.percent_encode' do
    it 'returns the same value' do
      expect(Cerner::OAuth1a::Protocol.percent_encode('nothing')).to(eq('nothing'))
    end

    it 'encodes spaces with %20' do
      expect(Cerner::OAuth1a::Protocol.percent_encode('something here')).to(eq('something%20here'))
    end
  end

  describe '.realm_for' do
    it 'raises ArgumentError with nil input' do
      expect { Cerner::OAuth1a::Protocol.realm_for(nil) }.to(raise_error(ArgumentError))
    end

    context 'returns rooted and canonical URL String' do
      it 'when input includes a path' do
        expect(
          Cerner::OAuth1a::Protocol.realm_for(URI('https://oauth-api.cerner.com/oauth/access'))
        ).to(eq('https://oauth-api.cerner.com'))
      end

      it 'when input does not include a path' do
        expect(
          Cerner::OAuth1a::Protocol.realm_for(URI('https://oauth-api.cerner.com'))
        ).to(eq('https://oauth-api.cerner.com'))
      end

      it 'when input includes a port' do
        expect(
          Cerner::OAuth1a::Protocol.realm_for(URI('https://oauth-api.cerner.com:8443'))
        ).to(eq('https://oauth-api.cerner.com:8443'))
      end
    end
  end

  describe '.parse_url_query_string' do
    it 'raises ArgumentError with nil input' do
      expect { Cerner::OAuth1a::Protocol.parse_url_query_string(nil) }.to(raise_error(ArgumentError))
    end

    it 'returns Hash with unreserved chars input' do
      expect(Cerner::OAuth1a::Protocol.parse_url_query_string('a=1&b=2')).to(eq(a: '1', b: '2'))
    end

    it 'returns Hash with reserved chars input' do
      expect(Cerner::OAuth1a::Protocol.parse_url_query_string('a=1+1&b=2')).to(eq(a: '1 1', b: '2'))
    end

    it 'returns empty Hash with empty input' do
      expect(Cerner::OAuth1a::Protocol.parse_url_query_string('')).to(eq({}))
    end
  end

  describe '.generate_authorization_header' do
    context 'alias form' do
      it 'returns String when params has two entries' do
        expect(
          Cerner::OAuth1a::Protocol.generate_www_authenticate_header(key: 'value', key2: 'value2')
        ).to(eq('OAuth key="value",key2="value2"'))
      end
    end

    context 'returns nil' do
      it 'when params is nil' do
        expect(
          Cerner::OAuth1a::Protocol.generate_authorization_header(nil)
        ).to(be_nil)
      end

      it 'when params is empty' do
        expect(
          Cerner::OAuth1a::Protocol.generate_authorization_header({})
        ).to(be_nil)
      end
    end

    context 'returns String' do
      it 'when params has one entry' do
        expect(
          Cerner::OAuth1a::Protocol.generate_authorization_header(key: 'value')
        ).to(eq('OAuth key="value"'))
      end

      it 'when params has two entries' do
        expect(
          Cerner::OAuth1a::Protocol.generate_authorization_header(key: 'value', key2: 'value2')
        ).to(eq('OAuth key="value",key2="value2"'))
      end

      it 'when params has reserved character entries' do
        params = { 'key=key' => 'value1/value2' }
        expect(
          Cerner::OAuth1a::Protocol.generate_authorization_header(params)
        ).to(eq('OAuth key%3Dkey="value1%2Fvalue2"'))
      end

      context 'with the realm parameter not percent-encoded' do
        it 'when params has only the realm entry' do
          expect(
            Cerner::OAuth1a::Protocol.generate_authorization_header(realm: 'http://example.com')
          ).to(eq('OAuth realm="http://example.com"'))
        end

        it 'when params has the realm entry and another entry' do
          expect(
            Cerner::OAuth1a::Protocol.generate_authorization_header(key: 'value', realm: 'http://example.com')
          ).to(eq('OAuth realm="http://example.com",key="value"'))
        end
      end
    end
  end

  describe '.parse_www_authenticate_header' do
    it 'returns params when both are quoted-string' do
      expect(
        Cerner::OAuth1a::Protocol.parse_www_authenticate_header('OAuth realm="https://oauth-api.cerner.com",oauth_problem="token_expired"')
      ).to(eq(realm: 'https://oauth-api.cerner.com', oauth_problem: 'token_expired'))
    end

    it 'returns params when one is quoted-string and one is token' do
      expect(
        Cerner::OAuth1a::Protocol.parse_www_authenticate_header('OAuth realm="https://oauth-api.cerner.com",oauth_problem=token_expired')
      ).to(eq(realm: 'https://oauth-api.cerner.com', oauth_problem: 'token_expired'))
    end

    it 'returns params when there is whitespace' do
      expect(
        Cerner::OAuth1a::Protocol.parse_www_authenticate_header('OAuth realm="https://oauth-api.cerner.com", oauth_problem=token_expired')
      ).to(eq(realm: 'https://oauth-api.cerner.com', oauth_problem: 'token_expired'))
    end

    it 'returns param when it is token' do
      expect(
        Cerner::OAuth1a::Protocol.parse_www_authenticate_header('OAuth oauth_problem=token_expired')
      ).to(eq(oauth_problem: 'token_expired'))
    end
  end

  describe '.parse_authorization_header' do
    context 'alias form' do
      it 'returns Hash with encoded values' do
        expect(
          Cerner::OAuth1a::Protocol.parse_www_authenticate_header('OAuth oauth_token="token%23token"')
        ).to(eq(oauth_token: 'token#token'))
      end
    end

    it 'returns empty Hash with nil input' do
      expect(Cerner::OAuth1a::Protocol.parse_authorization_header(nil)).to(eq({}))
    end

    it 'returns empty Hash with empty input' do
      expect(Cerner::OAuth1a::Protocol.parse_authorization_header('')).to(eq({}))
    end

    it 'returns empty Hash with invalid prefix' do
      expect(
        Cerner::OAuth1a::Protocol.parse_authorization_header('OAuth1 oauth_version="1.0"')
      ).to(eq({}))
    end

    it 'returns Hash with non-canonical prefix' do
      expect(
        Cerner::OAuth1a::Protocol.parse_authorization_header('OAUTH oauth_version="1.0"')
      ).to(eq(oauth_version: '1.0'))
    end

    it 'returns Hash with one parameter' do
      expect(
        Cerner::OAuth1a::Protocol.parse_authorization_header('OAuth oauth_version="1.0"')
      ).to(eq(oauth_version: '1.0'))
    end

    it 'returns Hash with two parameters' do
      expect(
        Cerner::OAuth1a::Protocol.parse_authorization_header('OAuth oauth_version="1.0",oauth_token="token"')
      ).to(eq(oauth_version: '1.0', oauth_token: 'token'))
    end

    it 'returns Hash with spaces between parameters' do
      expect(
        Cerner::OAuth1a::Protocol.parse_authorization_header('OAuth oauth_version="1.0", oauth_token="token"')
      ).to(eq(oauth_version: '1.0', oauth_token: 'token'))
    end

    it 'returns Hash with encoded keys' do
      expect(
        Cerner::OAuth1a::Protocol.parse_authorization_header('OAuth oauth+token="token"')
      ).to(eq('oauth token': 'token'))
    end

    it 'returns Hash with encoded values' do
      expect(
        Cerner::OAuth1a::Protocol.parse_authorization_header('OAuth oauth_token="token%23token"')
      ).to(eq(oauth_token: 'token#token'))
    end
  end

  describe '.convert_problem_to_http_status' do
    context 'when problem is nil' do
      it 'returns default' do
        expect(
          Cerner::OAuth1a::Protocol.convert_problem_to_http_status(nil)
        ).to(eq(:unauthorized))
      end

      it 'returns overriden default' do
        expect(
          Cerner::OAuth1a::Protocol.convert_problem_to_http_status(nil, :internal_server_error)
        ).to(eq(:internal_server_error))
      end
    end

    context 'when problem is unknown' do
      it 'returns default' do
        expect(
          Cerner::OAuth1a::Protocol.convert_problem_to_http_status('DEFINITELY NOT KNOWN')
        ).to(eq(:unauthorized))
      end
    end

    context 'when problem is in BAD_REQUEST_PROBLEMS' do
      Cerner::OAuth1a::Protocol::BAD_REQUEST_PROBLEMS.each do |problem|
        it "returns :bad_request for #{problem}" do
          expect(
            Cerner::OAuth1a::Protocol.convert_problem_to_http_status(problem)
          ).to(eq(:bad_request))
        end
      end
    end

    context 'when problem is in UNAUTHORIZED_PROBLEMS' do
      Cerner::OAuth1a::Protocol::UNAUTHORIZED_PROBLEMS.each do |problem|
        it "returns :unauthorized for #{problem}" do
          expect(
            Cerner::OAuth1a::Protocol.convert_problem_to_http_status(problem)
          ).to(eq(:unauthorized))
        end
      end
    end
  end
end
