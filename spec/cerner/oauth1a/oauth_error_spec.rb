# frozen_string_literal: true

require 'spec_helper'

require 'cerner/oauth1a/oauth_error'

# rubocop:disable Metrics/BlockLength
RSpec.describe Cerner::OAuth1a::OAuthError do
  describe '#initialize' do
    it 'constructs with only a message' do
      oauth_error = Cerner::OAuth1a::OAuthError.new('MESSAGE')
      expect(oauth_error.message).to eq('MESSAGE')
      expect(oauth_error.http_response_code).to be_nil
      expect(oauth_error.oauth_problem).to be_nil
    end

    it 'constructs with message and HTTP response code' do
      oauth_error = Cerner::OAuth1a::OAuthError.new('MESSAGE', 401)
      expect(oauth_error.message).to eq('MESSAGE HTTP 401')
      expect(oauth_error.http_response_code).to eq(401)
      expect(oauth_error.oauth_problem).to be_nil
    end

    it 'constructs with message and OAuth Problem' do
      oauth_error = Cerner::OAuth1a::OAuthError.new('MESSAGE', nil, 'token_rejected')
      expect(oauth_error.message).to eq('MESSAGE OAuth Problem token_rejected')
      expect(oauth_error.http_response_code).to be_nil
      expect(oauth_error.oauth_problem).to eq('token_rejected')
    end

    it 'constructs with message, HTTP response code and OAuth Problem' do
      oauth_error = Cerner::OAuth1a::OAuthError.new('MESSAGE', 403, 'token_rejected')
      expect(oauth_error.message).to eq('MESSAGE HTTP 403 OAuth Problem token_rejected')
      expect(oauth_error.http_response_code).to eq(403)
      expect(oauth_error.oauth_problem).to eq('token_rejected')
    end
  end
end
# rubocop:enable Metrics/BlockLength
