# frozen_string_literal: true

require 'spec_helper'

require 'cerner/oauth1a/oauth_error'

RSpec.describe Cerner::OAuth1a::OAuthError do
  describe '#initialize' do
    it 'constructs with only a message' do
      oauth_error = Cerner::OAuth1a::OAuthError.new('MESSAGE')
      expect(oauth_error.message).to eq('MESSAGE')
      expect(oauth_error.http_response_code).to be_nil
      expect(oauth_error.oauth_problem).to be_nil
      expect(oauth_error.oauth_parameters).to be_nil
    end

    it 'constructs with nil message' do
      oauth_error = Cerner::OAuth1a::OAuthError.new(nil)
      expect(oauth_error.message).to eq(oauth_error.class.name)
      expect(oauth_error.http_response_code).to be_nil
      expect(oauth_error.oauth_problem).to be_nil
      expect(oauth_error.oauth_parameters).to be_nil
    end

    it 'constructs with message and HTTP response code' do
      oauth_error = Cerner::OAuth1a::OAuthError.new('MESSAGE', 401)
      expect(oauth_error.message).to eq('MESSAGE HTTP 401')
      expect(oauth_error.http_response_code).to eq(401)
      expect(oauth_error.oauth_problem).to be_nil
      expect(oauth_error.oauth_parameters).to be_nil
    end

    it 'constructs with message and OAuth Problem' do
      oauth_error = Cerner::OAuth1a::OAuthError.new('MESSAGE', nil, 'token_rejected')
      expect(oauth_error.message).to eq('MESSAGE OAuth Problem token_rejected')
      expect(oauth_error.http_response_code).to be_nil
      expect(oauth_error.oauth_problem).to eq('token_rejected')
      expect(oauth_error.oauth_parameters).to be_nil
    end

    it 'constructs with message, HTTP response code and OAuth Problem' do
      oauth_error = Cerner::OAuth1a::OAuthError.new('MESSAGE', 403, 'token_rejected')
      expect(oauth_error.message).to eq('MESSAGE HTTP 403 OAuth Problem token_rejected')
      expect(oauth_error.http_response_code).to eq(403)
      expect(oauth_error.oauth_problem).to eq('token_rejected')
      expect(oauth_error.oauth_parameters).to be_nil
    end

    it 'constructs with one OAuth Parameter' do
      oauth_error = Cerner::OAuth1a::OAuthError.new('MESSAGE', nil, 'parameter_absent', 'param1')
      expect(oauth_error.message).to eq('MESSAGE OAuth Problem parameter_absent OAuth Parameters [param1]')
      expect(oauth_error.oauth_problem).to eq('parameter_absent')
      expect(oauth_error.oauth_parameters).to eq(['param1'])
    end

    it 'constructs with multiple OAuth Parameter' do
      oauth_error = Cerner::OAuth1a::OAuthError.new('MESSAGE', nil, 'parameter_absent', ['param1', 'param2'])
      expect(oauth_error.message).to eq('MESSAGE OAuth Problem parameter_absent OAuth Parameters [param1, param2]')
      expect(oauth_error.oauth_problem).to eq('parameter_absent')
      expect(oauth_error.oauth_parameters).to eq(['param1', 'param2'])
    end
  end

  describe '#to_http_www_authenticate_header' do
    context 'returns nil' do
      it 'when oauth_problem is nil' do
        oe = Cerner::OAuth1a::OAuthError.new('message')
        expect(oe.to_http_www_authenticate_header).to be_nil
      end
    end

    context 'returns String' do
      it 'when oauth_problem is present' do
        oe = Cerner::OAuth1a::OAuthError.new('message', nil, 'token_rejected')
        expect(oe.to_http_www_authenticate_header).to eq('OAuth oauth_problem="token_rejected"')
      end

      context 'when oauth_problem is parameter_absent' do
        it 'and no parameters' do
          oe = Cerner::OAuth1a::OAuthError.new('message', nil, 'parameter_absent')
          expect(oe.to_http_www_authenticate_header).to eq('OAuth oauth_problem="parameter_absent"')
        end

        it 'and one parameter' do
          oe = Cerner::OAuth1a::OAuthError.new('message', nil, 'parameter_absent', 'param1')
          expect(oe.to_http_www_authenticate_header).to(
            eq('OAuth oauth_problem="parameter_absent",oauth_parameters_absent="param1"')
          )
        end

        it 'and multiple parameters' do
          oe = Cerner::OAuth1a::OAuthError.new('message', nil, 'parameter_absent', ['param1', 'param2'])
          expect(oe.to_http_www_authenticate_header).to(
            eq('OAuth oauth_problem="parameter_absent",oauth_parameters_absent="param1%26param2"')
          )
        end
      end

      context 'when oauth_problem is parameter_rejected' do
        it 'and no parameters' do
          oe = Cerner::OAuth1a::OAuthError.new('message', nil, 'parameter_rejected')
          expect(oe.to_http_www_authenticate_header).to eq('OAuth oauth_problem="parameter_rejected"')
        end

        it 'and one parameter' do
          oe = Cerner::OAuth1a::OAuthError.new('message', nil, 'parameter_rejected', 'param1')
          expect(oe.to_http_www_authenticate_header).to(
            eq('OAuth oauth_problem="parameter_rejected",oauth_parameters_rejected="param1"')
          )
        end

        it 'and multiple parameters' do
          oe = Cerner::OAuth1a::OAuthError.new('message', nil, 'parameter_rejected', ['param1', 'param2'])
          expect(oe.to_http_www_authenticate_header).to(
            eq('OAuth oauth_problem="parameter_rejected",oauth_parameters_rejected="param1%26param2"')
          )
        end
      end
    end
  end

  describe '#to_http_status' do
    it 'returns default when oauth_problem is nil' do
      oe = Cerner::OAuth1a::OAuthError.new('message')
      expect(oe.to_http_status).to eq(:unauthorized)
    end

    it 'returns default when overridden and unknown' do
      oe = Cerner::OAuth1a::OAuthError.new('message', nil, 'NOT VALID')
      expect(oe.to_http_status(:internal_server_error)).to eq(:internal_server_error)
    end
  end
end
