# frozen_string_literal: true

require 'spec_helper'

require 'cerner/oauth1a/access_token'

RSpec.describe(Cerner::OAuth1a::AccessToken) do
  describe '.from_authorization_header' do
    context 'raises error' do
      it 'when oauth_version is not 1.0' do
        expect do
          Cerner::OAuth1a::AccessToken.from_authorization_header(
            'OAuth realm="realm", ' \
            'oauth_version="1.1", ' \
            'oauth_consumer_key="consumer key", ' \
            'oauth_nonce="nonce", ' \
            'oauth_timestamp="1", ' \
            'oauth_token="token", ' \
            'oauth_signature_method="PLAINTEXT", ' \
            'oauth_signature="signature"'
          )
        end.to(
          raise_error(Cerner::OAuth1a::OAuthError, /version_rejected/)
        )
      end

      it 'when oauth_consumer_key is missing' do
        expect do
          Cerner::OAuth1a::AccessToken.from_authorization_header(
            'OAuth realm="realm", ' \
            'oauth_version="1.0", ' \
            'oauth_nonce="nonce", ' \
            'oauth_timestamp="1", ' \
            'oauth_token="token", ' \
            'oauth_signature_method="PLAINTEXT", ' \
            'oauth_signature="signature"'
          )
        end.to(
          raise_error(Cerner::OAuth1a::OAuthError, /consumer_key/)
        )
      end

      it 'when oauth_token is missing' do
        expect do
          Cerner::OAuth1a::AccessToken.from_authorization_header(
            'OAuth oauth_version="1.0", ' \
            'oauth_consumer_key="consumer key", ' \
            'oauth_nonce="nonce", ' \
            'oauth_timestamp="1", ' \
            'oauth_signature_method="PLAINTEXT", ' \
            'oauth_signature="signature"'
          )
        end.to(
          raise_error(Cerner::OAuth1a::OAuthError, /token/)
        )
      end

      it 'when oauth_signature_method is missing' do
        expect do
          Cerner::OAuth1a::AccessToken.from_authorization_header(
            'OAuth oauth_version="1.0", ' \
            'oauth_consumer_key="consumer key", ' \
            'oauth_nonce="nonce", ' \
            'oauth_token="token", ' \
            'oauth_timestamp="1", ' \
            'oauth_signature="signature"'
          )
        end.to(
          raise_error(Cerner::OAuth1a::OAuthError, /signature_method/)
        )
      end
    end

    context 'does not raise error' do
      it 'when oauth_version is not present' do
        access_token = Cerner::OAuth1a::AccessToken.from_authorization_header(
          'OAuth oauth_consumer_key="consumer key", ' \
          'oauth_nonce="nonce", ' \
          'oauth_timestamp="1", ' \
          'oauth_token="token", ' \
          'oauth_signature_method="PLAINTEXT", ' \
          'oauth_signature="signature"'
        )
        expect(access_token).to(be_a(Cerner::OAuth1a::AccessToken))
      end
    end
  end

  describe '#authenticate' do
    context 'raises error' do
      it 'when access_token_agent is nil' do
        at = Cerner::OAuth1a::AccessToken.new(
          consumer_key: 'CONSUMER KEY',
          nonce: 'NONCE',
          timestamp: Time.now,
          token: 'TOKEN'
        )
        expect { at.authenticate(nil) }.to(raise_error(ArgumentError))
      end

      it 'when realm does not match agent realm' do
        at = Cerner::OAuth1a::AccessToken.new(
          consumer_key: 'CONSUMER KEY',
          nonce: 'NONCE',
          timestamp: Time.now,
          token: 'TOKEN',
          signature_method: 'REJECT_THIS',
          realm: 'REALM'
        )
        ata = double('AccessTokenAgent')
        expect(ata).to(receive(:realm).and_return('AGENT REALM'))
        expect(ata).to(receive(:realm_eql?).and_return(false))
        expect { at.authenticate(ata) }.to(raise_error do |error|
          expect(error).to(be_a(Cerner::OAuth1a::OAuthError))
          expect(error.message).to(include('token_rejected'))
          expect(error.realm).to(eq('AGENT REALM'))
        end)
      end

      it 'when signature_method is not PLAINTEXT' do
        at = Cerner::OAuth1a::AccessToken.new(
          consumer_key: 'CONSUMER KEY',
          nonce: 'NONCE',
          timestamp: Time.now,
          token: 'TOKEN',
          signature_method: 'REJECT_THIS',
          realm: 'REALM'
        )
        ata = double('AccessTokenAgent')
        expect(ata).to(receive(:realm_eql?).and_return(true))
        expect { at.authenticate(ata) }.to(raise_error do |error|
          expect(error).to(be_a(Cerner::OAuth1a::OAuthError))
          expect(error.message).to(include('signature_method_rejected'))
          expect(error.realm).to(eq('REALM'))
        end)
      end

      it 'when consumer keys do not match' do
        at = Cerner::OAuth1a::AccessToken.new(
          consumer_key: 'CONSUMER KEY',
          nonce: 'NONCE',
          timestamp: Time.now,
          token: 'ConsumerKey=WRONG%20CONSUMER%20KEY',
          realm: 'REALM'
        )
        ata = double('AccessTokenAgent')
        expect(ata).to(receive(:realm_eql?).and_return(true))
        expect { at.authenticate(ata) }.to(raise_error do |error|
          expect(error).to(be_a(Cerner::OAuth1a::OAuthError))
          expect(error.message).to(include('consumer_key_rejected'))
          expect(error.realm).to(eq('REALM'))
        end)
      end

      it 'when ExpiresOn is missing' do
        at = Cerner::OAuth1a::AccessToken.new(
          consumer_key: 'CONSUMER KEY',
          nonce: 'NONCE',
          timestamp: Time.now,
          token: 'ConsumerKey=CONSUMER%20KEY',
          realm: 'REALM'
        )
        ata = double('AccessTokenAgent')
        expect(ata).to(receive(:realm_eql?).and_return(true))
        expect { at.authenticate(ata) }.to(raise_error do |error|
          expect(error).to(be_a(Cerner::OAuth1a::OAuthError))
          expect(error.message).to(include('missing ExpiresOn'))
          expect(error.realm).to(eq('REALM'))
        end)
      end

      it 'when ExpiresOn has expired' do
        at = Cerner::OAuth1a::AccessToken.new(
          consumer_key: 'CONSUMER KEY',
          nonce: 'NONCE',
          timestamp: Time.now,
          token: "ConsumerKey=CONSUMER+KEY&ExpiresOn=#{Time.now.utc.to_i - 60}",
          realm: 'REALM'
        )
        ata = double('AccessTokenAgent')
        expect(ata).to(receive(:realm_eql?).and_return(true))
        expect { at.authenticate(ata) }.to(raise_error do |error|
          expect(error).to(be_a(Cerner::OAuth1a::OAuthError))
          expect(error.message).to(include('token_expired'))
          expect(error.realm).to(eq('REALM'))
        end)
      end

      it 'when KeysVersion is missing' do
        at = Cerner::OAuth1a::AccessToken.new(
          consumer_key: 'CONSUMER KEY',
          nonce: 'NONCE',
          timestamp: Time.now,
          token: "ConsumerKey=CONSUMER+KEY&ExpiresOn=#{Time.now.utc.to_i + 60}",
          realm: 'REALM'
        )
        ata = double('AccessTokenAgent')
        expect(ata).to(receive(:realm_eql?).and_return(true))
        expect { at.authenticate(ata) }.to(raise_error do |error|
          expect(error).to(be_a(Cerner::OAuth1a::OAuthError))
          expect(error.message).to(include('missing KeysVersion'))
          expect(error.realm).to(eq('REALM'))
        end)
      end

      it 'when retrieve_keys fails' do
        at = Cerner::OAuth1a::AccessToken.new(
          consumer_key: 'CONSUMER KEY',
          nonce: 'NONCE',
          timestamp: Time.now,
          token: "ConsumerKey=CONSUMER+KEY&ExpiresOn=#{Time.now.utc.to_i + 60}&KeysVersion=2",
          realm: 'REALM'
        )
        ata = double('AccessTokenAgent')
        expect(ata).to(
          receive(:retrieve_keys).with('2').and_raise(Cerner::OAuth1a::OAuthError, 'invalid keys')
        )
        expect(ata).to(receive(:realm_eql?).and_return(true))
        expect { at.authenticate(ata) }.to(raise_error do |error|
          expect(error).to(be_a(Cerner::OAuth1a::OAuthError))
          expect(error.message).to(include('token references invalid keys version'))
          expect(error.realm).to(eq('REALM'))
        end)
      end

      it 'when token is not authentic' do
        at = Cerner::OAuth1a::AccessToken.new(
          consumer_key: 'CONSUMER KEY',
          nonce: 'NONCE',
          timestamp: Time.now,
          token: "ConsumerKey=CONSUMER+KEY&ExpiresOn=#{Time.now.utc.to_i + 60}&KeysVersion=1",
          realm: 'REALM'
        )
        keys = double('Keys')
        expect(keys).to(receive(:verify_rsasha1_signature).and_return(false))
        ata = double('AccessTokenAgent')
        expect(ata).to(receive(:retrieve_keys).with('1').and_return(keys))
        expect(ata).to(receive(:realm_eql?).and_return(true))
        expect { at.authenticate(ata) }.to(raise_error do |error|
          expect(error).to(be_a(Cerner::OAuth1a::OAuthError))
          expect(error.message).to(include('not authentic'))
          expect(error.realm).to(eq('REALM'))
        end)
      end

      it 'when signature is missing' do
        at = Cerner::OAuth1a::AccessToken.new(
          consumer_key: 'CONSUMER KEY',
          nonce: 'NONCE',
          timestamp: Time.now,
          token: "ConsumerKey=CONSUMER+KEY&ExpiresOn=#{Time.now.utc.to_i + 60}&KeysVersion=1",
          realm: 'REALM'
        )
        keys = double('Keys')
        expect(keys).to(receive(:verify_rsasha1_signature).and_return(true))
        ata = double('AccessTokenAgent')
        expect(ata).to(receive(:retrieve_keys).with('1').and_return(keys))
        expect(ata).to(receive(:realm_eql?).and_return(true))
        expect { at.authenticate(ata) }.to(raise_error do |error|
          expect(error).to(be_a(Cerner::OAuth1a::OAuthError))
          expect(error.message).to(include('missing signature'))
          expect(error.realm).to(eq('REALM'))
        end)
      end

      it 'when HMACSecrets is missing' do
        at = Cerner::OAuth1a::AccessToken.new(
          consumer_key: 'CONSUMER KEY',
          nonce: 'NONCE',
          timestamp: Time.now,
          token: "ConsumerKey=CONSUMER+KEY&ExpiresOn=#{Time.now.utc.to_i + 60}&KeysVersion=1",
          signature: 'SIGNATURE',
          realm: 'REALM'
        )
        keys = double('Keys')
        expect(keys).to(receive(:verify_rsasha1_signature).and_return(true))
        ata = double('AccessTokenAgent')
        expect(ata).to(receive(:retrieve_keys).with('1').and_return(keys))
        expect(ata).to(receive(:realm_eql?).and_return(true))
        expect { at.authenticate(ata) }.to(raise_error do |error|
          expect(error).to(be_a(Cerner::OAuth1a::OAuthError))
          expect(error.message).to(include('missing HMACSecrets'))
          expect(error.realm).to(eq('REALM'))
        end)
      end

      it 'when HMACSecrets fail to decrypt' do
        at = Cerner::OAuth1a::AccessToken.new(
          consumer_key: 'CONSUMER KEY',
          nonce: 'NONCE',
          timestamp: Time.now,
          token: "ConsumerKey=CONSUMER+KEY&ExpiresOn=#{Time.now.utc.to_i + 60}&KeysVersion=1&HMACSecrets=SECRETS",
          signature: 'SIGNATURE',
          realm: 'REALM'
        )
        keys = double('Keys')
        expect(keys).to(receive(:verify_rsasha1_signature).and_return(true))
        expect(keys).to(receive(:decrypt_hmac_secrets).with('SECRETS').and_raise(ArgumentError, 'SIMULATED_FAILURE'))
        ata = double('AccessTokenAgent')
        expect(ata).to(receive(:retrieve_keys).with('1').and_return(keys))
        expect(ata).to(receive(:realm_eql?).and_return(true))
        expect { at.authenticate(ata) }.to(raise_error do |error|
          expect(error).to(be_a(Cerner::OAuth1a::OAuthError))
          expect(error.message).to(include('SIMULATED_FAILURE'))
          expect(error.realm).to(eq('REALM'))
        end)
      end

      it 'when signature does not match secrets' do
        at = Cerner::OAuth1a::AccessToken.new(
          consumer_key: 'CONSUMER KEY',
          nonce: 'NONCE',
          timestamp: Time.now,
          token: "ConsumerKey=CONSUMER+KEY&ExpiresOn=#{Time.now.utc.to_i + 60}&KeysVersion=1&HMACSecrets=SECRETS",
          signature: 'SIGNATURE',
          realm: 'REALM'
        )
        keys = double('Keys')
        expect(keys).to(receive(:verify_rsasha1_signature).and_return(true))
        expect(keys).to(
          receive(:decrypt_hmac_secrets)
            .with('SECRETS')
            .and_return('ConsumerSecret=CONSUMER+SECRET&TokenSecret=TOKEN+SECRET')
        )
        ata = double('AccessTokenAgent')
        expect(ata).to(receive(:retrieve_keys).with('1').and_return(keys))
        expect(ata).to(receive(:realm_eql?).and_return(true))
        expect { at.authenticate(ata) }.to(raise_error do |error|
          expect(error).to(be_a(Cerner::OAuth1a::OAuthError))
          expect(error.message).to(include('signature_invalid'))
          expect(error.realm).to(eq('REALM'))
        end)
      end
    end

    context 'returns Hash' do
      it 'that is empty' do
        at = Cerner::OAuth1a::AccessToken.new(
          consumer_key: 'CONSUMER KEY',
          nonce: 'NONCE',
          timestamp: Time.now,
          token: "ConsumerKey=CONSUMER+KEY&ExpiresOn=#{Time.now.utc.to_i + 60}&KeysVersion=1&HMACSecrets=SECRETS",
          signature: 'CONSUMER SECRET&TOKEN SECRET'
        )
        keys = double('Keys')
        expect(keys).to(receive(:verify_rsasha1_signature).and_return(true))
        expect(keys).to(
          receive(:decrypt_hmac_secrets)
            .with('SECRETS')
            .and_return('ConsumerSecret=CONSUMER+SECRET&TokenSecret=TOKEN+SECRET')
        )
        ata = double('AccessTokenAgent')
        expect(ata).to(receive(:retrieve_keys).with('1').and_return(keys))
        expect(ata).to(receive(:realm).and_return('REALM'))
        expect(at.authenticate(ata)).to(eq({}))
      end

      it 'with Consumer.Principal' do
        at = Cerner::OAuth1a::AccessToken.new(
          consumer_key: 'CONSUMER KEY',
          nonce: 'NONCE',
          timestamp: Time.now,
          token: 'Consumer.Principal=CONSUMER+PRINCIPAL&' \
            'ConsumerKey=CONSUMER+KEY&' \
            'Extra=SOMETHING&' \
            "ExpiresOn=#{Time.now.utc.to_i + 60}&" \
            'KeysVersion=1&HMACSecrets=SECRETS',
          signature: 'CONSUMER SECRET&TOKEN SECRET'
        )
        keys = double('Keys')
        expect(keys).to(receive(:verify_rsasha1_signature).and_return(true))
        expect(keys).to(
          receive(:decrypt_hmac_secrets)
            .with('SECRETS')
            .and_return('ConsumerSecret=CONSUMER+SECRET&TokenSecret=TOKEN+SECRET')
        )
        ata = double('AccessTokenAgent')
        expect(ata).to(receive(:retrieve_keys).with('1').and_return(keys))
        expect(ata).to(receive(:realm).and_return('REALM'))
        expect(at.consumer_principal).to(be(nil))
        expect(at.authenticate(ata)).to(eq('Extra': 'SOMETHING'))
        expect(at.consumer_principal).to(eq('CONSUMER PRINCIPAL'))
      end
    end

    context 'sets the realm from the agent' do
      it 'when the token realm is nil' do
        at = Cerner::OAuth1a::AccessToken.new(
          consumer_key: 'CONSUMER KEY',
          nonce: 'NONCE',
          timestamp: Time.now,
          token: "ConsumerKey=CONSUMER+KEY&ExpiresOn=#{Time.now.utc.to_i + 60}&KeysVersion=1&HMACSecrets=SECRETS",
          signature: 'CONSUMER SECRET&TOKEN SECRET'
        )
        keys = double('Keys')
        expect(keys).to(receive(:verify_rsasha1_signature).and_return(true))
        expect(keys).to(
          receive(:decrypt_hmac_secrets)
            .with('SECRETS')
            .and_return('ConsumerSecret=CONSUMER+SECRET&TokenSecret=TOKEN+SECRET')
        )
        ata = double('AccessTokenAgent')
        expect(ata).to(receive(:retrieve_keys).with('1').and_return(keys))
        expect(ata).to(receive(:realm).and_return('AGENT REALM'))
        expect(at.realm).to(be_nil)
        expect(at.authenticate(ata)).to(eq({}))
        expect(at.realm).to(eq('AGENT REALM'))
      end
    end
  end

  describe '#to_h' do
    it 'returns a Hash of attributes' do
      access_token = Cerner::OAuth1a::AccessToken.new(
        accessor_secret: 'ACCESSOR SECRET',
        consumer_key: 'CONSUMER KEY',
        expires_at: Time.at(Time.now.to_i + 1),
        nonce: 'NONCE',
        timestamp: Time.at(Time.now.to_i),
        token: 'TOKEN',
        token_secret: 'TOKEN SECRET',
        realm: 'REALM'
      )
      hash = access_token.to_h
      expect(hash[:accessor_secret]).to(eq(access_token.accessor_secret))
      expect(hash[:consumer_key]).to(eq(access_token.consumer_key))
      expect(hash[:expires_at]).to(eq(access_token.expires_at))
      expect(hash[:nonce]).to(eq(access_token.nonce))
      expect(hash[:timestamp]).to(eq(access_token.timestamp))
      expect(hash[:token]).to(eq(access_token.token))
      expect(hash[:token_secret]).to(eq(access_token.token_secret))
      expect(hash[:realm]).to(eq(access_token.realm))
    end
  end

  describe '#==' do
    let!(:current_time) { Time.at(Time.now.to_i) }
    let!(:expires_at) { Time.at(current_time.to_i + 1) }
    let!(:access_token) do
      Cerner::OAuth1a::AccessToken.new(
        accessor_secret: 'ACCESSOR SECRET',
        consumer_key: 'CONSUMER KEY',
        expires_at: expires_at,
        nonce: 'NONCE',
        timestamp: current_time,
        token: 'TOKEN',
        token_secret: 'TOKEN SECRET',
        realm: 'REALM'
      )
    end

    context 'returns true' do
      it 'when compared to self' do
        expect(access_token == access_token).to(be(true))
        expect(access_token.eql?(access_token)).to(be(true))
      end

      it 'when two instances have the same attributes' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(
          accessor_secret: 'ACCESSOR SECRET',
          consumer_key: 'CONSUMER KEY',
          expires_at: expires_at,
          nonce: 'NONCE',
          timestamp: current_time,
          token: 'TOKEN',
          token_secret: 'TOKEN SECRET',
          realm: 'REALM'
        )

        expect(access_token.object_id).not_to(eq(access_token2.object_id))
        expect(access_token == access_token2).to(be(true))
        expect(access_token.eql?(access_token2)).to(be(true))
      end

      it 'when two instances have the same attributes and authorization_header is built' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(
          accessor_secret: 'ACCESSOR SECRET',
          consumer_key: 'CONSUMER KEY',
          expires_at: expires_at,
          nonce: 'NONCE',
          timestamp: current_time,
          token: 'TOKEN',
          token_secret: 'TOKEN SECRET',
          realm: 'REALM'
        )

        expect(access_token2.authorization_header).not_to(be_nil)
        expect(access_token.object_id).not_to(eq(access_token2.object_id))
        expect(access_token == access_token2).to(be(true))
        expect(access_token.eql?(access_token2)).to(be(true))
      end
    end

    context 'returns false' do
      it 'when accessor_secret varies' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(
          accessor_secret: 'NOT ACCESSOR SECRET',
          consumer_key: 'CONSUMER KEY',
          expires_at: expires_at,
          nonce: 'NONCE',
          timestamp: current_time,
          token: 'TOKEN',
          token_secret: 'TOKEN SECRET'
        )
        expect(access_token == access_token2).to(be(false))
        expect(access_token.eql?(access_token2)).to(be(false))
      end

      it 'when consumer_key varies' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(
          accessor_secret: 'ACCESSOR SECRET',
          consumer_key: 'NOT CONSUMER KEY',
          expires_at: expires_at,
          nonce: 'NONCE',
          timestamp: current_time,
          token: 'TOKEN',
          token_secret: 'TOKEN SECRET'
        )
        expect(access_token == access_token2).to(be(false))
        expect(access_token.eql?(access_token2)).to(be(false))
      end

      it 'when expires_at varies' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(
          accessor_secret: 'ACCESSOR SECRET',
          consumer_key: 'CONSUMER KEY',
          expires_at: expires_at + 10,
          nonce: 'NONCE',
          timestamp: current_time,
          token: 'TOKEN',
          token_secret: 'TOKEN SECRET'
        )
        expect(access_token == access_token2).to(be(false))
        expect(access_token.eql?(access_token2)).to(be(false))
      end

      it 'when nonce varies' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(
          accessor_secret: 'ACCESSOR SECRET',
          consumer_key: 'CONSUMER KEY',
          expires_at: expires_at,
          nonce: 'NOT NONCE',
          timestamp: current_time,
          token: 'TOKEN',
          token_secret: 'TOKEN SECRET'
        )
        expect(access_token == access_token2).to(be(false))
        expect(access_token.eql?(access_token2)).to(be(false))
      end

      it 'when timestamp varies' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(
          accessor_secret: 'ACCESSOR SECRET',
          consumer_key: 'CONSUMER KEY',
          expires_at: expires_at,
          nonce: 'NONCE',
          timestamp: current_time + 10,
          token: 'TOKEN',
          token_secret: 'TOKEN SECRET'
        )
        expect(access_token == access_token2).to(be(false))
        expect(access_token.eql?(access_token2)).to(be(false))
      end

      it 'when token varies' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(
          accessor_secret: 'ACCESSOR SECRET',
          consumer_key: 'CONSUMER KEY',
          expires_at: expires_at,
          nonce: 'NONCE',
          timestamp: current_time,
          token: 'NOT TOKEN',
          token_secret: 'TOKEN SECRET'
        )
        expect(access_token == access_token2).to(be(false))
        expect(access_token.eql?(access_token2)).to(be(false))
      end

      it 'when token_secret varies' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(
          accessor_secret: 'ACCESSOR SECRET',
          consumer_key: 'CONSUMER KEY',
          expires_at: expires_at,
          nonce: 'NONCE',
          timestamp: current_time,
          token: 'TOKEN',
          token_secret: 'NOT TOKEN SECRET'
        )
        expect(access_token == access_token2).to(be(false))
        expect(access_token.eql?(access_token2)).to(be(false))
      end

      it 'when realm varies' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(
          accessor_secret: 'ACCESSOR SECRET',
          consumer_key: 'CONSUMER KEY',
          expires_at: expires_at,
          nonce: 'NONCE',
          timestamp: current_time,
          token: 'TOKEN',
          token_secret: 'TOKEN SECRET',
          realm: 'NOT REALM'
        )
        expect(access_token == access_token2).to(be(false))
        expect(access_token.eql?(access_token2)).to(be(false))
      end
    end
  end

  describe '#authorization_header' do
    let!(:current_time) { Time.at(Time.now.to_i) }
    let!(:expires_at) { Time.at(current_time.to_i + 1) }
    let!(:access_token) do
      Cerner::OAuth1a::AccessToken.new(
        accessor_secret: 'ACCESSOR SECRET',
        consumer_key: 'CONSUMER KEY',
        expires_at: expires_at,
        nonce: 'NONCE',
        timestamp: current_time,
        token: 'TOKEN',
        token_secret: 'TOKEN SECRET'
      )
    end

    context 'raises error' do
      it 'when signature_method is not PLAINTEXT' do
        at = Cerner::OAuth1a::AccessToken.new(
          accessor_secret: 'ACCESSOR SECRET',
          consumer_key: 'CONSUMER KEY',
          expires_at: expires_at,
          nonce: 'NONCE',
          timestamp: current_time,
          token: 'TOKEN',
          token_secret: 'TOKEN SECRET',
          signature_method: 'REJECT_THIS',
          realm: 'REALM'
        )
        expect { at.authorization_header }.to(raise_error do |error|
          expect(error).to(be_a(Cerner::OAuth1a::OAuthError))
          expect(error.message).to(include('signature_method_rejected'))
          expect(error.realm).to(eq('REALM'))
        end)
      end

      it 'when signature is calculated and token_secret is nil' do
        at = Cerner::OAuth1a::AccessToken.new(
          accessor_secret: 'ACCESSOR SECRET',
          consumer_key: 'CONSUMER KEY',
          expires_at: expires_at,
          nonce: 'NONCE',
          timestamp: current_time,
          token: 'TOKEN',
          token_secret: nil
        )
        expect { at.authorization_header }.to(raise_error(Cerner::OAuth1a::OAuthError, /parameter_absent/))
      end
    end

    it 'starts with OAuth' do
      expect(access_token.authorization_header).to(start_with('OAuth '))
    end

    it 'contains oauth_ parts' do
      expect(access_token.authorization_header).to(include('oauth_version="1.0"'))
      expect(access_token.authorization_header).to(include('oauth_signature_method="PLAINTEXT"'))
      expect(access_token.authorization_header).to(include('oauth_signature="ACCESSOR%2520SECRET%26TOKEN%2520SECRET"'))
      expect(access_token.authorization_header).to(include('oauth_consumer_key="CONSUMER%20KEY"'))
      expect(access_token.authorization_header).to(include('oauth_nonce="NONCE"'))
      expect(access_token.authorization_header).to(include('oauth_token="TOKEN"'))
      expect(access_token.authorization_header).to(match(/oauth_timestamp="\d+"/))
    end

    it 'contains populated parts' do
      at = Cerner::OAuth1a::AccessToken.new(
        accessor_secret: 'ACCESSOR SECRET',
        consumer_key: 'CONSUMER KEY',
        expires_at: expires_at,
        token: 'TOKEN',
        token_secret: 'TOKEN SECRET'
      )
      expect(at.authorization_header).to(include('oauth_version="1.0"'))
      expect(at.authorization_header).to(include('oauth_signature_method="PLAINTEXT"'))
      expect(at.authorization_header).to(include('oauth_signature="ACCESSOR%2520SECRET%26TOKEN%2520SECRET"'))
      expect(at.authorization_header).to(include('oauth_consumer_key="CONSUMER%20KEY"'))
      expect(at.authorization_header).to(include('oauth_token="TOKEN"'))
      expect(at.authorization_header).not_to(include('oauth_nonce'))
      expect(at.authorization_header).not_to(include('oauth_timestamp'))
      expect(at.authorization_header).not_to(include('realm'))
    end

    it 'does not calculate signature' do
      at = Cerner::OAuth1a::AccessToken.new(
        consumer_key: 'CONSUMER KEY',
        expires_at: expires_at,
        nonce: 'NONCE',
        timestamp: current_time,
        token: 'TOKEN',
        signature: 'SIGNATURE'
      )
      expect(at.authorization_header).to(include('oauth_signature="SIGNATURE"'))
    end
  end

  describe '#expired?' do
    it 'is expired with no arguments, because of fudge_sec' do
      access_token = Cerner::OAuth1a::AccessToken.new(
        accessor_secret: 'ACCESSOR SECRET',
        consumer_key: 'CONSUMER KEY',
        expires_at: Time.now.to_i,
        nonce: 'NONCE',
        timestamp: Time.now.to_i,
        token: 'TOKEN',
        token_secret: 'TOKEN SECRET'
      )

      expect(access_token.expired?).to(be(true))
    end

    it 'is not expired with fudge of large negative fudge_sec' do
      access_token = Cerner::OAuth1a::AccessToken.new(
        accessor_secret: 'ACCESSOR SECRET',
        consumer_key: 'CONSUMER KEY',
        expires_at: Time.now.to_i,
        nonce: 'NONCE',
        timestamp: Time.now.to_i,
        token: 'TOKEN',
        token_secret: 'TOKEN SECRET'
      )

      expect(access_token.expired?(fudge_sec: -300)).to(be(false))
    end

    it 'is expired with Time argument' do
      access_token = Cerner::OAuth1a::AccessToken.new(
        accessor_secret: 'ACCESSOR SECRET',
        consumer_key: 'CONSUMER KEY',
        expires_at: Time.now.to_i,
        nonce: 'NONCE',
        timestamp: Time.now.to_i,
        token: 'TOKEN',
        token_secret: 'TOKEN SECRET'
      )

      expect(access_token.expired?(now: Time.at(Time.now.to_i + 10))).to(be(true))
    end

    it 'is expired when expires_at and now are equal and fudge_sec of 0' do
      fixed_time = Time.now

      access_token = Cerner::OAuth1a::AccessToken.new(
        accessor_secret: 'ACCESSOR SECRET',
        consumer_key: 'CONSUMER KEY',
        expires_at: fixed_time,
        nonce: 'NONCE',
        timestamp: fixed_time,
        token: 'TOKEN',
        token_secret: 'TOKEN SECRET'
      )

      expect(access_token.expired?(now: fixed_time, fudge_sec: 0)).to(be(true))
    end
  end

  describe '#initialize' do
    it 'massages signature_method to PLAINTEXT when nil' do
      access_token = Cerner::OAuth1a::AccessToken.new(
        consumer_key: 'CONSUMER KEY',
        nonce: 'NONCE',
        timestamp: Time.now,
        token: 'TOKEN',
        signature_method: nil
      )
      expect(access_token.signature_method).to(eq('PLAINTEXT'))
    end

    it 'converts Integer to Time for expires_at' do
      fixture = Time.at(Time.now.to_i + 60)
      access_token = Cerner::OAuth1a::AccessToken.new(
        accessor_secret: 'ACCESSOR SECRET',
        consumer_key: 'CONSUMER KEY',
        expires_at: fixture.to_i,
        nonce: 'NONCE',
        timestamp: Time.now.utc,
        token: 'TOKEN',
        token_secret: 'TOKEN SECRET'
      )
      expect(access_token.expires_at).to(eq(fixture))
    end

    it 'converts Integer to Time for timestamp' do
      fixture = Time.at(Time.now.to_i)
      access_token = Cerner::OAuth1a::AccessToken.new(
        accessor_secret: 'ACCESSOR SECRET',
        consumer_key: 'CONSUMER KEY',
        expires_at: Time.now.utc,
        nonce: 'NONCE',
        timestamp: fixture.to_i,
        token: 'TOKEN',
        token_secret: 'TOKEN SECRET'
      )
      expect(access_token.timestamp).to(eq(fixture))
    end

    it 'requires a non-nil consumer_key' do
      expect do
        Cerner::OAuth1a::AccessToken.new(
          accessor_secret: 'ACCESSOR SECRET',
          consumer_key: nil,
          expires_at: Time.now.utc,
          nonce: 'NONCE',
          timestamp: Time.now.utc,
          token: 'TOKEN',
          token_secret: 'TOKEN SECRET'
        )
      end.to(raise_error(ArgumentError, /consumer_key/))
    end

    it 'requires a non-nil token' do
      expect do
        Cerner::OAuth1a::AccessToken.new(
          accessor_secret: 'ACCESSOR SECRET',
          consumer_key: 'CONSUMER KEY',
          expires_at: Time.now.utc,
          nonce: 'NONCE',
          timestamp: Time.now.utc,
          token: nil,
          token_secret: 'TOKEN SECRET'
        )
      end.to(raise_error(ArgumentError, /token/))
    end
  end
end
