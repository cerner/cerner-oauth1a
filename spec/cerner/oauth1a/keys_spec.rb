# frozen_string_literal: true

require 'spec_helper'

require 'base64'
require 'cerner/oauth1a/keys'
require 'openssl'
require 'uri'

RSpec.describe(Cerner::OAuth1a::Keys) do
  describe '#initialize' do
    it 'raises ArgumentError on nil version' do
      expect { Cerner::OAuth1a::Keys.new(version: nil, aes_secret_key: '', rsa_public_key: '') }.to(
        raise_error(ArgumentError, /version/)
      )
    end

    it 'raises ArgumentError on nil aes_secret_key' do
      expect { Cerner::OAuth1a::Keys.new(version: '', aes_secret_key: nil, rsa_public_key: '') }.to(
        raise_error(ArgumentError, /aes_secret_key/)
      )
    end

    it 'raises ArgumentError on nil rsa_public_key' do
      expect { Cerner::OAuth1a::Keys.new(version: '', aes_secret_key: '', rsa_public_key: nil) }.to(
        raise_error(ArgumentError, /rsa_public_key/)
      )
    end

    it 'populates attributes' do
      keys = Cerner::OAuth1a::Keys.new(version: '1', aes_secret_key: '123456', rsa_public_key: '123456')
      expect(keys.version).to(eq('1'))
      expect(keys.aes_secret_key).to(eq('123456'))
      expect(keys.rsa_public_key).to(eq('123456'))
    end
  end

  describe '#==' do
    let(:keys) { Cerner::OAuth1a::Keys.new(version: '1', aes_secret_key: '123456', rsa_public_key: '123456') }

    context 'returns true' do
      it 'when compared to self' do
        expect(keys == keys).to(be(true))
        expect(keys.eql?(keys)).to(be(true))
      end

      it 'when two instances have same attributes' do
        keys2 = Cerner::OAuth1a::Keys.new(version: '1', aes_secret_key: '123456', rsa_public_key: '123456')
        expect(keys.object_id).not_to(eq(keys2.object_id))
        expect(keys == keys2).to(be(true))
        expect(keys.eql?(keys2)).to(be(true))
      end
    end

    context 'returns false' do
      it 'when version varies' do
        keys2 = Cerner::OAuth1a::Keys.new(version: '2', aes_secret_key: '123456', rsa_public_key: '123456')
        expect(keys == keys2).to(be(false))
        expect(keys.eql?(keys2)).to(be(false))
      end

      it 'when aes_secret_key varies' do
        keys2 = Cerner::OAuth1a::Keys.new(version: '1', aes_secret_key: '789012', rsa_public_key: '123456')
        expect(keys == keys2).to(be(false))
        expect(keys.eql?(keys2)).to(be(false))
      end

      it 'when rsa_public_key varies' do
        keys2 = Cerner::OAuth1a::Keys.new(version: '1', aes_secret_key: '123456', rsa_public_key: '789012')
        expect(keys == keys2).to(be(false))
        expect(keys.eql?(keys2)).to(be(false))
      end
    end
  end

  describe '#to_h' do
    it 'returns Hash of attributes' do
      hash = Cerner::OAuth1a::Keys.new(
        version: '1',
        aes_secret_key: '123456',
        rsa_public_key: '123456'
      ).to_h

      expect(hash.size).to(eq(3))
      expect(hash[:version]).to(eq('1'))
      expect(hash[:aes_secret_key]).to(eq('123456'))
      expect(hash[:rsa_public_key]).to(eq('123456'))
    end
  end

  describe '#rsa_public_key_as_pkey' do
    it 'returns valid PKey' do
      pkey = OpenSSL::PKey::RSA.generate(1024)
      keys = Cerner::OAuth1a::Keys.new(version: '1', aes_secret_key: '123456', rsa_public_key: pkey.to_pem)
      actual = keys.rsa_public_key_as_pkey
      expect(actual.to_pem).to(eq(pkey.to_pem))
    end

    it 'raises error when invalid' do
      keys = Cerner::OAuth1a::Keys.new(version: '1', aes_secret_key: '123456', rsa_public_key: '123456')
      expect { keys.rsa_public_key_as_pkey }.to(raise_error(OpenSSL::PKey::RSAError))
    end
  end

  describe '#verify_rsasha1_signature' do
    context 'raises error' do
      let(:keys) { Cerner::OAuth1a::Keys.new(version: '1', aes_secret_key: '123456', rsa_public_key: '123456') }

      it 'when oauth_token is nil' do
        expect { keys.verify_rsasha1_signature(nil) }.to(raise_error(ArgumentError))
      end

      it 'when oauth_token has no message' do
        expect { keys.verify_rsasha1_signature('') }.to(raise_error(ArgumentError))
      end

      it 'when oauth_token has no RSASHA1 param' do
        expect { keys.verify_rsasha1_signature('message') }.to(raise_error(ArgumentError))
      end

      it 'when rsa_public_key is not a valid key' do
        expect { keys.verify_rsasha1_signature('message&RSASHA1=abc') }.to(raise_error(OpenSSL::PKey::RSAError))
      end
    end

    it 'returns true when message is authentic' do
      pkey = OpenSSL::PKey::RSA.generate(1024)
      keys = Cerner::OAuth1a::Keys.new(version: '1', aes_secret_key: '123456', rsa_public_key: pkey.to_pem)
      digest = OpenSSL::Digest::SHA1.new
      sig = pkey.sign(digest, 'message')
      oauth_token = "message&RSASHA1=#{URI.encode_www_form_component(Base64.urlsafe_encode64(sig)).tr('+', '%20')}"
      expect(keys.verify_rsasha1_signature(oauth_token)).to(be(true))
    end

    it 'returns false when message is not authentic' do
      pkey = OpenSSL::PKey::RSA.generate(1024)
      keys = Cerner::OAuth1a::Keys.new(version: '1', aes_secret_key: '123456', rsa_public_key: pkey.to_pem)
      digest = OpenSSL::Digest::SHA1.new
      sig = pkey.sign(digest, 'message')
      oauth_token = "NOT+message&RSASHA1=#{URI.encode_www_form_component(Base64.urlsafe_encode64(sig)).tr('+', '%20')}"
      expect(keys.verify_rsasha1_signature(oauth_token)).to(be(false))
    end
  end

  describe '#decrypt_hmac_secrets' do
    context 'raises error' do
      let(:keys) { Cerner::OAuth1a::Keys.new(version: '1', aes_secret_key: '123456', rsa_public_key: '123456') }

      it 'when hmac_secrets_param is nil' do
        expect { keys.decrypt_hmac_secrets(nil) }.to(raise_error(ArgumentError, /nil/))
      end

      it 'when hmac_secrets_param is invalid base 64' do
        expect { keys.decrypt_hmac_secrets('invalid') }.to(raise_error(ArgumentError))
      end

      it 'when hmac_secrets_param is too short' do
        expect { keys.decrypt_hmac_secrets(Base64.urlsafe_encode64('short')) }.to(
          raise_error(ArgumentError, /enough data/)
        )
      end
    end

    it 'returns decrypted text' do
      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.encrypt
      iv = cipher.random_iv
      key = cipher.random_key
      ciphertext = cipher.update('secret message') + cipher.final
      keys = Cerner::OAuth1a::Keys.new(version: '1', aes_secret_key: key, rsa_public_key: '123456')
      ciphertext = iv + ciphertext
      expect(keys.decrypt_hmac_secrets(Base64.urlsafe_encode64(ciphertext))).to(eq('secret message'))
    end
  end
end
