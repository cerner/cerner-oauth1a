# frozen_string_literal: true

require 'spec_helper'

require 'cerner/oauth1a/signature'

RSpec.describe(Cerner::OAuth1a::Signature) do
  describe '.sign_via_hmacsha1' do
    it 'signs empty secrets' do
      expect(
        Cerner::OAuth1a::Signature.sign_via_hmacsha1(
          client_shared_secret: '',
          token_shared_secret: '',
          signature_base_string: 'signature'
        )
      ).to(eq('vX80J+zTatuolnnMETy5owZLHdQ='))
    end

    it 'signs secrets' do
      expect(
        Cerner::OAuth1a::Signature.sign_via_hmacsha1(
          client_shared_secret: 'css',
          token_shared_secret: 'tss',
          signature_base_string: 'signature'
        )
      ).to(eq('vYi97aRXz2cSvplKapDQvQmH/Bc='))
    end
  end

  describe '.build_signature_base_string' do
    it 'build with empty parameters' do
      expect(
        Cerner::OAuth1a::Signature.build_signature_base_string(
          http_method: 'GET',
          fully_qualified_url: 'https://example/path',
          params: {}
        )
      ).to(eq('GET&https%3A%2F%2Fexample%2Fpath&'))
    end

    it 'build with parameters' do
      expect(
        Cerner::OAuth1a::Signature.build_signature_base_string(
          http_method: 'GET',
          fully_qualified_url: 'https://example/path',
          params: { name: 'value' }
        )
      ).to(eq('GET&https%3A%2F%2Fexample%2Fpath&name%3Dvalue'))
    end
  end

  describe '.sign_via_plaintext' do
    it 'signs empty secrets' do
      expect(
        Cerner::OAuth1a::Signature.sign_via_plaintext(
          client_shared_secret: '',
          token_shared_secret: ''
        )
      ).to(eq('&'))
    end

    it 'signs secrets' do
      expect(
        Cerner::OAuth1a::Signature.sign_via_plaintext(
          client_shared_secret: 'css',
          token_shared_secret: 'tss'
        )
      ).to(eq('css&tss'))
    end

    it 'encodes secrets' do
      expect(
        Cerner::OAuth1a::Signature.sign_via_plaintext(
          client_shared_secret: 'c s s',
          token_shared_secret: 't s s'
        )
      ).to(eq('c%20s%20s&t%20s%20s'))
    end
  end

  describe '.normalize_parameters' do
    it 'raises ArgumentError with nil input' do
      expect { Cerner::OAuth1a::Signature.normalize_parameters(nil) }.to(raise_error(ArgumentError))
    end

    context 'normalizes' do
      it 'parameter from Strings' do
        expect(Cerner::OAuth1a::Signature.normalize_parameters('name' => 'value')).to(
          eq('name%3Dvalue')
        )
      end

      it 'sorts names' do
        expect(Cerner::OAuth1a::Signature.normalize_parameters('n2' => 'v2', 'n1' => 'v1')).to(
          eq('n1%3Dv1%26n2%3Dv2')
        )
      end

      it 'sorts values' do
        expect(Cerner::OAuth1a::Signature.normalize_parameters('n' => ['v2', 'v1'])).to(
          eq('n%3Dv1%26n%3Dv2')
        )
      end

      it 'encodes name and value' do
        expect(Cerner::OAuth1a::Signature.normalize_parameters('n 1' => 'v 1')).to(
          eq('n%25201%3Dv%25201')
        )
      end
    end
  end

  describe '.normalize_base_string_uri' do
    it 'raises ArgumentError with nil input' do
      expect { Cerner::OAuth1a::Signature.normalize_base_string_uri(nil) }.to(raise_error(ArgumentError))
    end

    context 'normalizes' do
      it 'a simple URL in String' do
        expect(Cerner::OAuth1a::Signature.normalize_base_string_uri('http://example/path')).to(
          eq('http%3A%2F%2Fexample%2Fpath')
        )
      end

      it 'a simple URL in URI' do
        expect(Cerner::OAuth1a::Signature.normalize_base_string_uri(URI('http://example/path'))).to(
          eq('http%3A%2F%2Fexample%2Fpath')
        )
      end

      it 'a complex URL in String' do
        expect(Cerner::OAuth1a::Signature.normalize_base_string_uri('http://example:8080/path?n=v')).to(
          eq('http%3A%2F%2Fexample%3A8080%2Fpath')
        )
      end

      it 'a complex URL in URI' do
        expect(Cerner::OAuth1a::Signature.normalize_base_string_uri(URI('http://example:8080/path?n=v'))).to(
          eq('http%3A%2F%2Fexample%3A8080%2Fpath')
        )
      end
    end
  end

  describe '.normalize_http_method' do
    it 'raises ArgumentError with nil input' do
      expect { Cerner::OAuth1a::Signature.normalize_http_method(nil) }.to(raise_error(ArgumentError))
    end

    context 'normalizes' do
      it 'a lower case Symbol' do
        expect(Cerner::OAuth1a::Signature.normalize_http_method(:get)).to(eq('GET'))
      end

      it 'a mixed case Symbol' do
        expect(Cerner::OAuth1a::Signature.normalize_http_method(:Get)).to(eq('GET'))
      end

      it 'a lower case String' do
        expect(Cerner::OAuth1a::Signature.normalize_http_method('put')).to(eq('PUT'))
      end

      it 'a mixed case String' do
        expect(Cerner::OAuth1a::Signature.normalize_http_method('Post')).to(eq('POST'))
      end

      it 'a custom method' do
        expect(Cerner::OAuth1a::Signature.normalize_http_method('Fun Times')).to(eq('FUN%20TIMES'))
      end
    end
  end
end
