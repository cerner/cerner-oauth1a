# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'uri'

module Cerner
  module OAuth1a
    # Public: Keys for authenticating Access Tokens by service providers. Keys can be retrieved
    # via AccessTokenAgent#retrieve_keys.
    class Keys
      # Returns the String version identifier of the keys.
      attr_reader :version
      # Returns the String AES secret key.
      attr_reader :aes_secret_key
      # Returns the String RSA public key.
      attr_reader :rsa_public_key

      # Public: Constructs an instance.
      #
      # arguments - The keyword arguments of the method:
      #             :version        - The version identifier of the keys.
      #             :aes_secret_key - The AES secret key.
      #             :rsa_public_key - The RSA public key.
      #
      # Raises ArgumentError if version, aes_secret_key or rsa_public_key is nil.
      def initialize(version:, aes_secret_key:, rsa_public_key:)
        raise ArgumentError, 'version is nil' unless version
        raise ArgumentError, 'aes_secret_key is nil' unless aes_secret_key
        raise ArgumentError, 'rsa_public_key is nil' unless rsa_public_key

        @version = version
        @aes_secret_key = aes_secret_key
        @rsa_public_key = rsa_public_key
      end

      # Public: Compare this to other based on attributes.
      #
      # other - The Keys to compare this to.
      #
      # Return true if equal; false otherwise
      def ==(other)
        version == other.version &&
          aes_secret_key == other.aes_secret_key &&
          rsa_public_key == other.rsa_public_key
      end

      # Public: Compare this to other based on attributes.
      #
      # other - The Keys to compare this to.
      #
      # Return true if equal; false otherwise
      def eql?(other)
        self == other
      end

      # Public: Generates a Hash of the attributes.
      #
      # Returns a Hash with keys for each attribute.
      def to_h
        {
          version: @version,
          aes_secret_key: @aes_secret_key,
          rsa_public_key: @rsa_public_key
        }
      end

      # Public: Returns the #rsa_public_key as an OpenSSL::PKey::RSA intance.
      #
      # Raises OpenSSL::PKey::RSAError if #rsa_public_key is not a valid key
      def rsa_public_key_as_pkey
        OpenSSL::PKey::RSA.new(@rsa_public_key)
      end

      # Public: Verifies that an oauth_token is authentic based on the #rsa_public_key.
      #
      # oauth_token - The oauth_token value to verify.
      #
      # Returns true if authentic; false otherwise.
      #
      # Raises ArgumentError if oauth_token is nil or invalid
      # Raises OpenSSL::PKey::RSAError if #rsa_public_key is not a valid key
      def verify_rsasha1_signature(oauth_token)
        raise ArgumentError, 'oauth_token is nil' unless oauth_token

        message, raw_sig = oauth_token.split('&RSASHA1=')
        raise ArgumentError, 'unable to get message out of oauth_token' unless message
        raise ArgumentError, 'unable to get RSASHA1 signature out of oauth_token' unless raw_sig

        # URL decode value and Base64 (urlsafe) decode that result
        sig = Base64.urlsafe_decode64(URI.decode_www_form_component(raw_sig))
        rsa_public_key_as_pkey.verify(OpenSSL::Digest::SHA1.new, sig, message)
      end

      # Public: Decrypts the HMACSecrets parameter of an oauth_token using the #aes_secret_key.
      #
      # hmac_secrets_param - The extracted value of the HMACSecrets parameter of an oauth_token. The
      #                      value is assumed to be Base64 (URL safe) encoded.
      #
      # Returns the decrypted secrets.
      #
      # Raises ArgumentError if oauth_token is nil or invalid
      def decrypt_hmac_secrets(hmac_secrets_param)
        raise ArgumentError, 'hmac_secrets_param is nil' unless hmac_secrets_param

        ciphertext = Base64.urlsafe_decode64(hmac_secrets_param)
        raise ArgumentError, 'hmac_secrets_param does not contain enough data' unless ciphertext.size > 16

        # extract first 16 bytes to get initialization vector
        iv = ciphertext[0, 16]
        # trim off the IV
        ciphertext = ciphertext[16..-1]

        cipher = OpenSSL::Cipher.new('AES-128-CBC')
        # invoke #decrypt to prep the instance
        cipher.decrypt
        cipher.iv = iv
        cipher.key = @aes_secret_key
        text = cipher.update(ciphertext) + cipher.final
        text
      end
    end
  end
end
