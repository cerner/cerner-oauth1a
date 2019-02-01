# frozen_string_literal: true

require 'cerner/oauth1a/oauth_error'
require 'cerner/oauth1a/protocol'
require 'uri'

module Cerner
  module OAuth1a

    # Public: A Cerner OAuth 1.0a Access Token and related request parameters for use in Consumer or
    # Service Provider use cases.
    class AccessToken
      # Public: Constructs an AccessToken using the value of an HTTP Authorization Header based on
      # the OAuth HTTP Authorization Scheme (https://oauth.net/core/1.0a/#auth_header).
      #
      # value - A String containing the HTTP Authorization Header value.
      #
      # Returns an AccessToken.
      #
      # Raises a Cerner::OAuth1a::OAuthError with a populated oauth_problem if any of the parameters
      # in the value are invalid.
      def self.from_authorization_header(value)
        params = Protocol.parse_authorization_header(value)

        if params[:oauth_version] && !params[:oauth_version].eql?('1.0')
          raise OAuthError.new('', nil, 'version_rejected')
        end

        missing_params = []
        consumer_key = params[:oauth_consumer_key]
        missing_params << :oauth_consumer_key if consumer_key.nil? || consumer_key.empty?
        nonce = params[:oauth_nonce]
        missing_params << :oauth_nonce if nonce.nil? || nonce.empty?
        timestamp = params[:oauth_timestamp]
        missing_params << :oauth_timestamp if timestamp.nil? || timestamp.empty?
        token = params[:oauth_token]
        missing_params << :oauth_token if token.nil? || token.empty?
        signature_method = params[:oauth_signature_method]
        missing_params << :oauth_signature_method if signature_method.nil? || signature_method.empty?
        signature = params[:oauth_signature]
        missing_params << :oauth_signature if signature.nil? || signature.empty?

        raise OAuthError.new('', nil, 'parameter_absent', missing_params) unless missing_params.empty?

        AccessToken.new(
          consumer_key: consumer_key,
          nonce: nonce,
          timestamp: timestamp,
          token: token,
          signature_method: signature_method,
          signature: signature,
          realm: params[:realm]
        )
      end

      # Returns a String, but may be nil, with the Accessor Secret related to this token.
      attr_reader :accessor_secret
      # Returns a String with the Consumer Key (oauth_consumer_key) related to this token.
      attr_reader :consumer_key
      # Returns a Time, but may be nil, which represents the moment when this token expires.
      attr_reader :expires_at
      # Returns a String with the Nonce (oauth_nonce) related to this token.
      attr_reader :nonce
      # Returns a Time, which represents the moment when this token was created (oauth_timestamp).
      attr_reader :timestamp
      # Returns a String with the Token (oauth_token).
      attr_reader :token
      # Returns a String, but may be nil, with the Token Secret related to this token.
      attr_reader :token_secret
      # Returns a String with the Signature Method (oauth_signature_method) related to this token.
      attr_reader :signature_method
      # Returns a String, but may be nil, with the Signature (oauth_signature) related to this token.
      attr_reader :signature
      # Returns a String with the Consumer Principal (Consumer.Principal param encoded within oauth_token).
      # This value is only populated after a successful #authenticate and only if the #token (oauth_token)
      # contains a 'Consumer.Principal' parameter.
      attr_reader :consumer_principal
      # Returns a String, but may be nil, with the Protection Realm related to this token.
      attr_reader :realm

      # Public: Constructs an instance.
      #
      # arguments - The keyword arguments of the method:
      #             :accessor_secret  - The optional String representing the accessor secret.
      #             :consumer_key     - The required String representing the consumer key.
      #             :expires_at       - An optional Time representing the expiration moment or any
      #                                 object responding to to_i that represents the expiration
      #                                 moment as the number of seconds since the epoch.
      #             :nonce            - The required String representing the nonce.
      #             :timestamp        - A required Time representing the creation moment or any
      #                                 object responding to to_i that represents the creation
      #                                 moment as the number of seconds since the epoch.
      #             :token            - The required String representing the token.
      #             :token_secret     - The required String representing the token secret.
      #             :signature_method - The optional String representing the signature method.
      #                                 Defaults to PLAINTEXT.
      #             :signature        - The optional String representing the signature.
      #                                 Defaults to nil.
      #             :realm            - The optional String representing the protection realm.
      #                                 Defaults to nil.
      #
      # Raises ArgumentError if consumer_key, nonce, timestamp, token or signature_method is nil.
      def initialize(
        accessor_secret: nil,
        consumer_key:,
        expires_at: nil,
        nonce:,
        signature: nil,
        signature_method: 'PLAINTEXT',
        timestamp:,
        token:,
        token_secret: nil,
        realm: nil
      )
        raise ArgumentError, 'consumer_key is nil' unless consumer_key
        raise ArgumentError, 'nonce is nil' unless nonce
        raise ArgumentError, 'timestamp is nil' unless timestamp
        raise ArgumentError, 'token is nil' unless token

        @accessor_secret = accessor_secret || nil
        @authorization_header = nil
        @consumer_key = consumer_key
        @consumer_principal = nil
        @expires_at = expires_at ? convert_to_time(expires_at) : nil
        @nonce = nonce
        @signature = signature
        @signature_method = signature_method || 'PLAINTEXT'
        @timestamp = convert_to_time(timestamp)
        @token = token
        @token_secret = token_secret || nil
        @realm = realm || nil
      end

      # Public: Generates a value suitable for use as an HTTP Authorization header. If #signature is
      # nil, then #accessor_secret and #token_secret will be used to build a signature via the
      # PLAINTEXT method.
      #
      # Returns a String representation of the access token.
      #
      # Raises Cerner::OAuth1a::OAuthError if #signature_method is not PLAINTEXT or if a signature
      # can't be determined.
      def authorization_header
        return @authorization_header if @authorization_header

        unless @signature_method == 'PLAINTEXT'
          raise OAuthError.new('signature_method must be PLAINTEXT', nil, 'signature_method_rejected', nil, @realm)
        end

        if @signature
          sig = @signature
        elsif @accessor_secret && @token_secret
          sig = "#{@accessor_secret}&#{@token_secret}"
        else
          raise OAuthError.new('accessor_secret or token_secret is nil', nil, 'parameter_absent', nil, @realm)
        end

        tuples = {
          realm: @realm,
          oauth_version: '1.0',
          oauth_signature_method: @signature_method,
          oauth_signature: sig,
          oauth_consumer_key: @consumer_key,
          oauth_nonce: @nonce,
          oauth_timestamp: @timestamp.tv_sec,
          oauth_token: @token
        }
        @authorization_header = Protocol.generate_authorization_header(tuples)
      end

      # Public: Authenticates the #token against the #consumer_key, #signature and side-channel
      # secrets exchange via AccessTokenAgent#retrieve_keys.
      #
      # access_token_agent - An instance of Cerner::OAuth1a::AccessTokenAgent configured with
      #                      appropriate credentials to retrieve secrets via
      #                      Cerner::OAuth1a::AccessTokenAgent#retrieve_keys.
      #
      # Returns a Hash (symbolized keys) of any extra parameters within #token (oauth_token),
      # if authentication succeeds. In most scenarios, the Hash will be empty.
      #
      # Raises ArgumentError if access_token_agent is nil
      # Raises Cerner::OAuth1a::OAuthError with an oauth_problem if authentication fails.
      def authenticate(access_token_agent)
        raise ArgumentError, 'access_token_agent is nil' unless access_token_agent

        if @realm && !@realm.eql?(access_token_agent.realm)
          raise OAuthError.new('realm does not match provider', nil, 'token_rejected', nil, access_token_agent.realm)
        end

        # Set realm to the provider's realm if it's not already set
        @realm ||= access_token_agent.realm

        unless @signature_method == 'PLAINTEXT'
          raise OAuthError.new('signature_method must be PLAINTEXT', nil, 'signature_method_rejected', nil, @realm)
        end

        tuples = Protocol.parse_url_query_string(@token)

        unless @consumer_key == tuples.delete(:ConsumerKey)
          raise OAuthError.new('consumer keys do not match', nil, 'consumer_key_rejected', nil, @realm)
        end

        verify_expiration(tuples.delete(:ExpiresOn))

        keys = load_keys(access_token_agent, tuples.delete(:KeysVersion))

        verify_token(keys)
        # RSASHA1 param gets consumed in #verify_token, so remove it too
        tuples.delete(:RSASHA1)

        verify_signature(keys, tuples.delete(:HMACSecrets))

        @consumer_principal = tuples.delete(:"Consumer.Principal")

        tuples
      end

      # Public: Check whether the access token has expired, if #expires_at is not nil. By default
      # (with no arguments), the method checks whether the token has expired based on the current
      # time and a fudge factor of 300 seconds (5 minutes). Non-default argument values can be used
      # to see whether the access token has expired at a different time and with a different fudge
      # factor.
      #
      # now       - A Time instance to check the expiration information against. Defaults to
      #             Time.now.
      # fudge_sec - The number of seconds to remove from #expires_at to adjust the comparison.
      #
      # Returns true if the access token is expired or #expires_at is nil; false otherwise
      def expired?(now: Time.now, fudge_sec: 300)
        # if @expires_at is nil, return true now
        return true unless @expires_at

        now = convert_to_time(now)
        now.tv_sec >= @expires_at.tv_sec - fudge_sec
      end

      # Public: Compare this to other based on attributes.
      #
      # other - The AccessToken to compare this to.
      #
      # Return true if equal; false otherwise
      def ==(other)
        accessor_secret == other.accessor_secret &&
          consumer_key == other.consumer_key &&
          expires_at == other.expires_at &&
          nonce == other.nonce &&
          timestamp == other.timestamp &&
          token == other.token &&
          token_secret == other.token_secret &&
          signature_method == other.signature_method &&
          signature == other.signature &&
          realm == other.realm
      end

      # Public: Compare this to other based on the attributes. Equivalent to calling #==.
      #
      # other - The AccessToken to compare this to.
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
          accessor_secret: @accessor_secret,
          consumer_key: @consumer_key,
          expires_at: @expires_at,
          nonce: @nonce,
          timestamp: @timestamp,
          token: @token,
          token_secret: @token_secret,
          signature_method: @signature_method,
          signature: @signature,
          consumer_principal: @consumer_principal,
          realm: @realm
        }
      end

      private

      # Internal: Used by #initialize and #expired? to convert data into a Time instance.
      #
      # time - Time or any object with a #to_i the returns an Integer.
      #
      # Returns a Time instance in the UTC time zone.
      def convert_to_time(time)
        raise ArgumentError, 'time is nil' unless time

        if time.is_a? Time
          time.utc
        else
          Time.at(time.to_i).utc
        end
      end

      # Internal: Used by #authenticate to verify the expiration time.
      #
      # expires_on - The ExpiresOn parameter of oauth_token
      #
      # Raises OAuthError if the parameter is invalid or expired
      def verify_expiration(expires_on)
        unless expires_on
          raise OAuthError.new(
            'token missing ExpiresOn',
            nil,
            'oauth_parameters_rejected',
            'oauth_token',
            @realm
          )
        end

        expires_on = convert_to_time(expires_on)
        now = convert_to_time(Time.now)
        if now.tv_sec >= expires_on.tv_sec
          raise OAuthError.new(
            'token has expired',
            nil,
            'token_expired',
            nil,
            @realm
          )
        end
      end

      def load_keys(access_token_agent, keys_version)
        unless keys_version
          raise OAuthError.new(
            'token missing KeysVersion',
            nil,
            'oauth_parameters_rejected',
            'oauth_token',
            @realm
          )
        end

        begin
          access_token_agent.retrieve_keys(keys_version)
        rescue OAuthError
          raise OAuthError.new(
            'token references invalid keys version',
            nil,
            'oauth_parameters_rejected',
            'oauth_token',
            @realm
          )
        end
      end

      # Internal: Used by #authenticate to verify the oauth_token value.
      #
      # keys - The Keys instance that contains the key used to sign the oauth_token
      #
      # Raises OAuthError if the parameter is not authentic
      def verify_token(keys)
        unless keys.verify_rsasha1_signature(@token)
          raise OAuthError.new('token is not authentic', nil, 'oauth_parameters_rejected', 'oauth_token', @realm)
        end
      end

      # Internal: Used by #authenticate to verify the request signature.
      #
      # keys         - The Keys instance that contains the key used to encrypt the HMACSecrets
      # hmac_secrets - The HMACSecrets parameter of oauth_token
      #
      # Raises OAuthError if there is no signature, the parameter is invalid or the signature does
      # not match the secrets
      def verify_signature(keys, hmac_secrets)
        unless @signature
          raise OAuthError.new('missing signature', nil, 'oauth_parameters_absent', 'oauth_signature', @realm)
        end
        unless hmac_secrets
          raise OAuthError.new('missing HMACSecrets', nil, 'oauth_parameters_rejected', 'oauth_token', @realm)
        end

        begin
          secrets = keys.decrypt_hmac_secrets(hmac_secrets)
        rescue ArgumentError, OpenSSL::PKey::RSAError => e
          raise OAuthError.new(
            "unable to decrypt HMACSecrets: #{e.message}",
            nil,
            'oauth_parameters_rejected',
            'oauth_token',
            @realm
          )
        end

        secrets_parts = Protocol.parse_url_query_string(secrets)
        expected_signature = "#{secrets_parts[:ConsumerSecret]}&#{secrets_parts[:TokenSecret]}"

        unless @signature == expected_signature
          raise OAuthError.new('signature is not valid', nil, 'signature_invalid', nil, @realm)
        end
      end
    end
  end
end
