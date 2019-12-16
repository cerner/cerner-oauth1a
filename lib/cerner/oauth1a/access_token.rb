# frozen_string_literal: true

require 'cerner/oauth1a/internal'
require 'cerner/oauth1a/oauth_error'
require 'cerner/oauth1a/protocol'
require 'cerner/oauth1a/signature'
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
        token = params[:oauth_token]
        missing_params << :oauth_token if token.nil? || token.empty?
        signature_method = params[:oauth_signature_method]
        missing_params << :oauth_signature_method if signature_method.nil? || signature_method.empty?
        signature = params[:oauth_signature]
        missing_params << :oauth_signature if signature.nil? || signature.empty?

        raise OAuthError.new('', nil, 'parameter_absent', missing_params) unless missing_params.empty?

        AccessToken.new(
          accessor_secret: params[:oauth_accessor_secret],
          consumer_key: consumer_key,
          nonce: params[:oauth_nonce],
          timestamp: params[:oauth_timestamp],
          token: token,
          signature_method: signature_method,
          signature: signature,
          realm: params[:realm]
        )
      end

      # Returns a String, but may be nil, with the Accessor Secret (oauth_accessor_secret) related
      # to this token. Note: nil and empty are considered equivalent.
      attr_reader :accessor_secret
      # Returns a String with the Consumer Key (oauth_consumer_key) related to this token.
      attr_reader :consumer_key
      # Returns a Time, but may be nil, which represents the moment when this token expires.
      attr_reader :expires_at
      # Returns a String, but may be nil, with the Nonce (oauth_nonce) related to this token. This
      # is generally only populated when parsing a token for authentication.
      attr_reader :nonce
      # Returns a Time, but may be nil, with the Timestamp (oauth_timestamp) related to this token.
      # This is generally only populated when parsing a token for authentication.
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
      #             :nonce            - The optional String representing the nonce.
      #             :timestamp        - A optional Time representing the creation moment or any
      #                                 object responding to to_i that represents the creation
      #                                 moment as the number of seconds since the epoch.
      #             :token            - The required String representing the token.
      #             :token_secret     - The optional String representing the token secret.
      #             :signature_method - The optional String representing the signature method.
      #                                 Defaults to PLAINTEXT.
      #             :signature        - The optional String representing the signature.
      #             :realm            - The optional String representing the protection realm.
      #
      # Raises ArgumentError if consumer_key or token is nil.
      def initialize(
        accessor_secret: nil,
        consumer_key:,
        expires_at: nil,
        nonce: nil,
        signature: nil,
        signature_method: 'PLAINTEXT',
        timestamp: nil,
        token:,
        token_secret: nil,
        realm: nil
      )
        raise ArgumentError, 'consumer_key is nil' unless consumer_key
        raise ArgumentError, 'token is nil' unless token

        @accessor_secret = accessor_secret || nil
        @consumer_key = consumer_key
        @consumer_principal = nil
        @expires_at = expires_at ? Internal.convert_to_time(time: expires_at, name: 'expires_at') : nil
        @nonce = nonce
        @signature = signature
        @signature_method = signature_method || 'PLAINTEXT'
        @timestamp = timestamp ? Internal.convert_to_time(time: timestamp, name: 'timestamp') : nil
        @token = token
        @token_secret = token_secret || nil
        @realm = realm || nil
      end

      # Public: Generates a value suitable for use as an HTTP Authorization header. If #signature is
      # nil, then a signature will be generated based on the #signature_method.
      #
      # PLAINTEXT Signature (preferred)
      #
      # When using PLAINTEXT signatures, no additional arguments are necessary. If an oauth_nonce
      # or oauth_timestamp are desired, then the values can be passed via the :nonce and :timestamp
      # keyword arguments. The actual signature will be constructed from the Accessor Secret
      # (#accessor_secret) and the Token Secret (#token_secret).
      #
      # HMAC-SHA1 Signature
      #
      # When using HMAC-SHA1 signatures, access to the HTTP request information is necessary. This
      # requies that additional information is passed via the keyword arguments. The required
      # information includes the HTTP method (see :http_method), the host authority & path (see
      # :fully_qualified_url) and the request parameters (see :fully_qualified_url and
      # :request_params).
      #
      # keywords - The keyword arguments:
      #            :nonce               - The optional String containing a Nonce to generate the
      #                                   header with HMAC-SHA1 signatures. When nil, a Nonce will
      #                                   be generated.
      #            :timestamp           - The optional Time or #to_i compliant object containing a
      #                                   Timestamp to generate the header with HMAC-SHA1
      #                                   signatures. When nil, a Timestamp will be generated.
      #            :http_method         - The optional String or Symbol containing a HTTP Method for
      #                                   constructing the HMAC-SHA1 signature. When nil, the value
      #                                   defualts to 'GET'.
      #            :fully_qualified_url - The optional String or URI containing the fully qualified
      #                                   URL of the HTTP API being invoked for constructing the
      #                                   HMAC-SHA1 signature. If the URL contains a query string,
      #                                   the parameters will be extracted and used in addition to
      #                                   the :request_params keyword argument.
      #            :request_params      - The optional Hash of name/value pairs containing the
      #                                   request parameters of the HTTP API being invoked for
      #                                   constructing the HMAC-SHA1 signature. Parameters passed
      #                                   here will override and augment those passed in the
      #                                   :fully_qualified_url parameter. The parameter names and
      #                                   values MUST be unencoded. See
      #                                   Protocol#parse_url_query_string for help with decoding an
      #                                   encoded query string.
      #
      # Returns a String representation of the access token.
      #
      # Raises Cerner::OAuth1a::OAuthError if #signature_method is not PLAINTEXT or if a signature
      # can't be determined.
      def authorization_header(
        nonce: nil, timestamp: nil, http_method: 'GET', fully_qualified_url: nil, request_params: nil
      )
        oauth_params = {}
        oauth_params[:oauth_version] = '1.0'
        oauth_params[:oauth_signature_method] = @signature_method
        oauth_params[:oauth_consumer_key] = @consumer_key
        oauth_params[:oauth_nonce] = nonce if nonce
        oauth_params[:oauth_timestamp] = Internal.convert_to_time(time: timestamp, name: 'timestamp').to_i if timestamp
        oauth_params[:oauth_token] = @token

        if @signature
          sig = @signature
        else
          # NOTE: @accessor_secret is always used, but an empty value is allowed and project assumes
          # that nil implies an empty value

          raise OAuthError.new('token_secret is nil', nil, 'parameter_absent', nil, @realm) unless @token_secret

          if @signature_method == 'PLAINTEXT'
            sig =
              Signature.sign_via_plaintext(client_shared_secret: @accessor_secret, token_shared_secret: @token_secret)
          elsif @signature_method == 'HMAC-SHA1'
            http_method ||= 'GET' # default to HTTP GET
            request_params ||= {} # default to no request params
            oauth_params[:oauth_nonce] = Internal.generate_nonce unless oauth_params[:oauth_nonce]
            oauth_params[:oauth_timestamp] = Internal.generate_timestamp unless oauth_params[:oauth_timestamp]

            begin
              fully_qualified_url = Internal.convert_to_http_uri(url: fully_qualified_url, name: 'fully_qualified_url')
            rescue ArgumentError => ae
              raise OAuthError.new(ae.message, nil, 'parameter_absent', nil, @realm)
            end

            query_params = fully_qualified_url.query ? Protocol.parse_url_query_string(fully_qualified_url.query) : {}
            request_params = query_params.merge(request_params)

            params = request_params.merge(oauth_params)
            signature_base_string =
              Signature.build_signature_base_string(
                http_method: http_method, fully_qualified_url: fully_qualified_url, params: params
              )

            sig =
              Signature.sign_via_hmacsha1(
                client_shared_secret: @accessor_secret,
                token_shared_secret: @token_secret,
                signature_base_string: signature_base_string
              )
          else
            raise OAuthError.new('signature_method is invalid', nil, 'signature_method_rejected', nil, @realm)
          end
        end

        oauth_params[:realm] = @realm if @realm
        oauth_params[:oauth_signature] = sig

        Protocol.generate_authorization_header(oauth_params)
      end

      # Public: Authenticates the #token against the #consumer_key, #signature and side-channel
      # secrets exchange via AccessTokenAgent#retrieve_keys. If this instance has a #realm set,
      # then it will compare it to the AccessTokenAgent#realm using the AccessTokenAgent#realm_eql?
      # method.
      #
      # access_token_agent - An instance of Cerner::OAuth1a::AccessTokenAgent configured with
      #                      appropriate credentials to retrieve secrets via
      #                      Cerner::OAuth1a::AccessTokenAgent#retrieve_keys.
      # keywords           - The keyword arguments:
      #                      :http_method         - An optional String or Symbol containing an HTTP
      #                                             method name. (default: 'GET')
      #                      :fully_qualified_url - An optional String or URI that contains the
      #                                             scheme, host, port (optional) and path of a URL.
      #                      :request_params      - An optional Hash of name/value pairs
      #                                             representing the request parameters. The keys
      #                                             and values  of the Hash will be assumed to be
      #                                             represented by the value returned from #to_s.
      #
      # Returns a Hash (symbolized keys) of any extra parameters within #token (oauth_token),
      # if authentication succeeds. In most scenarios, the Hash will be empty.
      #
      # Raises ArgumentError if access_token_agent is nil
      # Raises Cerner::OAuth1a::OAuthError with an oauth_problem if authentication fails.
      def authenticate(
        access_token_agent,
        http_method: 'GET',
        fully_qualified_url: nil,
        request_params: nil
      )
        raise ArgumentError, 'access_token_agent is nil' unless access_token_agent

        if @realm && !access_token_agent.realm_eql?(@realm)
          raise OAuthError.new('realm does not match provider', nil, 'token_rejected', nil, access_token_agent.realm)
        end

        # Set realm to the provider's realm if it's not already set
        @realm ||= access_token_agent.realm

        tuples = Protocol.parse_url_query_string(@token)

        unless @consumer_key == tuples.delete(:ConsumerKey)
          raise OAuthError.new('consumer keys do not match', nil, 'consumer_key_rejected', nil, @realm)
        end

        verify_expiration(tuples.delete(:ExpiresOn))

        keys = load_keys(access_token_agent, tuples.delete(:KeysVersion))

        verify_token(keys)
        # RSASHA1 param gets consumed in #verify_token, so remove it too
        tuples.delete(:RSASHA1)

        verify_signature(
          keys: keys,
          hmac_secrets: tuples.delete(:HMACSecrets),
          http_method: http_method,
          fully_qualified_url: fully_qualified_url,
          request_params: request_params
        )

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

        now = Internal.convert_to_time(time: now, name: 'now')
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

      # Internal: Used by #authenticate to verify the expiration time.
      def verify_expiration(expires_on)
        unless expires_on
          raise OAuthError.new('token missing ExpiresOn', nil, 'oauth_parameters_rejected', 'oauth_token', @realm)
        end

        expires_on = Internal.convert_to_time(time: expires_on, name: 'expires_on')
        now = Internal.convert_to_time(time: Time.now)

        raise OAuthError.new('token has expired', nil, 'token_expired', nil, @realm) if now.tv_sec >= expires_on.tv_sec
      end

      # Internal: Used by #authenticate to load the keys
      def load_keys(access_token_agent, keys_version)
        unless keys_version
          raise OAuthError.new('token missing KeysVersion', nil, 'oauth_parameters_rejected', 'oauth_token', @realm)
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
      def verify_token(keys)
        return if keys.verify_rsasha1_signature(@token)

        raise OAuthError.new('token is not authentic', nil, 'oauth_parameters_rejected', 'oauth_token', @realm)
      end

      # Internal: Used by #authenticate to verify the request signature.
      def verify_signature(keys:, hmac_secrets:, http_method:, fully_qualified_url:, request_params:)
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

        if @signature_method == 'PLAINTEXT'
          expected_signature =
            Signature.sign_via_plaintext(
              client_shared_secret: secrets_parts[:ConsumerSecret], token_shared_secret: secrets_parts[:TokenSecret]
            )
        elsif @signature_method == 'HMAC-SHA1'
          http_method ||= 'GET' # default to HTTP GET
          request_params ||= {} # default to no request params
          oauth_params = {
            oauth_version: '1.0', # assumes version is present
            oauth_signature_method: 'HMAC-SHA1',
            oauth_consumer_key: @consumer_key,
            oauth_nonce: @nonce,
            oauth_timestamp: @timestamp.to_i,
            oauth_token: @token
          }

          begin
            fully_qualified_url = Internal.convert_to_http_uri(url: fully_qualified_url, name: 'fully_qualified_url')
          rescue ArgumentError => ae
            raise OAuthError.new(ae.message, nil, 'parameter_absent', nil, @realm)
          end

          query_params = fully_qualified_url.query ? Protocol.parse_url_query_string(fully_qualified_url.query) : {}
          request_params = query_params.merge(request_params)

          params = request_params.merge(oauth_params)
          signature_base_string =
            Signature.build_signature_base_string(
              http_method: http_method, fully_qualified_url: fully_qualified_url, params: params
            )

          expected_signature =
            Signature.sign_via_hmacsha1(
              client_shared_secret: secrets_parts[:ConsumerSecret],
              token_shared_secret: secrets_parts[:TokenSecret],
              signature_base_string: signature_base_string
            )
        else
          raise OAuthError.new(
            'signature_method must be PLAINTEXT or HMAC-SHA1',
            nil,
            'signature_method_rejected',
            nil,
            @realm
          )
        end

        return if @signature == expected_signature

        raise OAuthError.new('signature is not valid', nil, 'signature_invalid', nil, @realm)
      end
    end
  end
end
