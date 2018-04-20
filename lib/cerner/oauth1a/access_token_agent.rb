# frozen_string_literal: true

require 'base64'
require 'cerner/oauth1a/access_token'
require 'cerner/oauth1a/keys'
require 'cerner/oauth1a/oauth_error'
require 'cerner/oauth1a/cache'
require 'cerner/oauth1a/protocol'
require 'cerner/oauth1a/version'
require 'json'
require 'net/https'
require 'securerandom'
require 'uri'

module Cerner
  module OAuth1a
    # Public: A user agent for interacting with the Cerner OAuth 1.0a Access Token service to acquire
    # consumer Access Tokens or service provider Keys.
    class AccessTokenAgent
      MIME_WWW_FORM_URL_ENCODED = 'application/x-www-form-urlencoded'

      # Returns the URI Access Token URL.
      attr_reader :access_token_url
      # Returns the String Consumer Key.
      attr_reader :consumer_key
      # Returns the String Consumer Secret.
      attr_reader :consumer_secret

      # Public: Constructs an instance of the agent.
      #
      # Caching - By default, AccessToken and Keys instances are maintained in a small, constrained
      # memory cache used by #retrieve and #retrieve_keys, respectively.
      #
      # The AccessToken cache keeps a maximum of 5 entries and prunes them when they expire. As the
      # cache is based on the #consumer_key and the 'principal' parameter, the cache has limited
      # effect. It's strongly suggested that AccessToken's be cached independently, as well.
      #
      # The Keys cache keeps a maximum of 10 entries and prunes them 24 hours after retrieval.
      #
      # arguments - The keyword arguments of the method:
      #             :access_token_url    - The String or URI of the Access Token service endpoint.
      #             :consumer_key        - The String of the Consumer Key of the account.
      #             :consumer_secret     - The String of the Consumer Secret of the account.
      #             :open_timeout        - An object responding to to_i. Used to set the timeout, in
      #                                    seconds, for opening HTTP connections to the Access Token
      #                                    service (optional, default: 5).
      #             :read_timeout        - An object responding to to_i. Used to set the timeout, in
      #                                    seconds, for reading data from HTTP connections to the
      #                                    Access Token service (optional, default: 5).
      #             :cache_keys          - A Boolean for configuring Keys caching within
      #                                    #retrieve_keys. (optional, default: true)
      #             :cache_access_tokens - A Boolean for configuring AccessToken caching within
      #                                    #retrieve. (optional, default: true)
      #
      # Raises ArgumentError if access_token_url, consumer_key or consumer_key is nil; if
      #                      access_token_url is an invalid URI.
      def initialize(
        access_token_url:,
        consumer_key:,
        consumer_secret:,
        open_timeout: 5,
        read_timeout: 5,
        cache_keys: true,
        cache_access_tokens: true
      )
        raise ArgumentError, 'consumer_key is nil' unless consumer_key
        raise ArgumentError, 'consumer_secret is nil' unless consumer_secret

        @consumer_key = consumer_key
        @consumer_secret = consumer_secret

        @access_token_url = convert_to_http_uri(access_token_url)

        @open_timeout = (open_timeout ? open_timeout.to_i : 5)
        @read_timeout = (read_timeout ? read_timeout.to_i : 5)

        @keys_cache = cache_keys ? Cache.new(max: 10) : nil
        @access_token_cache = cache_access_tokens ? Cache.new(max: 5) : nil
      end

      # Public: Retrieves the service provider keys from the configured Access Token service endpoint
      # (@access_token_url). This method will invoke #retrieve to acquire an AccessToken to request
      # the keys.
      #
      # keys_version - The version identifier of the keys to retrieve. This corresponds to the
      #                KeysVersion parameter of the oauth_token.
      #
      # Return a Keys instance upon success.
      #
      # Raises ArgumentError if keys_version is nil.
      # Raises OAuthError for any functional errors returned within an HTTP 200 response.
      # Raises StandardError sub-classes for any issues interacting with the service, such as networking issues.
      def retrieve_keys(keys_version)
        raise ArgumentError, 'keys_version is nil' unless keys_version

        if @keys_cache
          cache_entry = @keys_cache.get(keys_version)
          return cache_entry.value if cache_entry
        end

        request = retrieve_keys_prepare_request(keys_version)
        response = http_client.request(request)
        keys = retrieve_keys_handle_response(keys_version, response)
        @keys_cache&.put(keys_version, Cache::KeysEntry.new(keys, Cache::TWENTY_FOUR_HOURS))
        keys
      end

      # Public: Retrieves an AccessToken from the configured Access Token service endpoint (#access_token_url).
      # This method will use the #generate_accessor_secret, #generate_nonce and #generate_timestamp methods to
      # interact with the service, which can be overridden via a sub-class, if desired.
      #
      # principal - An optional principal identifier, which is passed via the xoauth_principal protocol parameter.
      #
      # Returns a AccessToken upon success.
      #
      # Raises OAuthError for any functional errors returned within an HTTP 200 response.
      # Raises StandardError sub-classes for any issues interacting with the service, such as networking issues.
      def retrieve(principal = nil)
        cache_key = "#{@consumer_key}&#{principal}"
        if @access_token_cache
          cache_entry = @access_token_cache.get(cache_key)
          return cache_entry.value if cache_entry
        end

        # generate token request info
        nonce = generate_nonce
        timestamp = generate_timestamp
        accessor_secret = generate_accessor_secret

        request = retrieve_prepare_request(timestamp, nonce, accessor_secret, principal)
        response = http_client.request(request)
        access_token = retrieve_handle_response(response, timestamp, nonce, accessor_secret)
        @access_token_cache&.put(cache_key, Cache::AccessTokenEntry.new(access_token))
        access_token
      end

      # Public: Generate an Accessor Secret for invocations of the Access Token service.
      #
      # Returns a String containing the secret.
      def generate_accessor_secret
        SecureRandom.uuid
      end

      # Public: Generate a Nonce for invocations of the Access Token service.
      #
      # Returns a String containing the nonce.
      def generate_nonce
        SecureRandom.hex
      end

      # Public: Generate a Timestamp for invocations of the Access Token service.
      #
      # Returns an Integer representing the number of seconds since the epoch.
      def generate_timestamp
        Time.now.to_i
      end

      private

      # Internal: Generate a User-Agent HTTP Header string
      def user_agent_string
        "cerner-oauth1a #{VERSION} (Ruby #{RUBY_VERSION})"
      end

      # Internal: Provide the HTTP client instance for invoking requests
      def http_client
        http = Net::HTTP.new(@access_token_url.host, @access_token_url.port)

        if @access_token_url.scheme == 'https'
          # if the scheme is HTTPS, then enable SSL
          http.use_ssl = true
          # make sure to verify peers
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
          # tweak the ciphers to eliminate unsafe options
          http.ciphers = 'DEFAULT:!aNULL:!eNULL:!LOW:!SSLv2:!RC4'
        end

        http.open_timeout = @open_timeout
        http.read_timeout = @read_timeout

        http
      end

      # Internal: Convert an Access Token URL into a URI with some verification checks
      #
      # access_token_url - A String URL or a URI instance
      # Returns a URI::HTTP or URI::HTTPS
      #
      # Raises ArgumentError if access_token_url is nil, invalid or not an HTTP/HTTPS URI
      def convert_to_http_uri(access_token_url)
        raise ArgumentError, 'access_token_url is nil' unless access_token_url
        if access_token_url.is_a? URI
          uri = access_token_url
        else
          begin
            uri = URI(access_token_url)
          rescue URI::InvalidURIError
            # raise argument error with cause
            raise ArgumentError, 'access_token_url is invalid'
          end
        end
        raise ArgumentError, 'access_token_url must be an HTTP or HTTPS URI' unless uri.is_a?(URI::HTTP)
        uri
      end

      # Internal: Prepare a request for #retrieve
      def retrieve_prepare_request(timestamp, nonce, accessor_secret, principal)
        # construct a POST request
        request = Net::HTTP::Post.new(@access_token_url)
        # setup the data to construct the POST's message
        params = [
          [:oauth_consumer_key, @consumer_key],
          [:oauth_signature_method, 'PLAINTEXT'],
          [:oauth_version, '1.0'],
          [:oauth_timestamp, timestamp],
          [:oauth_nonce, nonce],
          [:oauth_signature, "#{@consumer_secret}&"],
          [:oauth_accessor_secret, accessor_secret]
        ]
        params << [:xoauth_principal, principal.to_s] if principal
        # set the POST's body as a URL form-encoded string
        request.set_form(params, MIME_WWW_FORM_URL_ENCODED, charset: 'UTF-8')
        request['Accept'] = MIME_WWW_FORM_URL_ENCODED
        # Set a custom User-Agent to help identify these invocation
        request['User-Agent'] = user_agent_string
        request
      end

      # Internal: Handle a response for #retrieve
      def retrieve_handle_response(response, timestamp, nonce, accessor_secret)
        case response
        when Net::HTTPSuccess
          # Parse the HTTP response and convert it into a Symbol-keyed Hash
          tuples = Protocol.parse_url_query_string(response.body)
          # Use the parsed response to construct the AccessToken
          access_token = AccessToken.new(
            accessor_secret: accessor_secret,
            consumer_key: @consumer_key,
            expires_at: timestamp + tuples[:oauth_expires_in].to_i,
            nonce: nonce,
            timestamp: timestamp,
            token: tuples[:oauth_token],
            token_secret: tuples[:oauth_token_secret]
          )
          access_token
        else
          # Extract any OAuth Problems reported in the response
          oauth_data = Protocol.parse_authorization_header(response['WWW-Authenticate'])
          # Raise an error for a failure to acquire a token
          raise OAuthError.new('unable to acquire token', response.code, oauth_data[:oauth_problem])
        end
      end

      # Internal: Prepare a request for #retrieve_keys
      def retrieve_keys_prepare_request(keys_version)
        request = Net::HTTP::Get.new("#{@access_token_url}/keys/#{keys_version}")
        request['Accept'] = 'application/json'
        request['User-Agent'] = user_agent_string
        request['Authorization'] = retrieve.authorization_header
        request
      end

      # Internal: Handle a response for #retrieve_keys
      def retrieve_keys_handle_response(keys_version, response)
        case response
        when Net::HTTPSuccess
          parsed_response = JSON.parse(response.body)
          aes_key = parsed_response.dig('aesKey', 'secretKey')
          raise OAuthError, 'AES secret key retrieved was invalid' unless aes_key
          rsa_key = parsed_response.dig('rsaKey', 'publicKey')
          raise OAuthError, 'RSA public key retrieved was invalid' unless rsa_key
          Keys.new(
            version: keys_version,
            aes_secret_key: Base64.decode64(aes_key),
            rsa_public_key: Base64.decode64(rsa_key)
          )
        else
          # Extract any OAuth Problems reported in the response
          oauth_data = Protocol.parse_authorization_header(response['WWW-Authenticate'])
          # Raise an error for a failure to acquire keys
          raise OAuthError.new('unable to acquire keys', response.code, oauth_data[:oauth_problem])
        end
      end
    end
  end
end
