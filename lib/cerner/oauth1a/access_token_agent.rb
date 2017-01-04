require 'cerner/oauth1a/access_token'
require 'cerner/oauth1a/oauth_error'
require 'cerner/oauth1a/version'
require 'net/https'
require 'securerandom'
require 'uri'

module Cerner
  module OAuth1a

    # Public: A User Agent for interacting with the Access Token service to acquire
    # Access Tokens.
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
      # arguments - The keyword arguments of the method:
      #             :access_token_url - The String or URI of the Access Token service endpoint.
      #             :consumer_key     - The String of the Consumer Key of the account.
      #             :consumer_secret  - The String of the Consumer Secret of the account.
      #             :open_timeout     - An object responding to to_i. Used to set the timeout, in seconds,
      #                                 for opening HTTP connections to the Access Token service (optional, default: 5).
      #             :read_timeout     - An object responding to to_i. Used to set the timeout, in seconds,
      #                                 for reading data from HTTP connections to the Access Token service (optional, default: 5).
      #
      # Raises ArgumentError if access_token_url, consumer_key or consumer_key is nil; if access_token_url is
      #                      an invalid URI.
      def initialize(access_token_url:, consumer_key:, consumer_secret:, open_timeout: 5, read_timeout: 5)
        raise ArgumentError, 'consumer_key is nil' unless consumer_key
        raise ArgumentError, 'consumer_secret is nil' unless consumer_secret

        @consumer_key = consumer_key
        @consumer_secret = consumer_secret

        @access_token_url = convert_to_http_uri(access_token_url)

        @open_timeout = (open_timeout ? open_timeout.to_i : 5)
        @read_timeout = (read_timeout ? read_timeout.to_i : 5)
      end

      # Public: Retrives an AccessToken from the configured Access Token service endpoint (#access_token_url).
      # This method will the #generate_accessor_secret, #generate_nonce and #generate_timestamp methods to
      # interact with the service, which can be overridden via a sub-class, if desired.
      #
      # Returns a AccessToken upon success.
      #
      # Raises OAuthError unless the service returns a HTTP Status Code of 200.
      # Raises StandardError sub-classes for any issues interacting with the service.
      def retrieve
        # construct a POST request
        request = Net::HTTP::Post.new @access_token_url

        # setup the data to construct the POST's message
        accessor_secret = generate_accessor_secret
        nonce = generate_nonce
        timestamp = generate_timestamp
        params = [
                  [:oauth_consumer_key, @consumer_key],
                  [:oauth_signature_method, 'PLAINTEXT'],
                  [:oauth_version, '1.0'],
                  [:oauth_timestamp, timestamp],
                  [:oauth_nonce, nonce],
                  [:oauth_signature, "#{@consumer_secret}&"],
                  [:oauth_accessor_secret, accessor_secret]
                 ]
        # set the POST's body as a URL form-encoded string
        request.set_form(params, MIME_WWW_FORM_URL_ENCODED, charset: 'UTF-8')

        request['Accept'] = MIME_WWW_FORM_URL_ENCODED
        # Set a custom User-Agent to help identify these invocation
        request['User-Agent'] = "cerner-oauth1a #{VERSION} (Ruby #{RUBY_VERSION})"

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

        response = http.request request

        case response
        when Net::HTTPSuccess
          # Part the HTTP response and convert it into a Symbol-keyed Hash
          tuples = Hash[URI.decode_www_form(response.body).map { |pair| [pair[0].to_sym, pair[1]] }]
          # Use the parsed response to construct the AccessToken
          access_token = AccessToken.new(accessor_secret: accessor_secret,
                                         consumer_key: @consumer_key,
                                         expires_at: timestamp + tuples[:oauth_expires_in].to_i,
                                         nonce: nonce,
                                         timestamp: timestamp,
                                         token: tuples[:oauth_token],
                                         token_secret: tuples[:oauth_token_secret])
          access_token
        else
          # Extract any OAuth Problems reported in the response
          oauth_data = parse_www_authenticate(response['WWW-Authenticate'])
          # Raise an error for a failure to acquire a token
          raise OAuthError.new('unable to acquire token', response.code, oauth_data['oauth_problem'])
        end
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

      # Internal: Parse a WWW-Authenticate HTTP header for any OAuth
      # information, which is indicated by a value starting with 'OAuth '.
      #
      # value - The String containing the header value.
      #
      # Returns a Hash containing any name-value pairs found in the value.
      def parse_www_authenticate(value)
        return {} unless value
        value = value.strip
        return {} unless value.start_with?('OAuth ')

        Hash[value.scan(/([^\s=]*)=\"([^\"]*)\"/)]
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
          rescue URI::InvalidURIError => e
            # raise argument error with cause
            raise ArgumentError, 'access_token_url is invalid'
          end
        end
        unless uri.is_a? URI::HTTP
          raise ArgumentError, 'access_token_url must be an HTTP or HTTPS URI'
        end
        uri
      end
    end

  end
end
