# frozen_string_literal: true

require 'base64'
require 'cerner/oauth1a/protocol'
require 'openssl'
require 'uri'

module Cerner
  module OAuth1a
    # Public: OAuth 1.0a signature utilities.
    module Signature
      METHODS = ['PLAINTEXT', 'HMAC-SHA1'].freeze

      # Public: Creates a PLAINTEXT signature.
      #
      # Reference: https://tools.ietf.org/html/rfc5849#section-3.4.4
      #
      # keywords - The keyword arguments:
      #            :client_shared_secret - Either the Accessor Secret or the Consumer Secret.
      #            :token_shared_secret  - The Token Secret.
      #
      # Returns a String containing the signature.
      def self.sign_via_plaintext(client_shared_secret:, token_shared_secret:)
        client_shared_secret = Protocol.percent_encode(client_shared_secret)
        token_shared_secret = Protocol.percent_encode(token_shared_secret)
        "#{client_shared_secret}&#{token_shared_secret}"
      end

      # Public: Creates a HMAC-SHA1 signature.
      #
      # Reference: https://tools.ietf.org/html/rfc5849#section-3.4.2
      #
      # keywords - The keyword arguments:
      #            :client_shared_secret  - Either the Accessor Secret or the Consumer Secret.
      #            :token_shared_secret   - The Token Secret.
      #            :signature_base_string - The Signature Base String to sign. See
      #                                     Signature.build_signature_base_string.
      #
      # Returns a String containing the signature.
      def self.sign_via_hmacsha1(client_shared_secret:, token_shared_secret:, signature_base_string:)
        client_shared_secret = Protocol.percent_encode(client_shared_secret)
        token_shared_secret = Protocol.percent_encode(token_shared_secret)
        signature_key = "#{client_shared_secret}&#{token_shared_secret}"
        signature = OpenSSL::HMAC.digest('sha1', signature_key, signature_base_string)
        encoded_signature = Base64.encode64(signature)
        encoded_signature.delete!("\n")
        encoded_signature
      end

      # Public: Normalizes a text value as an HTTP method name for use in constructing a Signature
      # Base String.
      #
      # Reference https://tools.ietf.org/html/rfc5849#section-3.4.1.1
      #
      # http_method - A String or Symbol containing an HTTP method name.
      #
      # Returns the normalized value as a String.
      #
      # Raises ArgumentError if http_method is nil.
      def self.normalize_http_method(http_method)
        raise ArgumentError, 'http_method is nil' unless http_method

        # accepts Symbol or String
        Protocol.percent_encode(http_method.to_s.upcase)
      end

      # Public: Normalizes a fully qualified URL for use as the Base String URI in constructing a
      # Signature Base String.
      #
      # Reference https://tools.ietf.org/html/rfc5849#section-3.4.1.2
      #
      # fully_qualified_url - A String or URI that contains the scheme, host, port (optional) and
      #                       path of a URL.
      #
      # Returns the normalized value as a String.
      #
      # Raises ArgumentError if fully_qualified_url is nil.
      def self.normalize_base_string_uri(fully_qualified_url)
        raise ArgumentError, 'fully_qualified_url is nil' unless fully_qualified_url

        u = fully_qualified_url.is_a?(URI) ? fully_qualified_url : URI(fully_qualified_url)

        Protocol.percent_encode(URI("#{u.scheme}://#{u.host}:#{u.port}#{u.path}").to_s)
      end

      # Public: Normalizes the parameters (query string and OAuth parameters) for use as the
      # request parameters in constructing a Signature Base String.
      #
      # Reference: https://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
      #
      # params - A Hash of name/value pairs representing the parameters. The keys and values of the
      #          Hash will be assumed to be represented by the value returned from #to_s.
      #
      # Returns the normalized value as a String.
      #
      # Raises ArgumentError if params is nil.
      def self.normalize_parameters(params)
        raise ArgumentError, 'params is nil' unless params

        encoded_params =
          params.map do |name, value|
            result = [Protocol.percent_encode(name.to_s), nil]
            result[1] =
              if value.is_a?(Array)
                value = value.map { |e| Protocol.percent_encode(e.to_s) }
                value.sort
              else
                Protocol.percent_encode(value.to_s)
              end
            result
          end

        sorted_params = encoded_params.sort_by { |name, _| name }

        exploded_params =
          sorted_params.map do |pair|
            name = pair[0]
            value = pair[1]
            if value.is_a?(Array)
              value.map { |e| "#{name}=#{e}" }
            else
              "#{name}=#{value}"
            end
          end
        exploded_params.flatten!

        joined_params = exploded_params.join('&')
        Protocol.percent_encode(joined_params)
      end

      # Public: Builds a Signature Base String.
      #
      # keywords - The keyword arguments:
      #            :http_method         - A String or Symbol containing an HTTP method name.
      #            :fully_qualified_url - A String or URI that contains the scheme, host, port
      #                                   (optional) and path of a URL.
      #            :params              - A Hash of name/value pairs representing the parameters.
      #                                   The keys and values of the Hash will be assumed to be
      #                                   represented by the value returned from #to_s.
      #
      # Returns the Signature Base String as a String.
      #
      # Raises ArgumentError if http_method, fully_qualified_url or params is nil.
      def self.build_signature_base_string(http_method:, fully_qualified_url:, params:)
        raise ArgumentError, 'http_method is nil' unless http_method
        raise ArgumentError, 'fully_qualified_url is nil' unless fully_qualified_url
        raise ArgumentError, 'params is nil' unless params

        parts = [
          normalize_http_method(http_method),
          normalize_base_string_uri(fully_qualified_url),
          normalize_parameters(params)
        ]
        parts.join('&')
      end
    end
  end
end
