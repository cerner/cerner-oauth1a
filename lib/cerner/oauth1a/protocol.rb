# frozen_string_literal: true

require 'uri'

module Cerner
  module OAuth1a
    # Public: OAuth 1.0a protocol utilities.
    module Protocol
      # Public: Encodes the passed text using the percent encoding variant described in the OAuth
      # 1.0a specification.
      #
      # Reference: https://tools.ietf.org/html/rfc5849#section-3.6
      #
      # text - A String containing the text to encode.
      #
      # Returns a String that has been encoded.
      def self.percent_encode(text)
        URI.encode_www_form_component(text).gsub('+', '%20')
      end

      # Public: Parses a URL-encoded query string into a Hash with symbolized keys.
      #
      # query - String containing a URL-encoded query string to parse.
      #
      # Returns a Hash with symbolized keys matching the query parameter names.
      #
      # Raises ArgumentError if query is nil.
      def self.parse_url_query_string(query)
        raise ArgumentError, 'query is nil' unless query

        Hash[URI.decode_www_form(query).map { |pair| [pair[0].to_sym, pair[1]] }]
      end

      # Public: Parses an OAuth HTTP Authorization scheme value, which can manifest
      # in either an HTTP Authorization or WWW-Authenticate header.
      #
      # Reference: https://oauth.net/core/1.0a/#auth_header
      #
      # value - String containing the value to parse. If nil or doesn't begin with
      #         'OAuth ', then an empty Hash will be returned.
      #
      # Examples
      #
      #   header = 'OAuth oauth_version="1.0", oauth_token="XYZ"'
      #   Cerner::OAuth1a::Protocol.parse_authorization_header(header)
      #   # => {:oauth_version=>"1.0", :oauth_token=>"XYZ"}
      #
      #   header = 'OAuth realm="https://test.host", oauth_problem="token_expired"'
      #   Cerner::OAuth1a::Protocol.parse_www_authenticate_header(header)
      #   # => {:realm=>"https://test.host", :oauth_problem=>"token_expired"}
      #
      # Returns a Hash with symbolized keys of all of the parameters.
      def self.parse_authorization_header(value)
        params = {}
        return params unless value

        value = value.strip
        return params unless value.size > 6 && value[0..5].casecmp?('OAuth ')

        value.scan(/([^,\s=]*)=\"([^\"]*)\"/).each do |pair|
          k = URI.decode_www_form_component(pair[0])
          v = URI.decode_www_form_component(pair[1])
          params[k.to_sym] = v
        end

        params
      end

      # Public: Generates an OAuth HTTP Authorization scheme value, which can be
      # in either an HTTP Authorization or WWW-Authenticate header.
      #
      # Reference: https://oauth.net/core/1.0a/#auth_header
      #
      # params - Hash containing the key-value pairs to build the value with.
      #
      # Examples
      #
      #   params = { oauth_version: '1.0', oauth_token: 'XYZ' }
      #   Cerner::OAuth1a::Protocol.generate_authorization_header(params)
      #   # => "OAuth oauth_version=\"1.0\",oauth_token=\"XYZ\""
      #
      #   params = { realm: 'https://test.host', oauth_problem: 'token_expired' }
      #   Cerner::OAuth1a::Protocol.generate_www_authenticate_header(params)
      #   # => "OAuth realm=\"https://test.host\",oauth_problem=\"token_expired\""
      #
      # Returns the String containing the generated value or nil if params is nil or empty.
      def self.generate_authorization_header(params)
        return unless params && !params.empty?

        realm = "realm=\"#{params.delete(:realm)}\"" if params[:realm]
        realm += ',' if realm && !params.empty?

        encoded_params = params.map { |k, v| "#{percent_encode(k)}=\"#{percent_encode(v)}\"" }

        "OAuth #{realm}#{encoded_params.join(',')}"
      end

      # Alias the parse and generate methods
      class << self
        # Public: Alias for Protocol.parse_authorization_header
        alias parse_www_authenticate_header parse_authorization_header

        # Public: Alias for Protocol.generate_www_authenticate_header
        alias generate_www_authenticate_header generate_authorization_header
      end

      # Public: The oauth_problem values that are mapped to HTTP 400 Bad Request.
      # The values come from http://wiki.oauth.net/w/page/12238543/ProblemReporting
      # and are mapped based on https://oauth.net/core/1.0/#rfc.section.10.
      BAD_REQUEST_PROBLEMS = %w[
        additional_authorization_required
        parameter_absent
        parameter_rejected
        signature_method_rejected
        timestamp_refused
        verifier_invalid
        version_rejected
      ].freeze

      # Public: The oauth_problem values that are mapped to HTTP 401 Unauthorized.
      # The values come from http://wiki.oauth.net/w/page/12238543/ProblemReporting
      # and are mapped based on https://oauth.net/core/1.0/#rfc.section.10.
      UNAUTHORIZED_PROBLEMS = %w[
        consumer_key_refused
        consumer_key_rejected
        consumer_key_unknown
        nonce_used
        permission_denied
        permission_unknown
        signature_invalid
        token_expired
        token_rejected
        token_revoked
        token_used
        user_refused
      ].freeze

      # Public: Converts a oauth_problem value to an HTTP Status using the
      # mappings in ::BAD_REQUEST_PROBLEMS and ::UNAUTHORIZED_PROBLEMS.
      #
      # problem - A String containing the oauth_problem value.
      # default - An optional Symbol containing the value to return if an
      #           unknown problem value is passed. Defaults to :unauthorized.
      #
      # Returns :unauthorized, :bad_request or the value passed in the default
      #   parameter.
      def self.convert_problem_to_http_status(problem, default = :unauthorized)
        return default unless problem

        problem = problem.to_s

        return :unauthorized if UNAUTHORIZED_PROBLEMS.include?(problem)

        return :bad_request if BAD_REQUEST_PROBLEMS.include?(problem)

        default
      end

      # Public: Returns a String containing a realm value from the URI. The
      # String will be a rooted (path removed) and canonicalized URL of the
      # URL passed.
      #
      # uri - A URI instance containing the URL to construct the realm for.
      #
      # Returns a String containing the realm value.
      #
      # Raises ArgumentError if uri is nil.
      def self.realm_for(uri)
        raise ArgumentError, 'uri is nil' unless uri

        realm = URI("#{uri.scheme}://#{uri.host}:#{uri.port}")
        realm.to_s
      end
    end
  end
end
