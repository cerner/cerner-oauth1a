# frozen_string_literal: true

require 'uri'

module Cerner
  module OAuth1a
    # Public: OAuth 1.0a protocol utilities.
    module Protocol
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

      # Public: Parses an OAuth HTTP Authorization scheme values, which can manifest
      # in either HTTP Authorization or WWW-Authenticate headers.
      #
      # https://oauth.net/core/1.0a/#auth_header
      #
      # value - String containing the value to parse. If nil or doesn't begin with
      #         'OAuth ', then an empty Hash will be returned.
      #
      # Returns a Hash with symbolized keys of all of the parameters.
      def self.parse_authorization_header(value)
        params = {}
        return params unless value

        value = value.strip
        return params unless value.start_with?('OAuth ')

        value.scan(/([^,\s=]*)=\"([^\"]*)\"/).each do |pair|
          k = URI.decode_www_form_component(pair[0])
          v = URI.decode_www_form_component(pair[1])
          params[k.to_sym] = v
        end

        params
      end

      # Public: The oauth_problem values that are mapped to HTTP 400 Bad Request.
      # The values come from http://wiki.oauth.net/w/page/12238543/ProblemReporting
      # and are mapped based on https://oauth.net/core/1.0/#rfc.section.10.
      BAD_REQUEST_PROBLEMS = %w[
        additional_authorization_required parameter_absent parameter_rejected
        signature_method_rejected timestamp_refused verifier_invalid
        version_rejected
      ].freeze

      # Public: The oauth_problem values that are mapped to HTTP 401 Unauthorized.
      # The values come from http://wiki.oauth.net/w/page/12238543/ProblemReporting
      # and are mapped based on https://oauth.net/core/1.0/#rfc.section.10.
      UNAUTHORIZED_PROBLEMS = %w[
        consumer_key_refused consumer_key_rejected consumer_key_unknown
        nonce_used permission_denied permission_unknown signature_invalid
        token_expired token_rejected token_revoked token_used user_refused
      ].freeze

      # Public: Converts a oauth_problem value to an HTTP Status using the
      # mappings in ::BAD_REQUEST_PROBLEMS and ::UNAUTHORIZED_PROBLEMS.
      #
      # problem - A String containing the oauth_problem value.
      # default - An optional Symbol containing the value to return if an
      #           unknown problem value is passed. Defaults to :unauthorized.
      #
      # Returns :unauthorized, :bad_request or the value passed in the default
      # parameter.
      def self.convert_problem_to_http_status(problem, default = :unauthorized)
        return default unless problem
        problem = problem.to_s
        return :unauthorized if UNAUTHORIZED_PROBLEMS.include?(problem)
        return :bad_request if BAD_REQUEST_PROBLEMS.include?(problem)
        default
      end
    end
  end
end
