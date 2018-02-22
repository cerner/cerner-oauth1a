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
    end
  end
end
