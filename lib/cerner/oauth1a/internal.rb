# frozen_string_literal: true

require 'securerandom'
require 'uri'

module Cerner
  module OAuth1a
    # Internal: Internal utility methods
    module Internal
      # Internal: Convert a time value into a Time instance.
      #
      # keywords - The keyword arguments:
      #            :time - Time or any object with a #to_i that returns an Integer.
      #            :name - The parameter name of the data for invoking methods.
      #
      # Returns a Time instance in the UTC time zone.
      def self.convert_to_time(time:, name: 'time')
        raise ArgumentError, "#{name} is nil" unless time

        if time.is_a?(Time)
          time.utc
        else
          Time.at(time.to_i).utc
        end
      end
      # Internal: Convert an fully qualified URL String into a URI with some verification checks
      #
      # keywords - The keyword arguments:
      #            :url  - A String or a URI instance to convert to a URI instance.
      #            :name - The parameter name of the URL for invoking methods.
      #
      # Returns a URI::HTTP or URI::HTTPS
      #
      # Raises ArgumentError if url is nil, invalid or not an HTTP/HTTPS URI
      def self.convert_to_http_uri(url:, name: 'url')
        raise ArgumentError, "#{name} is nil" unless url

        if url.is_a?(URI)
          uri = url
        else
          begin
            uri = URI(url)
          rescue URI::InvalidURIError
            # raise argument error with cause
            raise ArgumentError, "#{name} is invalid"
          end
        end

        raise ArgumentError, "#{name} must be an HTTP or HTTPS URI" unless uri.is_a?(URI::HTTP)

        uri
      end

      # Internal: Generate a Nonce for invocations of the Access Token service.
      #
      # Returns a String containing the nonce.
      def self.generate_nonce
        SecureRandom.hex
      end

      # Internal: Generate a Timestamp for invocations of the Access Token service.
      #
      # Returns an Integer representing the number of seconds since the epoch.
      def self.generate_timestamp
        Time.now.to_i
      end
    end
  end
end
