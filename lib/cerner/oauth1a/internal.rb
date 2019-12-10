# frozen_string_literal: true

require 'uri'

module Cerner
  module OAuth1a
    # Internal: Internal utility methods
    module Internal
      # Internal: Convert an fully qualified URL String into a URI with some verification checks
      #
      # keywords - The keyword arguments:
      #            :url  - A String or a URI instance to convert to a URI instance.
      #            :name - The parameter name of the URL for invoking methods.
      #
      # Returns a URI::HTTP or URI::HTTPS
      #
      # Raises ArgumentError if url is nil, invalid or not an HTTP/HTTPS URI
      def self.convert_to_http_uri(url: nil, name: 'url')
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
    end
  end
end
