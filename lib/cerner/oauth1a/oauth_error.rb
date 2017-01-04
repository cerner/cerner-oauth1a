module Cerner
  module OAuth1a
    # Public: An OAuth-specific error.
    class OAuthError < StandardError
      # Returns the HTTP Response Code, if any, associated with this error.
      attr_reader :http_response_code
      # Returns the OAuth Problem string, if any, associated with this error.
      # See http://oauth.pbwiki.com/ProblemReporting for more information.
      attr_reader :oauth_problem

      # Public: Construct an instance with a message, optional HTTP response code
      # and optional OAuth Problem string.
      #
      # message            - A descriptive message, passed to the super class.
      # http_response_code - The HTTP response code associated with the error. Optional.
      # oauth_problem      - The OAuth Problem string associated with the error. Optional.
      def initialize(message, http_response_code=nil, oauth_problem=nil)
        @http_response_code = http_response_code
        @oauth_problem = oauth_problem
        message += " HTTP #{@http_response_code}" if @http_response_code
        message += " OAuth Problem #{@oauth_problem}" if @oauth_problem
        super message
      end
    end
  end
end
