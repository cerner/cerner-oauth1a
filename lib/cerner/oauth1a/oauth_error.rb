# frozen_string_literal: true

require 'cerner/oauth1a/protocol'
require 'uri'

module Cerner
  module OAuth1a
    # Public: An OAuth-specific error.
    class OAuthError < StandardError
      # Returns the HTTP Response Code, if any, associated with this error. May be nil.
      attr_reader :http_response_code

      # Returns the OAuth Problem string, if any, associated with this error. May be nil.
      # See http://oauth.pbwiki.com/ProblemReporting for more information.
      attr_reader :oauth_problem

      # Returns an Array of OAuth parameter names, if any, related to #oauth_problem.
      # May be nil.
      attr_reader :oauth_parameters

      # Public: Construct an instance with a message, optional HTTP response code
      # and optional OAuth Problem string.
      #
      # message            - A descriptive message, passed to the super class.
      # http_response_code - The HTTP response code associated with the error. Optional.
      # oauth_problem      - The OAuth Problem string associated with the error. Optional.
      # oauth_parameters   - A String/Symbol or Array of Strings/Symbols containing the names of parameters that
      #                      are absent or rejected. This is should only be used when oauth_problem
      #                      is 'parameter_absent' or 'parameter_rejected' Optional.
      def initialize(
        message,
        http_response_code = nil,
        oauth_problem = nil,
        oauth_parameters = nil
      )
        @http_response_code = http_response_code
        @oauth_problem = oauth_problem
        @oauth_parameters = oauth_parameters ? Array(oauth_parameters) : nil

        parts = []
        parts << message if message
        parts << "HTTP #{@http_response_code}" if @http_response_code
        parts << "OAuth Problem #{@oauth_problem}" if @oauth_problem
        parts << "OAuth Parameters [#{@oauth_parameters.join(', ')}]" if @oauth_parameters
        super(parts.empty? ? nil : parts.join(' '))
      end

      def to_http_www_authenticate_header
        params = {}
        params[:oauth_problem] = @oauth_problem if @oauth_problem

        if @oauth_parameters
          case @oauth_problem
          when 'parameter_absent'
            params[:oauth_parameters_absent] = format_parameters(@oauth_parameters)
          when 'parameter_rejected'
            params[:oauth_parameters_rejected] = format_parameters(@oauth_parameters)
          end
        end

        Protocol.generate_www_authenticate_header(params)
      end

      def to_http_status(default = :unauthorized)
        Protocol.convert_problem_to_http_status(@oauth_problem, default)
      end

      private

      def format_parameters(params)
        params.map { |p| URI.encode_www_form_component(p).gsub('+', '%20') }.join('&')
      end
    end
  end
end
