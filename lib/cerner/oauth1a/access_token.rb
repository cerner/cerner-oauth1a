module Cerner
  module OAuth1a

    # Public: An OAuth 1.0a Access Token.
    class AccessToken
      # Returns the String Accessor Secret related to this token.
      attr_reader :accessor_secret
      # Returns the String Consumer Key related to this token.
      attr_reader :consumer_key
      # Returns the Time this token expires at.
      attr_reader :expires_at
      # Returns the String nonce related to this token.
      attr_reader :nonce
      # Returns the Time this token was created.
      attr_reader :timestamp
      # Returns the String Token.
      attr_reader :token
      # Returns the String Token Secret related to this token.
      attr_reader :token_secret

      # Public: Constructs an instance.
      #
      # arguments - The keyword arguments of the method:
      #             :accessor_secret - The String representing the accessor secret.
      #             :consumer_key    - The String representing the consumer key.
      #             :expires_at      - A Time representing the expiration moment or any object
      #                                responding to to_i that represents the expiration moment
      #                                as the number of seconds since the epoch.
      #             :nonce           - The String representing the nonce.
      #             :expires_at      - A Time representing the creation moment or any object
      #                                responding to to_i that represents the creation moment
      #                                as the number of seconds since the epoch.
      #             :token           - The String representing the token.
      #             :token_secret    - The String representing the token secret.
      #
      # Raises ArgumentError if any of the arguments is nil
      def initialize(accessor_secret:, consumer_key:, expires_at:, nonce:, timestamp:, token:, token_secret:)
        raise ArgumentError, 'accessor_secret is nil' unless accessor_secret
        raise ArgumentError, 'consumer_key is nil' unless consumer_key
        raise ArgumentError, 'expires_at is nil' unless expires_at
        raise ArgumentError, 'nonce is nil' unless nonce
        raise ArgumentError, 'timestamp is nil' unless timestamp
        raise ArgumentError, 'token is nil' unless token
        raise ArgumentError, 'token_secret is nil' unless token_secret

        @accessor_secret = accessor_secret
        @consumer_key = consumer_key
        @expires_at = convert_to_time(expires_at)
        @nonce = nonce
        @timestamp = convert_to_time(timestamp)
        @token = token
        @token_secret = token_secret
        @authorization_header = nil
      end

      # Public: Generates a value suitable for use as an HTTP Authorization header.
      #
      # Returns a String representation of the access token.
      def authorization_header
        return @authorization_header if @authorization_header

        tuples = {
          oauth_version: '1.0',
          oauth_signature_method: 'PLAINTEXT',
          oauth_signature: "#{@accessor_secret}&#{@token_secret}",
          oauth_consumer_key: @consumer_key,
          oauth_nonce: @nonce,
          oauth_timestamp: @timestamp.tv_sec,
          oauth_token: @token
        }
        @authorization_header = "OAuth " + tuples.map { |k, v| "#{k}=\"#{URI.encode_www_form_component(v)}\"" }.join(', ')
      end

      # Public: Check whether the access token has expired. By default (with no arguments),
      # the method checks whether the token has expired based on the current time and a fudge
      # factor of 300 seconds (5 minutes). Non-default argument values can be used to see whether the
      # access token has expired at a different time and with a different fudge factor.
      #
      # now       - A Time instance to check the expiration information against. Default is Time.now.
      # fudge_sec - The number of seconds to remove from #expires_at to adjust the comparison.
      #
      # Returns true if the access token as expired; false otherwise
      def expired?(now: Time.now, fudge_sec: 300)
        now = convert_to_time(now)
        now.tv_sec >= expires_at.tv_sec - fudge_sec
      end

      # Public: Compare this to other based on attributes.
      #
      # Return true if equal; false otherwise
      def ==(other)
        accessor_secret == other.accessor_secret &&
          consumer_key == other.consumer_key &&
          expires_at == other.expires_at &&
          nonce == other.nonce &&
          timestamp == other.timestamp &&
          token == other.token &&
          token_secret == other.token_secret
      end

      # Public: Compare this to other based on the attributes. Equivalent to calling #==.
      #
      # Return true if equal; false otherwise
      def eql?(other)
        self == other
      end

      # Public: Generates a Hash of the attributes.
      #
      # Returns a Hash with keys for each attribute.
      def to_h
        {
          accessor_secret: @accessor_secret,
          consumer_key: @consumer_key,
          expires_at: @expires_at,
          nonce: @nonce,
          timestamp: @timestamp,
          token: @token,
          token_secret: @token_secret
        }
      end

      private

      # Internal: Used by #initialize and #expired? to convert data into a Time instance.
      # Returns a Time instance in the UTC time zone
      def convert_to_time(time)
        raise ArgumentError, 'time is nil' unless time
        if time.is_a? Time
          time.utc
        else
          Time.at(time.to_i).utc
        end
      end
    end

  end
end
