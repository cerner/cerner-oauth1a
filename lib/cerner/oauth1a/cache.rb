# frozen_string_literal: true

module Cerner
  module OAuth1a
    # Internal: A simple cache abstraction for use by AccessTokenAgent only.
    class Cache
      # Internal: A cache entry class for Keys values.
      class KeysEntry
        attr_reader :value

        def initialize(keys, expires_in)
          @value = keys
          @expires_at = Time.now.utc.to_i + expires_in
        end

        def expired?(now)
          @expires_at <= now
        end
      end

      # Internal: A cache entry class for AccessToken values.
      class AccessTokenEntry
        attr_reader :value

        def initialize(access_token)
          @value = access_token
        end

        def expired?(now)
          @value.expired?(now: now)
        end
      end

      ONE_HOUR = 3600
      TWENTY_FOUR_HOURS = 24 * ONE_HOUR

      def initialize(max:)
        @max = max
        @lock = Mutex.new
        @entries = {}
      end

      def put(key, entry)
        @lock.synchronize do
          now = Time.now.utc.to_i
          prune_expired(now)
          @entries[key] = entry
          prune_size
        end
      end

      def get(key)
        @lock.synchronize do
          prune_expired(Time.now.utc.to_i)
          @entries[key]
        end
      end

      private

      def prune_expired(now)
        return if @entries.empty?

        @entries.delete_if { |_, v| v.expired?(now) }

        nil
      end

      def prune_size
        return if @entries.empty? || @entries.size <= @max

        num_to_prune = @entries.size - @max
        num_to_prune.times { @entries.shift }

        nil
      end
    end
  end
end
