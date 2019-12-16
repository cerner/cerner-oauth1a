# frozen_string_literal: true

module Cerner
  module OAuth1a
    # Internal: A simple cache abstraction for use by AccessTokenAgent only.
    class Cache
      @cache_instance_lock = Mutex.new

      # Internal: Sets the singleton instance.
      def self.instance=(cache_impl)
        raise ArgumentError, 'cache_impl must not be nil' unless cache_impl

        @cache_instance_lock.synchronize { @cache_instance = cache_impl }
      end

      # Internal: Gets the singleton instance.
      def self.instance
        @cache_instance_lock.synchronize do
          return @cache_instance if @cache_instance

          @cache_instance = DefaultCache.new(max: 50)
        end
      end

      # Internal: A cache entry class for Keys values.
      class KeysEntry
        attr_reader :value
        attr_reader :expires_in

        # Internal: Constructs an instance.
        def initialize(keys, expires_in)
          @value = keys
          @expires_in = expires_in
          @expires_at = Time.now.utc.to_i + @expires_in
        end

        # Internal: Check if the entry is expired.
        def expired?(now)
          @expires_at <= now
        end
      end

      # Internal: A cache entry class for AccessToken values.
      class AccessTokenEntry
        attr_reader :value

        # Internal: Constructs an instance.
        def initialize(access_token)
          @value = access_token
        end

        # Internal: Returns the number of seconds until the entry expires.
        def expires_in
          @value.expires_at.to_i - Time.now.utc.to_i
        end

        # Internal: Check if the entry is expired.
        def expired?(now)
          @value.expired?(now: now)
        end
      end

      ONE_HOUR = 3_600
      TWENTY_FOUR_HOURS = 24 * ONE_HOUR

      # Internal: The default implementation of the Cerner::OAuth1a::Cache interface.
      # This implementation just maintains a capped list of entries in memory.
      class DefaultCache < Cerner::OAuth1a::Cache
        # Internal: Constructs an instance.
        def initialize(max:)
          super()
          @max = max
          @lock = Mutex.new
          @entries = {}
        end

        # Internal: Puts an entry into the cache.
        def put(namespace, key, entry)
          @lock.synchronize do
            now = Time.now.utc.to_i
            prune_expired(now)
            @entries[full_key(namespace, key)] = entry
            prune_size
          end
        end

        # Internal: Gets an entry from the cache.
        def get(namespace, key)
          @lock.synchronize do
            prune_expired(Time.now.utc.to_i)
            @entries[full_key(namespace, key)]
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

      # Internal: The base constructor for the interface.
      def initialize; end

      # Internal: The abstract operation for putting (storing) data in the cache.
      #
      # namespace - The namespace for the cache entries.
      # key       - The key for the cache entries, which is qualified by namespace.
      # entry     - The entry to be stored in the cache.
      def put(namespace, key, entry); end

      # Internal: Retrieves the entry, if available, from the cache store.
      #
      # namespace - The namespace for the cache entries.
      # key       - The key for the cache entries.
      def get(namespace, key); end

      # Internal: Constructs a single, fully qualified key based on the namespace and key value
      # passed.
      #
      # namespace - The namespace for the cache entries.
      # key       - The key for the cache entries.
      def full_key(namespace, key)
        "#{namespace}:#{key}"
      end
    end
  end
end
