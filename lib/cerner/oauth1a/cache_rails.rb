# frozen_string_literal: true

module Cerner
  module OAuth1a
    # Internal: A Railtie that initializer the cache implementation to use Rails.cache.
    # This will be picked up automatically if ::Rails and ::Rails.cache are defined.
    class CacheRailtie < ::Rails::Railtie
      initializer 'cerner-oauth1a.cache_initialization' do |_app|
        ::Rails.logger.info("#{CacheRailtie.name}: configuring cache to use Rails.cache")
        Cerner::OAuth1a::Cache.instance = RailsCache.new(::Rails.cache)
      end
    end

    # Internal: An implementation of the Cerner::OAuth1a::Cache interface that utilizes
    # ::Rails.cache.
    class RailsCache < Cerner::OAuth1a::Cache
      # Internal: Constructs an instance with a instance of ActiveSupport::Cache::Store, which
      # is generally ::Rails.cache.
      #
      # rails_cache - An instance of ActiveSupport::Cache::Store.
      def initialize(rails_cache)
        @cache = rails_cache
      end

      # Internal: Writes the entry to the cache store.
      #
      # namespace - The namespace for the cache entries.
      # key       - The key for the cache entries, which is qualified by namespace.
      # entry     - The entry to be stored in the cache.
      def put(namespace, key, entry)
        @cache.write(key, entry, namespace: namespace, expires_in: entry.expires_in, race_condition_ttl: 5)
      end

      # Internal: Retrieves the entry, if available, from the cache store.
      #
      # namespace - The namespace for the cache entries.
      # key       - The key for the cache entries.
      def get(namespace, key)
        @cache.read(key, namespace: namespace)
      end
    end
  end
end
