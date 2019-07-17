# frozen_string_literal: true

require 'cerner/oauth1a/cache'
require 'simple_entry'

RSpec.describe(Cerner::OAuth1a::Cache::DefaultCache) do
  describe '#initialize' do
    it 'requires max option' do
      expect { Cerner::OAuth1a::Cache::DefaultCache.new }.to(raise_error(ArgumentError))
    end
  end

  let(:cache) { Cerner::OAuth1a::Cache::DefaultCache.new(max: 2) }

  describe '#put' do
    it 'stores multiple entries' do
      se1 = SimpleEntry.new(value: 'val1')
      se2 = SimpleEntry.new(value: 'val2')
      cache.put(nil, 'key1', se1)
      cache.put(nil, 'key2', se2)
      expect(cache.get(nil, 'key1')).to(be(se1))
      expect(cache.get(nil, 'key2')).to(be(se2))
    end

    it 'stores new entry, evicts based on max size' do
      se1 = SimpleEntry.new(value: 'val1')
      se2 = SimpleEntry.new(value: 'val2')
      se3 = SimpleEntry.new(value: 'val3')
      cache.put(nil, 'key1', se1)
      cache.put(nil, 'key2', se2)
      cache.put(nil, 'key3', se3)
      expect(cache.get(nil, 'key1')).to(be_nil)
      expect(cache.get(nil, 'key2')).to(be(se2))
      expect(cache.get(nil, 'key3')).to(be(se3))
    end

    it 'stores new entry, evicts based on expiration' do
      se1 = SimpleEntry.new(value: 'val1')
      se2 = SimpleEntry.new(value: 'val2')
      cache.put(nil, 'key1', se1)
      se1.expired = true
      cache.put(nil, 'key2', se2)
      expect(cache.get(nil, 'key1')).to(be_nil)
      expect(cache.get(nil, 'key2')).to(be(se2))
    end
  end

  describe '#get' do
    it 'retrieves a stored entry' do
      se1 = SimpleEntry.new(value: 'val1')
      cache.put(nil, 'key1', se1)
      expect(cache.get(nil, 'key1')).to(be(se1))
    end

    it 'does not retrieve an expired entry' do
      se1 = SimpleEntry.new(value: 'val1')
      cache.put(nil, 'key1', se1)
      expect(cache.get(nil, 'key1')).to(be(se1))
      se1.expired = true
      expect(cache.get(nil, 'key1')).to(be_nil)
    end
  end
end
