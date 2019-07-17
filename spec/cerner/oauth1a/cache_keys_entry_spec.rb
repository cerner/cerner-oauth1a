# frozen_string_literal: true

require 'cerner/oauth1a/cache'

RSpec.describe(Cerner::OAuth1a::Cache::KeysEntry) do
  describe '#initialize' do
    it 'stores the value' do
      ke = Cerner::OAuth1a::Cache::KeysEntry.new('keys', 1)
      expect(ke.value).to(be('keys'))
    end
  end

  describe '#expired?' do
    it 'returns false, when now is behind expiration' do
      now = Time.now.utc.to_i
      ke = Cerner::OAuth1a::Cache::KeysEntry.new('keys', 0)
      expect(ke.expired?(now - 10)).to(be(false))
    end

    it 'returns true, when now is ahead of expiration' do
      now = Time.now.utc.to_i
      ke = Cerner::OAuth1a::Cache::KeysEntry.new('keys', 0)
      expect(ke.expired?(now + 10)).to(be(true))
    end
  end
end
