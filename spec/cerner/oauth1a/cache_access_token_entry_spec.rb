# frozen_string_literal: true

require 'cerner/oauth1a/cache'

RSpec.describe Cerner::OAuth1a::Cache::AccessTokenEntry do
  describe '#initialize' do
    it 'stores the value' do
      at = double('AccessToken')
      ate = Cerner::OAuth1a::Cache::AccessTokenEntry.new(at)
      expect(ate.value).to be(at)
    end
  end

  describe '#expired?' do
    it 'returns false, when now is behind expiration' do
      now = Time.now.utc.to_i
      at = double('AccessToken')
      ate = Cerner::OAuth1a::Cache::AccessTokenEntry.new(at)
      expect(at).to receive(:expired?).with(now: now - 10).and_return(false)
      expect(ate.expired?(now - 10)).to be false
    end

    it 'returns true, when now is ahead of expiration' do
      now = Time.now.utc.to_i
      at = double('AccessToken')
      ate = Cerner::OAuth1a::Cache::AccessTokenEntry.new(at)
      expect(at).to receive(:expired?).with(now: now + 10).and_return(true)
      expect(ate.expired?(now + 10)).to be true
    end
  end
end
