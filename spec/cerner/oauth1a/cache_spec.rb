# frozen_string_literal: true

require 'cerner/oauth1a/cache'

RSpec.describe(Cerner::OAuth1a::Cache) do
  describe '#full_key' do
    it 'creates full key with ns and key' do
      subject = Cerner::OAuth1a::Cache.new
      expect(subject.full_key('ns', 'key')).to(eq('ns:key'))
    end

    it 'creates full key with key' do
      subject = Cerner::OAuth1a::Cache.new
      expect(subject.full_key(nil, 'key')).to(eq(':key'))
    end

    it 'creates full key with ns' do
      subject = Cerner::OAuth1a::Cache.new
      expect(subject.full_key('ns', nil)).to(eq('ns:'))
    end
  end

  describe '.instance=' do
    it 'raises ArgumentError when nil' do
      expect { Cerner::OAuth1a::Cache.instance = nil }.to(raise_exception(ArgumentError))
    end
  end

  describe '.instance' do
    it 'provides a default' do
      expect(Cerner::OAuth1a::Cache.instance).not_to(be(nil))
    end
  end
end
