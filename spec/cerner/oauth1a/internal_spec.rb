# frozen_string_literal: true

require 'spec_helper'

require 'cerner/oauth1a/internal'
require 'digest'

RSpec.describe(Cerner::OAuth1a::Internal) do
  describe '.constant_time_compare' do
    it 'returns true on equal simple strings' do
      expect(
        Cerner::OAuth1a::Internal.constant_time_compare('1234', '1234')
      ).to(eq(true))
    end

    it 'returns true on equal SHA256 digested strings' do
      left = Digest::SHA256.base64digest('this is a very important message')
      right = Digest::SHA256.base64digest('this is a very important message')
      # these values should be the same size, but it's asserted for safety
      expect(left.bytesize).to(eq(right.bytesize))
      expect(
        Cerner::OAuth1a::Internal.constant_time_compare(left, right)
      ).to(eq(true))
    end

    it 'returns false on mismatched simple strings' do
      expect(
        Cerner::OAuth1a::Internal.constant_time_compare('1234', '5678')
      ).to(eq(false))
    end

    it 'returns false on mismatched SHA256 digested strings' do
      left = Digest::SHA256.base64digest('this is a very important message')
      right = Digest::SHA256.base64digest('this is NOT a very important message')
      # these values should be the same size, but it's asserted for safety
      expect(left.bytesize).to(eq(right.bytesize))
      expect(
        Cerner::OAuth1a::Internal.constant_time_compare(left, right)
      ).to(eq(false))
    end

    it 'returns false when string bytesize does not match' do
      expect(Cerner::OAuth1a::Internal.constant_time_compare('1', '12')).to(eq(false))
    end
  end
end
