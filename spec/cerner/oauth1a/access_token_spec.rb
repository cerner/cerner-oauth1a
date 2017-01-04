require 'spec_helper'

require 'cerner/oauth1a/access_token'

RSpec.describe Cerner::OAuth1a::AccessToken do
  describe '#to_h' do
    it 'returns a Hash of attributes' do
      access_token = Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                                      consumer_key: 'CONSUMER KEY',
                                                      expires_at: Time.at(Time.now.to_i + 1),
                                                      nonce: 'NONCE',
                                                      timestamp: Time.at(Time.now.to_i),
                                                      token: 'TOKEN',
                                                      token_secret: 'TOKEN SECRET')
      hash = access_token.to_h
      expect(hash[:accessor_secret]).to eq(access_token.accessor_secret)
      expect(hash[:consumer_key]).to eq(access_token.consumer_key)
      expect(hash[:expires_at]).to eq(access_token.expires_at)
      expect(hash[:nonce]).to eq(access_token.nonce)
      expect(hash[:timestamp]).to eq(access_token.timestamp)
      expect(hash[:token]).to eq(access_token.token)
      expect(hash[:token_secret]).to eq(access_token.token_secret)
    end
  end

  describe '#==' do
    let!(:current_time) { Time.at(Time.now.to_i) }
    let!(:expires_at) { Time.at(current_time.to_i + 1) }
    let!(:access_token) do
      Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                       consumer_key: 'CONSUMER KEY',
                                       expires_at: expires_at,
                                       nonce: 'NONCE',
                                       timestamp: current_time,
                                       token: 'TOKEN',
                                       token_secret: 'TOKEN SECRET')
    end

    context 'returns true' do
      it 'when compared to self' do
        expect(access_token == access_token).to be true
        expect(access_token.eql? access_token).to be true
      end

      it 'when two instances have the same attributes' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                                         consumer_key: 'CONSUMER KEY',
                                                         expires_at: expires_at,
                                                         nonce: 'NONCE',
                                                         timestamp: current_time,
                                                         token: 'TOKEN',
                                                         token_secret: 'TOKEN SECRET')

        expect(access_token.object_id).not_to eq(access_token2.object_id)
        expect(access_token == access_token2).to be true
        expect(access_token.eql? access_token2).to be true
      end

      it 'when two instances have the same attributes and authorization_header is built' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                                         consumer_key: 'CONSUMER KEY',
                                                         expires_at: expires_at,
                                                         nonce: 'NONCE',
                                                         timestamp: current_time,
                                                         token: 'TOKEN',
                                                         token_secret: 'TOKEN SECRET')

        expect(access_token2.authorization_header).not_to be nil
        expect(access_token.object_id).not_to eq(access_token2.object_id)
        expect(access_token == access_token2).to be true
        expect(access_token.eql? access_token2).to be true
      end
    end

    context 'returns false' do
      it 'when accessor_secret varies' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(accessor_secret: 'NOT ACCESSOR SECRET',
                                                         consumer_key: 'CONSUMER KEY',
                                                         expires_at: expires_at,
                                                         nonce: 'NONCE',
                                                         timestamp: current_time,
                                                         token: 'TOKEN',
                                                         token_secret: 'TOKEN SECRET')
        expect(access_token == access_token2).to be false
        expect(access_token.eql? access_token2).to be false
      end

      it 'when consumer_key varies' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                                         consumer_key: 'NOT CONSUMER KEY',
                                                         expires_at: expires_at,
                                                         nonce: 'NONCE',
                                                         timestamp: current_time,
                                                         token: 'TOKEN',
                                                         token_secret: 'TOKEN SECRET')
        expect(access_token == access_token2).to be false
        expect(access_token.eql? access_token2).to be false
      end

      it 'when expires_at varies' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                                         consumer_key: 'CONSUMER KEY',
                                                         expires_at: expires_at + 10,
                                                         nonce: 'NONCE',
                                                         timestamp: current_time,
                                                         token: 'TOKEN',
                                                         token_secret: 'TOKEN SECRET')
        expect(access_token == access_token2).to be false
        expect(access_token.eql? access_token2).to be false
      end

      it 'when nonce varies' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                                         consumer_key: 'CONSUMER KEY',
                                                         expires_at: expires_at,
                                                         nonce: 'NOT NONCE',
                                                         timestamp: current_time,
                                                         token: 'TOKEN',
                                                         token_secret: 'TOKEN SECRET')
        expect(access_token == access_token2).to be false
        expect(access_token.eql? access_token2).to be false
      end

      it 'when timestamp varies' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                                         consumer_key: 'CONSUMER KEY',
                                                         expires_at: expires_at,
                                                         nonce: 'NONCE',
                                                         timestamp: current_time + 10,
                                                         token: 'TOKEN',
                                                         token_secret: 'TOKEN SECRET')
        expect(access_token == access_token2).to be false
        expect(access_token.eql? access_token2).to be false
      end

      it 'when token varies' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                                         consumer_key: 'CONSUMER KEY',
                                                         expires_at: expires_at,
                                                         nonce: 'NONCE',
                                                         timestamp: current_time,
                                                         token: 'NOT TOKEN',
                                                         token_secret: 'TOKEN SECRET')
        expect(access_token == access_token2).to be false
        expect(access_token.eql? access_token2).to be false
      end

      it 'when token_secret varies' do
        access_token2 = Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                                         consumer_key: 'CONSUMER KEY',
                                                         expires_at: expires_at,
                                                         nonce: 'NONCE',
                                                         timestamp: current_time,
                                                         token: 'TOKEN',
                                                         token_secret: 'NOT TOKEN SECRET')
        expect(access_token == access_token2).to be false
        expect(access_token.eql? access_token2).to be false
      end

    end
  end

  describe '#authorization_header' do
    let!(:current_time) { Time.at(Time.now.to_i) }
    let!(:expires_at) { Time.at(current_time.to_i + 1) }
    let!(:access_token) do
      Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                       consumer_key: 'CONSUMER KEY',
                                       expires_at: expires_at,
                                       nonce: 'NONCE',
                                       timestamp: current_time,
                                       token: 'TOKEN',
                                       token_secret: 'TOKEN SECRET')
    end

    it 'starts with OAuth' do
      expect(access_token.authorization_header).to start_with('OAuth ')
    end

    it 'contains oauth_ parts' do
      expect(access_token.authorization_header).to include('oauth_version="1.0"')
      expect(access_token.authorization_header).to include('oauth_signature_method="PLAINTEXT"')
      expect(access_token.authorization_header).to include('oauth_signature="ACCESSOR+SECRET%26TOKEN+SECRET"')
      expect(access_token.authorization_header).to include('oauth_consumer_key="CONSUMER+KEY"')
      expect(access_token.authorization_header).to include('oauth_nonce="NONCE"')
      expect(access_token.authorization_header).to include('oauth_token="TOKEN"')
      expect(access_token.authorization_header).to match(/oauth_timestamp="\d+"/)
    end
  end

  describe '#expired?' do
    # Set current_time back 301 seconds, such that expires_at will be beyond default fudge_sec
    let!(:current_time) { Time.at(Time.now.to_i - 301) }
    let!(:expires_at) { Time.at(current_time.to_i + 1) }
    let!(:access_token) do
      Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                       consumer_key: 'CONSUMER KEY',
                                       expires_at: expires_at,
                                       nonce: 'NONCE',
                                       timestamp: current_time,
                                       token: 'TOKEN',
                                       token_secret: 'TOKEN SECRET')
    end

    it 'is expired with no arguments' do
      expect(access_token.expired?).to be true
    end

    it 'is expired with fudge of 0' do
      expect(access_token.expired?(fudge_sec: 0)).to be true
    end

    it 'is expired with Time argument' do
      expect(access_token.expired?(now: Time.at(Time.now.to_i + 10))).to be true
    end
  end

  describe '#initialize' do
    it 'converts Integer to Time for expires_at' do
      fixture = Time.at(Time.now.to_i + 60)
      access_token = Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                                      consumer_key: 'CONSUMER KEY',
                                                      expires_at: fixture.to_i,
                                                      nonce: 'NONCE',
                                                      timestamp: Time.now.utc,
                                                      token: 'TOKEN',
                                                      token_secret: 'TOKEN SECRET')
      expect(access_token.expires_at).to eq(fixture)
    end

    it 'converts Integer to Time for timestamp' do
      fixture = Time.at(Time.now.to_i)
      access_token = Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                                      consumer_key: 'CONSUMER KEY',
                                                      expires_at: Time.now.utc,
                                                      nonce: 'NONCE',
                                                      timestamp: fixture.to_i,
                                                      token: 'TOKEN',
                                                      token_secret: 'TOKEN SECRET')
      expect(access_token.timestamp).to eq(fixture)
    end

    it 'requires a non-nil accessor_secret' do
      expect {
        Cerner::OAuth1a::AccessToken.new(accessor_secret: nil,
                                         consumer_key: 'CONSUMER KEY',
                                         expires_at: Time.now.utc,
                                         nonce: 'NONCE',
                                         timestamp: Time.now.utc,
                                         token: 'TOKEN',
                                         token_secret: 'TOKEN SECRET')
             }.to raise_error(ArgumentError, /accessor_secret/)
    end

    it 'requires a non-nil consumer_key' do
      expect {
        Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                         consumer_key: nil,
                                         expires_at: Time.now.utc,
                                         nonce: 'NONCE',
                                         timestamp: Time.now.utc,
                                         token: 'TOKEN',
                                         token_secret: 'TOKEN SECRET')
             }.to raise_error(ArgumentError, /consumer_key/)
    end

    it 'requires a non-nil expires_at' do
      expect {
        Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                         consumer_key: 'CONSUMER KEY',
                                         expires_at: nil,
                                         nonce: 'NONCE',
                                         timestamp: Time.now.utc,
                                         token: 'TOKEN',
                                         token_secret: 'TOKEN SECRET')
             }.to raise_error(ArgumentError, /expires_at/)
    end

    it 'requires a non-nil nonce' do
      expect {
        Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                         consumer_key: 'CONSUMER KEY',
                                         expires_at: Time.now.utc,
                                         nonce: nil,
                                         timestamp: Time.now.utc,
                                         token: 'TOKEN',
                                         token_secret: 'TOKEN SECRET')
             }.to raise_error(ArgumentError, /nonce/)
    end

    it 'requires a non-nil timestamp' do
      expect {
        Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                         consumer_key: 'CONSUMER KEY',
                                         expires_at: Time.now.utc,
                                         nonce: 'NONCE',
                                         timestamp: nil,
                                         token: 'TOKEN',
                                         token_secret: 'TOKEN SECRET')
             }.to raise_error(ArgumentError, /timestamp/)
    end

    it 'requires a non-nil token' do
      expect {
        Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                         consumer_key: 'CONSUMER KEY',
                                         expires_at: Time.now.utc,
                                         nonce: 'NONCE',
                                         timestamp: Time.now.utc,
                                         token: nil,
                                         token_secret: 'TOKEN SECRET')
             }.to raise_error(ArgumentError, /token/)
    end

    it 'requires a non-nil token_secret' do
      expect {
        Cerner::OAuth1a::AccessToken.new(accessor_secret: 'ACCESSOR SECRET',
                                         consumer_key: 'CONSUMER KEY',
                                         expires_at: Time.now.utc,
                                         nonce: 'NONCE',
                                         timestamp: Time.now.utc,
                                         token: 'TOKEN',
                                         token_secret: nil)
             }.to raise_error(ArgumentError, /token_secret/)
    end
  end
end
