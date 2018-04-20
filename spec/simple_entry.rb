# frozen_string_literal: true

class SimpleEntry
  attr_accessor :value, :expired

  def initialize(value:, expired: false)
    @value = value
    @expired = expired
  end

  def expired?(now)
    expired
  end
end
