require 'spec_helper'

describe "Integration Specs" do
  before do
    @redis = Redis.new
    @redis.flushdb
  end

  after  { @redis.flushdb }

  describe "Bootstrap" do
    it "Redis is running" do
      @redis.ping.should == "PONG"
    end

    it "Webserver is running" do
      Curl.get("http://127.0.0.1:8888").response_code.should == 200
    end
  end

  describe "Actions" do
    it "Returns a 403 response if the actor is on the blacklist" do
      @redis.set("127.0.0.1:repsheet:blacklist", "true")
      Curl.get("http://127.0.0.1:8888").response_code.should == 403
    end

    it "Returns a 200 response if the actor is on the whitelist" do
      @redis.set("127.0.0.1:repsheet:blacklist", "true")
      @redis.set("127.0.0.1:repsheet:whitelist", "true")
      Curl.get("http://127.0.0.1:8888").response_code.should == 200
    end
  end
end
