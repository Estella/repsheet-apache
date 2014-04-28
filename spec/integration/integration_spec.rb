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

  describe "Recorder" do
    it "Records the IP, User Agent, Method, URI, and Arguments during a request" do
      Curl.get "http://127.0.0.1:8888"

      @redis.llen("127.0.0.1:requests").should == 1
    end

    it "Properly sets the expiry" do
      Curl.get "http://127.0.0.1:8888"

      @redis.ttl("127.0.0.1:requests").should > 1
    end

    it "Records activity using the proper IP when behind a proxy" do
      http = Curl.get("http://127.0.0.1:8888") do |http|
        http.headers['X-Forwarded-For'] = '1.1.1.1'
      end

      @redis.llen("1.1.1.1:requests").should == 1
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

  describe "Proxy Filtering" do
    it "Properly determines the IP address when multiple proxies are present in X-Forwarded-For" do
      http = Curl.get("http://127.0.0.1:8888?../../") do |http|
        http.headers['X-Forwarded-For'] = '8.8.8.8, 12.34.56.78, 98.76.54.32'
      end
      @redis.lrange("8.8.8.8:requests", 0, -1).size.should == 1
    end

    it "Ignores user submitted noise in X-Forwarded-For" do
      http = Curl.get("http://127.0.0.1:8888?../../") do |http|
        http.headers['X-Forwarded-For'] = '\x5000 8.8.8.8, 12.34.56.78, 98.76.54.32'
      end
      @redis.lrange("8.8.8.8:requests", 0, -1).size.should == 1
    end
  end
end
