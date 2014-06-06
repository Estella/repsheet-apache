require 'spec_helper'

describe "Integration Specs" do
  before do
    @redis = Redis.new
    @redis.flushdb
  end

  after  { @redis.flushdb }

  describe "Bootstrap" do
    it "Redis is running" do
      expect(@redis.ping).to eq("PONG")
    end

    it "Webserver is running" do
      http = Curl.get("http://127.0.0.1:8888")
      expect(http.response_code).to eq(200)
    end
  end

  describe "Recorder" do
    it "Records the IP, User Agent, Method, URI, and Arguments during a request" do
      Curl.get "http://127.0.0.1:8888"

      expect(@redis.llen("127.0.0.1:requests")).to eq(1)
    end

    it "Properly sets the expiry" do
      Curl.get "http://127.0.0.1:8888"

      @redis.ttl("127.0.0.1:requests").should > 1
    end

    it "Records activity using the proper IP when behind a proxy" do
      http = Curl.get("http://127.0.0.1:8888") do |http|
        http.headers['X-Forwarded-For'] = '1.1.1.1'
      end

      expect(@redis.llen("1.1.1.1:requests")).to eq(1)
    end
  end

  describe "Actions" do
    it "Returns a 403 response if the actor is on the blacklist" do
      @redis.set("127.0.0.1:repsheet:blacklist", "true")
      expect(Curl.get("http://127.0.0.1:8888").response_code).to eq(403)
    end

    it "Returns a 200 response if the actor is on the whitelist" do
      @redis.set("127.0.0.1:repsheet:blacklist", "true")
      @redis.set("127.0.0.1:repsheet:whitelist", "true")
      expect(Curl.get("http://127.0.0.1:8888").response_code).to eq(200)
    end
  end

  describe "Proxy Filtering" do
    it "Properly determines the IP address when multiple proxies are present in X-Forwarded-For" do
      http = Curl.get("http://127.0.0.1:8888?../../") do |http|
        http.headers['X-Forwarded-For'] = '8.8.8.8, 12.34.56.78, 98.76.54.32'
      end
      expect(@redis.lrange("8.8.8.8:requests", 0, -1).size).to eq(1)
    end

    it "Ignores user submitted noise in X-Forwarded-For" do
      http = Curl.get("http://127.0.0.1:8888?../../") do |http|
        http.headers['X-Forwarded-For'] = '\x5000 8.8.8.8, 12.34.56.78, 98.76.54.32'
      end
      expect(@redis.lrange("8.8.8.8:requests", 0, -1).size).to eq(1)
    end
  end

  describe "ModSecurity Integration" do
    it "Creates the proper Redis keys when a security rule is triggered" do
      Curl.get "http://127.0.0.1:8888?../../"

      expect(@redis.type("127.0.0.1:detected")).to eq("zset")
      expect(@redis.type("127.0.0.1:repsheet")).to eq("string")
    end

    it "Adds the offending IP address to the repsheet" do
      expect(@redis.get("127.0.0.1:repsheet")).to eq(nil)

      Curl.get "http://127.0.0.1:8888?../../"

      expect(@redis.get("127.0.0.1:repsheet")).to eq("true")
    end

    it "Properly sets and increments the waf events in <ip>:detected" do
      Curl.get "http://127.0.0.1:8888?../../"

      expect(@redis.zscore("127.0.0.1:detected", "950103")).to eq(1.0)
      expect(@redis.zscore("127.0.0.1:detected", "960009")).to eq(1.0)
      expect(@redis.zscore("127.0.0.1:detected", "960017")).to eq(1.0)

      Curl.get "http://127.0.0.1:8888?../../"

      expect(@redis.zscore("127.0.0.1:detected", "950103")).to eq(2.0)
      expect(@redis.zscore("127.0.0.1:detected", "960009")).to eq(2.0)
      expect(@redis.zscore("127.0.0.1:detected", "960017")).to eq(2.0)
    end

    it "Adds the offending IP address to the repsheet when behind a proxy" do
      expect(@redis.get("1.1.1.1:repsheet")).to eq(nil)

      http = Curl.get("http://127.0.0.1:8888?../../") do |http|
        http.headers['X-Forwarded-For'] = '1.1.1.1'
      end

      expect(@redis.get("1.1.1.1:repsheet")).to eq("true")
    end

    it "Blocks requests that exceed the anomaly threshold" do
      http = Curl.get("http://127.0.0.1:8888?../../<script>alert('hi')</script>####################")
      expect(http.response_code).to eq(403)
    end

    it "Blacklists actors that exceed the anomaly threshold" do
      Curl.get("http://127.0.0.1:8888?../../<script>alert('hi')</script>####################")
      expect(@redis.get("127.0.0.1:repsheet:blacklist")).to eq("true")
    end

    it "Sets a reason when blacklisting actors that exceed the anomaly threshold" do
      Curl.get("http://127.0.0.1:8888?../../<script>alert('hi')</script>####################")
      expect(@redis.get("127.0.0.1:repsheet:blacklist:reason")).to eq("ModSecurity Anomaly Threshold")
    end

  end
end
