require 'rake'
require 'rspec/core/rake_task'
require 'redis'

RSpec::Core::RakeTask.new(:integration) do |t|
  t.pattern = "spec/**/*_spec.rb"
end

namespace :apache do
  task :start do
    `build/apache24/bin/apachectl restart`
    sleep 1
  end

  task :stop do
    `build/apache24/bin/apachectl stop`
  end

  task :compile do
    sh "make local"
  end
end

namespace :repsheet do
  task :bootstrap do
    unless Dir.exists?("build") and Dir.exists?("vendor")
      puts "Run script/bootstrap to setup local development environment"
      exit(1)
    end
  end
end

desc "Run the integration tests against Apache"
task :default => ["repsheet:bootstrap", "apache:compile", "apache:start", :integration, "apache:stop"]
