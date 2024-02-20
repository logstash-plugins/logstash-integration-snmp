# encoding: utf-8
require 'logstash/devutils/rake'

task :install_jars do
  sh('./gradlew clean vendor')
end

task :vendor => :install_jars

namespace :test do
  task :integration do
    require 'rspec'
    require 'rspec/core/runner'
    exit(RSpec::Core::Runner.run(%w[spec/integration --format=documentation --tag integration]))
  end

  task :unit do
    Rake::Task[:install_jars].invoke
    exit(1) unless system './gradlew test'

    require 'rspec'
    require 'rspec/core/runner'
    exit(RSpec::Core::Runner.run(%w[spec/unit --format=documentation]))
  end
end