VERSION = File.read(File.expand_path(File.join(File.dirname(__FILE__), "VERSION"))).strip unless defined?(VERSION)

Gem::Specification.new do |s|
  s.name = 'logstash-integration-snmp'
  s.version         = VERSION
  s.licenses = ['Apache License (2.0)']
  s.summary         = "Integration with SNMP - Logstash plugins"
  s.description     = "This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program"
  s.authors = ["Elastic"]
  s.email = 'info@elastic.co'
  s.homepage = "http://www.elastic.co/guide/en/logstash/current/index.html"
  s.require_paths   = ["lib", "vendor/jar-dependencies"]

  # Files
  s.files = Dir["lib/**/*","spec/**/*","*.gemspec","*.md","CONTRIBUTORS","Gemfile","LICENSE","NOTICE.TXT", "vendor/jar-dependencies/**/*.jar", "vendor/jar-dependencies/**/*.rb", "VERSION", "docs/**/*"]

   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = {
      "logstash_plugin"     => "true",
      "logstash_group"      => "integration",
      "integration_plugins" => "logstash-input-snmp,logstash-input-snmptrap"
  }

  # Gem dependencies
  s.add_development_dependency 'jar-dependencies', '~> 0.3'
  s.add_runtime_dependency "logstash-core-plugin-api", ">= 1.60", "<= 2.99"
  s.add_runtime_dependency 'logstash-mixin-ecs_compatibility_support', '~>1.3'
  s.add_runtime_dependency "logstash-mixin-validator_support", '~> 1.0'
  s.add_runtime_dependency "logstash-mixin-event_support", '~> 1.0'
  s.add_runtime_dependency 'logstash-mixin-normalize_config_support', '~>1.0'
  s.add_runtime_dependency 'logstash-codec-plain'
  # Restrict use of this plugin to versions of Logstash where support for integration plugins is present.
  s.add_runtime_dependency "logstash-core", ">= 6.5.0"
  s.add_development_dependency 'rspec-wait'
  s.add_development_dependency 'logstash-devutils', '>= 2.3'
  s.platform = "java"
end
