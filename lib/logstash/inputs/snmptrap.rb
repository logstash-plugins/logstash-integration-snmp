# encoding: utf-8
require 'logstash/inputs/base'
require 'logstash/namespace'
require 'set'

require 'logstash-integration-snmp_jars'
require 'logstash/plugin_mixins/ecs_compatibility_support'
require 'logstash/plugin_mixins/ecs_compatibility_support/target_check'
require 'logstash/plugin_mixins/event_support/event_factory_adapter'
require 'logstash/plugin_mixins/validator_support/field_reference_validation_adapter'
require 'logstash/plugin_mixins/normalize_config_support'
require 'logstash/plugin_mixins/snmp/common'

# Read snmp trap messages as events
#
# Resulting `@message` looks like :
# [source,json]
# {"error_index":0,"variable_bindings":{"1.3.6.1.6.3.1.1.4.1.0":"value"},"error_status":0,"type":"TRAP","error_status_text":"Success","version":"3","request_id":145014487}
#
class LogStash::Inputs::Snmptrap < LogStash::Inputs::Base

  java_import 'org.logstash.snmp.SnmpClient'

  include LogStash::PluginMixins::ECSCompatibilitySupport(:disabled, :v1, :v8 => :v1)

  include LogStash::PluginMixins::ECSCompatibilitySupport::TargetCheck

  include LogStash::PluginMixins::EventSupport::EventFactoryAdapter

  extend LogStash::PluginMixins::ValidatorSupport::FieldReferenceValidationAdapter

  include LogStash::PluginMixins::NormalizeConfigSupport

  include LogStash::PluginMixins::Snmp::Common

  config_name 'snmptrap'

  # The address to listen on
  config :host, :validate => :string, :required => true, :default => '0.0.0.0'

  # The port to listen on. Remember that ports less than 1024 (privileged
  # ports) may require root to use. hence the default of 1062.
  config :port, :validate => :number, :required => true, :default => 1062

  # The supported transport protocols to listen on.
  config :supported_transports, :validate => %w[tcp udp], :default => %w[udp], :required => true, :list => true

  # The supported SNMP versions to listen on
  config :supported_versions, :validate => %w[1 2c 3], default: %w[1 2c], :required => true, :list => true

  # SNMP Community String to listen for.
  config :community, :validate => :array, :default => 'public'

  # directory of YAML MIB maps  (same format ruby-snmp uses)
  config :yamlmibdir, :validate => :string, :deprecated => "Use `mib_paths` instead."

  # Number of threads to use for processing the received SNMP messages.
  # By default, SNMP4J uses a single listener thread, which delegates all received data
  # to the message dispatcher. This setting, configures the number of threads to be used
  # by the message dispatcher, so it won't block the listener thread.
  config :threads, :validate => :number, :required => true, :default => ::LogStash::Config::CpuCoreStrategy.seventy_five_percent

  # These MIBs were automatically added by ruby-snmp when no @yamlmibdir was provided.
  MIB_DEFAULT_PATHS = [
    ::File.join(MIB_BASE_PATH, 'ietf', 'SNMPv2-SMI.dic'),
    ::File.join(MIB_BASE_PATH, 'ietf', 'SNMPv2-MIB.dic'),
    ::File.join(MIB_BASE_PATH, 'ietf', 'IF-MIB.dic'),
    ::File.join(MIB_BASE_PATH, 'ietf', 'IP-MIB.dic'),
    ::File.join(MIB_BASE_PATH, 'ietf', 'TCP-MIB.dic'),
    ::File.join(MIB_BASE_PATH, 'ietf', 'UDP-MIB.dic')
  ].map { |path| ::File.expand_path(path) }

  def initialize(params = {})
    super(params)

    setup_deprecated_params!
    @host_ip_field = ecs_select[disabled: 'host', v1: '[host][ip]']
  end

  def register
    validate_config!
    mib_manager = build_mib_manager!

    if !@mib_paths && !@use_provided_mibs
      logger.info("Using default MIB paths #{MIB_DEFAULT_PATHS}")
      MIB_DEFAULT_PATHS.each do |path|
        mib_manager.add(path)
      end
    end

    @client = build_client!(mib_manager)
  end

  def run(output_queue)
    begin
      trap_message_consumer = lambda { |trap| consume_trap_message(output_queue, trap) }
      @client.trap(@community, trap_message_consumer)
    rescue => e
      @logger.warn('SNMP Trap listener died', format_log_data(e))
      Stud.stoppable_sleep(5) { stop? }
      retry if !stop?
    end
  end

  def stop
    begin
      @client.close unless @client.nil?
    rescue => e
      logger.warn('Error closing SNMP client. Ignoring', format_log_data(e))
    end
  end

  def client_listening?
    @client.isListening()
  end

  private

  def validate_config!
    if !@security_name.nil? && !@supported_versions.include?('3')
      raise(LogStash::ConfigurationError, "Using a `security_name` requires `supported_versions` to include version '3': #{@supported_versions}")
    end
  end

  def build_client!(mib_manager)
    client_builder = org.logstash.snmp.SnmpClient
                        .builder(mib_manager, @supported_transports.to_set, @port)
                        .setHost(@host)
                        .setSupportedVersions(@supported_versions.to_set)
                        .setMessageDispatcherPoolName('SnmpTrapMessageDispatcherWorker')
                        .setMessageDispatcherPoolSize(@threads)

    build_snmp_client!(client_builder, validate_usm_user: @supported_versions.include?('3'))
  end

  def consume_trap_message(output_queue, trap_message)
    begin
      output_queue << process_trap_message(trap_message)
    rescue => e
      extra_data = { :trap_event => format_trap_message(trap_message) } if trap_message rescue {}
      @logger.error('Failed to create event', format_log_data(e, extra_data))
    end
  end

  def process_trap_message(trap_message)
    data = Hash.new

    trap_message.getFormattedVariableBindings.each do |name, value|
      data[name] = value
    end

    event = targeted_event_factory.new_event(data)
    event.set(@host_ip_field, trap_message.getPeerIpAddress)
    event.set('message', format_trap_message(trap_message))

    add_metadata_fields(event, trap_message.getTrapEvent)
    decorate(event)

    event
  end

  def format_trap_message(trap_message)
    trap_event = trap_message.getTrapEvent.to_hash
    trap_event['variable_bindings'] = trap_event['variable_bindings'].to_hash
    LogStash::Json.dump(trap_event)
  end

  def add_metadata_fields(event, trap_event)
    trap_event.each do |name, value|
      event.set("[@metadata][input][snmptrap][pdu][#{name}]", value) if value
    end
  end

  def setup_deprecated_params!
    @mib_paths = normalize_config(:mib_paths) do |normalize|
      normalize.with_deprecated_mapping(:yamlmibdir) do |yamlmibdir|
        [yamlmibdir]
      end
    end
  end

  def format_log_data(exception, extra_data = {})
    data = {}
    data[:exception] = exception.class
    data[:message] = exception.message
    data[:backtrace] = exception.backtrace if logger.debug?
    data.merge!(extra_data)
    data
  end
end
