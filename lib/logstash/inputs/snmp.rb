# encoding: utf-8
require 'logstash/inputs/base'
require 'logstash/namespace'
require 'stud/interval'
require 'set'

require 'logstash-integration-snmp_jars'
require 'logstash/plugin_mixins/ecs_compatibility_support'
require 'logstash/plugin_mixins/ecs_compatibility_support/target_check'
require 'logstash/plugin_mixins/event_support/event_factory_adapter'
require 'logstash/plugin_mixins/validator_support/field_reference_validation_adapter'
require 'logstash/plugin_mixins/snmp/common'

# Generate a repeating message.
#
# This plugin is intented only as an example.

class LogStash::Inputs::Snmp < LogStash::Inputs::Base

  java_import 'org.logstash.snmp.SnmpClient'
  java_import 'org.snmp4j.smi.OID'

  include LogStash::PluginMixins::ECSCompatibilitySupport(:disabled, :v1, :v8 => :v1)
  include LogStash::PluginMixins::ECSCompatibilitySupport::TargetCheck

  include LogStash::PluginMixins::EventSupport::EventFactoryAdapter

  extend LogStash::PluginMixins::ValidatorSupport::FieldReferenceValidationAdapter

  include LogStash::PluginMixins::Snmp::Common

  config_name "snmp"

  # List of OIDs for which we want to retrieve the scalar value
  config :get,:validate => :array # ["1.3.6.1.2.1.1.1.0"]

  # List of OIDs for which we want to retrieve the subtree of information
  config :walk,:validate => :array # ["1.3.6.1.2.1.1.1.0"]

  # List of tables to walk
  config :tables, :validate => :array  #[ {"name" => "interfaces" "columns" => ["1.3.6.1.2.1.2.2.1.1", "1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.2.2.1.5"]} ]

  # List of hosts to query the configured `get` and `walk` options.
  #
  # Each host definition is a hash and must define the `host` key and value.
  #  `host` must use the format {tcp|udp}:{ip address}/{port}
  #  for example `host => "udp:127.0.0.1/161"`
  # Each host definition can optionally include the following keys and values:
  #  `community` with a default value of `public`
  #  `version` `1`, `2c` or `3` with a default value of `2c`
  #  `retries` with a default value of `2`
  #  `timeout` in milliseconds with a default value of `1000`
  config :hosts, :validate => :array  #[ {"host" => "udp:127.0.0.1/161", "community" => "public"} ]

  # Set polling interval in seconds
  #
  # The default, `30`, means poll each host every 30 seconds.
  config :interval, :validate => :number, :default => 30

  # SNMPv3 Credentials
  #
  # A single user can be configured and will be used for all defined SNMPv3 hosts.
  # Multiple snmp input declarations will be needed if multiple SNMPv3 users are required.
  # If not using SNMPv3 simply leave options empty.

  # The SNMPv3 security name or user name
  config :security_name, :validate => :string

  # The SNMPv3 authentication protocol or type
  config :auth_protocol, :validate => ["md5", "sha", "sha2", "hmac128sha224", "hmac192sha256", "hmac256sha384", "hmac384sha512"]

  # The SNMPv3 authentication passphrase or password
  config :auth_pass, :validate => :password

  # The SNMPv3 privacy/encryption protocol
  config :priv_protocol, :validate => ["des", "3des", "aes", "aes128", "aes192", "aes256"]

  # The SNMPv3 encryption password
  config :priv_pass, :validate => :password

  # The SNMPv3 security level can be Authentication, No Privacy; Authentication, Privacy; or no Authentication, no Privacy
  config :security_level, :validate => ["noAuthNoPriv", "authNoPriv", "authPriv"]

  def initialize(params={})
    super(params)

    @host_protocol_field = ecs_select[disabled: '[@metadata][host_protocol]', v1: '[@metadata][input][snmp][host][protocol]']
    @host_address_field = ecs_select[disabled: '[@metadata][host_address]', v1: '[@metadata][input][snmp][host][address]']
    @host_port_field = ecs_select[disabled: '[@metadata][host_port]', v1: '[@metadata][input][snmp][host][port]']
    @host_community_field = ecs_select[disabled: '[@metadata][host_community]', v1: '[@metadata][input][snmp][host][community]']

    # Add the default "host" field to the event, for backwards compatibility, or host.ip in ecs mode
    unless params.key?('add_field')
      host_ip_field = ecs_select[disabled: "host", v1: "[host][ip]"]
      @add_field = { host_ip_field => "%{#{@host_address_field}}" }
    end
  end

  def register
    validate_oids!
    validate_hosts!
    validate_tables!

    mib_manager = build_mib_manager!

    # setup client definitions per provided host
    @client_definitions = []
    client_protocols = Set.new

    @hosts.each do |host|
      host_name = host["host"]
      community = host["community"] || "public"
      version = host["version"] || "2c"
      raise(LogStash::ConfigurationError, "only protocol version '1', '2c' and '3' are supported for host option '#{host_name}'") unless version =~ VERSION_REGEX

      retries = host["retries"] || 2
      timeout = host["timeout"] || 1000

      # TODO: move these validations in a custom validator so it happens before the register method is called.
      host_details = host_name.match(HOST_REGEX)
      raise(LogStash::ConfigurationError, "invalid format for host option '#{host_name}'") unless host_details
      raise(LogStash::ConfigurationError, "only udp & tcp protocols are supported for host option '#{host_name}'") unless host_details[:host_protocol].to_s =~ /^(?:udp|tcp)$/i

      protocol = host_details[:host_protocol]
      address = host_details[:host_address]
      port = host_details[:host_port]

      if version == "3"
        validate_v3_user!
      end

      definition = {
        :get => Array(get),
        :walk => Array(walk),

        :host => host_name,
        :host_address => address,
        :host_protocol => protocol,
        :host_port => port,
        :host_community => community,

        :retries => retries,
        :timeout => timeout,
        :version => version,

        :security_name => @security_name,
        :security_level => @security_level,
      }

      client_protocols << protocol
      @client_definitions << definition
    end

    @client = build_client!(mib_manager, client_protocols)
  end

  def run(queue)
    @client.listen
    # for now a naive single threaded poller which sleeps off the remaining interval between
    # each run. each run polls all the defined hosts for the get, table and walk options.
    stoppable_interval_runner.every(@interval, "polling hosts") do
      poll_clients(queue)
    end
  end

  def poll_clients(queue)
    @client_definitions.each do |definition|
      host = definition[:host_address]
      target = @client.create_target(
        definition[:host],
        definition[:version],
        definition[:retries],
        definition[:timeout],
        definition[:host_community],
        definition[:security_name],
        definition[:security_level],
      )

      result = {}

      if !definition[:get].empty?
        oids = definition[:get]
        begin
          data = @client.get(target, oids.map { |oid| OID.new(oid) })
          if data&.any?
            result.update(data)
          else
            logger.debug? && logger.debug("get operation returned no response", host: host, oids: oids)
          end
        rescue => e
          logger.error("error invoking get operation, ignoring", host: host, oids: oids, exception: e, backtrace: e.backtrace)
        end
      end

      if !definition[:walk].empty?
        definition[:walk].each do |oid|
          begin
            data = @client.walk(target, OID.new(oid))
            if data&.any?
              result.update(data)
            else
              logger.debug? && logger.debug("walk operation returned no response", host: host, oid: oid)
            end
          rescue => e
            logger.error("error invoking walk operation, ignoring", host: host, oid: oid, exception: e, backtrace: e.backtrace)
          end
        end
      end

      if !Array(@tables).empty?
        @tables.each do |table_entry|
          begin
            table_name = table_entry['name']
            oids = table_entry["columns"].map { |oid| OID.new(oid) }
            data = @client.table(target, table_name, oids)
            if data&.any?
              result.update(data)
            else
              logger.debug? && logger.debug("table operation returned no response", host: host, table: table_entry)
            end
          rescue => e
            logger.error("error invoking table operation, ignoring",
                         host: host, table_name: table_entry['name'], exception: e, backtrace: e.backtrace)
          end
        end
      end

      unless result.empty?
        event = targeted_event_factory.new_event(result)
        event.set(@host_protocol_field, definition[:host_protocol])
        event.set(@host_address_field, definition[:host_address])
        event.set(@host_port_field, definition[:host_port])
        event.set(@host_community_field, definition[:host_community])
        decorate(event)
        queue << event
      else
        logger.debug? && logger.debug("no snmp data retrieved", host: definition[:host_address])
      end
    end
  end

  def stoppable_interval_runner
    StoppableIntervalRunner.new(self)
  end

  def close
    return if @client.nil?

    begin
      @client.close
    rescue => e
      logger.warn("Error closing client. Ignoring", :exception => e)
    end
  end

  def stop
  end

  private

  OID_REGEX = /^\.?([0-9\.]+)$/
  HOST_REGEX = /^(?<host_protocol>\w+):(?<host_address>.+)\/(?<host_port>\d+)$/i
  VERSION_REGEX =/^1|2c|3$/

  def validate_oids!
    @get = Array(@get).map do |oid|
      # verify oids for valid pattern and get rid or any leading dot if present
      unless oid =~ OID_REGEX
        raise(LogStash::ConfigurationError, "The get option oid '#{oid}' has an invalid format")
      end
      $1
    end

    @walk = Array(@walk).map do |oid|
      # verify oids for valid pattern and get rid or any leading dot if present
      unless oid =~ OID_REGEX
        raise(LogStash::ConfigurationError, "The walk option oid '#{oid}' has an invalid format")
      end
      $1
    end

    if !@tables.nil?
      @tables.each do |table_entry|
      # Verify oids for valid pattern and get rid of any leading dot if present
        columns = table_entry["columns"]
        columns.each do |column|
          unless column =~ OID_REGEX
      	    raise(Logstash::ConfigurationError, "The table column oid '#{column}' is an invalid format")
          end
        end
        $1
      end
    end

    raise(LogStash::ConfigurationError, "at least one get OID, one walk OID, or one table OID is required") if @get.empty? && @walk.empty? && @tables.nil?
  end

  def validate_v3_user!
    errors = []

    errors << "v3 user must have a \"security_name\" option" if @security_name.nil?
    errors << "you must specify an auth protocol if you specify an auth pass" if @auth_protocol.nil? && !@auth_pass.nil?
    errors << "you must specify an auth pass if you specify an auth protocol" if !@auth_protocol.nil? && @auth_pass.nil?
    errors << "you must specify a priv protocol if you specify a priv pass" if @priv_protocol.nil? && !@priv_pass.nil?
    errors << "you must specify a priv pass if you specify a priv protocol" if !@priv_protocol.nil? &&  @priv_pass.nil?

    raise(LogStash::ConfigurationError, errors.join(", ")) unless errors.empty?
   end


  def validate_hosts!
    # TODO: for new we only validate the host part, not the other optional options

    raise(LogStash::ConfigurationError, "at least one host definition is required") if Array(@hosts).empty?

    @hosts.each do |host|
      raise(LogStash::ConfigurationError, "each host definition must have a \"host\" option") if !host.is_a?(Hash) || host["host"].nil?
    end
  end
  
  def validate_tables!
    if !@tables.nil?
      @tables.each do |table_entry|
        raise(LogStash::ConfigurationError, "each table definition must have a \"name\" option") if !table_entry.is_a?(Hash) || table_entry["name"].nil?
      end
    end
  end

  def build_client!(mib_manager, client_protocols)
    client_builder = org.logstash.snmp.SnmpClient.builder(mib_manager, client_protocols)
    unless @security_name.nil?
      client_builder.addUsmUser(@security_name, @auth_protocol, @auth_pass&.value, @priv_protocol, @priv_pass&.value)
    end
    client_builder.build
  end

  ##
  # The StoppableIntervalRunner is capable of running a block of code at a
  # repeating interval, while respecting the stop condition of the plugin.
  class StoppableIntervalRunner
    ##
    # @param plugin [#logger,#stop?]
    def initialize(plugin)
      @plugin = plugin
    end

    ##
    # Runs the provided block repeatedly using the provided interval.
    # After executing the block, the remainder of the interval if any is slept off
    # using an interruptible sleep.
    # If no time remains, a warning is emitted to the logs.
    #
    # @param interval_seconds [Integer,Float]
    # @param desc [String] (default: "operation"): a description to use when logging
    # @yield
    def every(interval_seconds, desc="operation", &block)
      until @plugin.stop?
        start_time = Time.now

        yield

        duration_seconds = Time.now - start_time
        if duration_seconds >= interval_seconds
          @plugin.logger.warn("#{desc} took longer than the configured interval", :interval_seconds => interval_seconds, :duration_seconds => duration_seconds.round(3))
        else
          remaining_interval = interval_seconds - duration_seconds
          sleep(remaining_interval)
        end
      end
    end

    # @api private
    def sleep(duration)
      Stud.stoppable_sleep(duration) { @plugin.stop? }
    end
  end
end
