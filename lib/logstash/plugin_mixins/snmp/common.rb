module LogStash
  module PluginMixins
    module Snmp
      # This module provides common configurations and functions to all SNMP plugins
      #
      module Common
        require 'logstash-integration-snmp_jars'

        java_import 'org.logstash.snmp.RubySnmpOidFieldMapper'
        java_import 'org.logstash.snmp.DefaultOidFieldMapper'
        java_import 'org.logstash.snmp.DottedStringOidFieldMapper'
        java_import 'org.logstash.snmp.mib.MibManager'

        OID_MAPPING_FORMAT_DEFAULT = 'default'.freeze
        OID_MAPPING_FORMAT_RUBY_SNMP = 'ruby_snmp'.freeze

        MIB_BASE_PATH = ::File.join(__FILE__, '..', '..', '..', '..', 'mibs')
        MIB_PROVIDED_PATHS = [::File.join(MIB_BASE_PATH, 'logstash'), ::File.join(MIB_BASE_PATH, 'ietf')].map { |path| ::File.expand_path(path) }

        def self.included(base)
          # Common configuration supported by all SNMP plugins

          # This plugin provides sets of MIBs publicly available. The full paths to these provided MIBs paths
          # Will be displayed at plugin startup.
          base.config :use_provided_mibs, :validate => :boolean, :default => true

          # List of paths of MIB (.dic, .yaml) files of dirs. If a dir path is specified, all files with
          # .dic and .yaml extension will be loaded.
          #
          # ATTENTION: a MIB .dic file must be generated using the libsmi library `smidump` command line utility
          # like this for example. Here the `RFC1213-MIB.txt` file is an ASN.1 MIB file.
          #
          # `$ smidump -k -f python RFC1213-MIB.txt > RFC1213-MIB.dic`
          #
          # The OSS libsmi library https://www.ibr.cs.tu-bs.de/projects/libsmi/ is available & installable
          # on most OS.
          #
          # .yaml MIBs files must be on the https://github.com/hallidave/ruby-snmp MIB format.
          base.config :mib_paths, :validate => :array # ["path/to/mib.dic", "path/to/mib/dir"]

          # Defines the OID field format.
          # `ruby_snmp` produces ruby-snmp-like fields, prefixing the module name, followed
          # by :: and resolved identifiers. E.g:
          # 1.3.6.1.2.1.1.2.0 -> SNMPv2-MIB::sysObjectID.0
          # `default` translates every identifier separating them by dots. E.g:
          # 1.3.6.1.2.1.1.2.0 -> iso.org.dod.internet.mgmt.mib-2.system.sysObjectID.0
          # `dotted_string` does not change the OID format and map fields using the dotted string format, E.g:
          # 1.3.6.1.2.1.1.2.0 -> 1.3.6.1.2.1.1.2.0
          base.config :oid_mapping_format, :validate => %w[default ruby_snmp dotted_string], :default => 'default'

          # Defines if the Logstash event field values, which types are `OID`, are mapped using the configured OID textual representation
          # set on the `oid_mapping_format`.
          base.config :oid_map_field_values, :validate => :boolean, :default => false

          # Number of OID root digits to ignore in event field name. For example, in a numeric OID
          # like 1.3.6.1.2.1.1.1.0" the first 5 digits could be ignored by setting oid_root_skip => 5
          # which would result in a field name "1.1.1.0". Similarly when a MIB is used an OID such
          # as "1.3.6.1.2.mib-2.system.sysDescr.0" would become "mib-2.system.sysDescr.0"
          base.config :oid_root_skip, :validate => :number, :default => 0

          # Number of OID tail digits to retain in event field name. For example, in a numeric OID
          # like 1.3.6.1.2.1.1.1.0" the last 2 digits could be retained by setting oid_path_length => 2
          # which would result in a field name "1.0". Similarly, when a MIB is used an OID such as
          # "1.3.6.1.2.mib-2.system.sysDescr.0" would become "sysDescr.0"
          base.config :oid_path_length, :validate => :number, :default => 0

          # Defines a target field for placing fields.
          # If this setting is omitted, data gets stored at the root (top level) of the event.
          # The target is only relevant while decoding data into a new event.
          base.config :target, :validate => :field_reference

          # SNMPv3 Credentials
          #
          # A single user can be configured and will be used for all defined SNMPv3 requests.
          # Multiple snmp input declarations will be needed if multiple SNMPv3 users are required.
          # If not using SNMPv3 simply leave options empty.

          # The SNMPv3 security name or user name
          base.config :security_name, :validate => :string

          # The SNMPv3 authentication protocol or type
          base.config :auth_protocol, :validate => %w[md5 sha sha2 hmac128sha224 hmac192sha256 hmac256sha384 hmac384sha512]

          # The SNMPv3 authentication passphrase or password
          base.config :auth_pass, :validate => :password

          # The SNMPv3 privacy/encryption protocol
          base.config :priv_protocol, :validate => %w[des 3des aes aes128 aes192 aes256]

          # The SNMPv3 encryption password
          base.config :priv_pass, :validate => :password

          # The SNMPv3 security level can be Authentication, No Privacy; Authentication, Privacy; or no Authentication, no Privacy
          base.config :security_level, :validate => %w[noAuthNoPriv authNoPriv authPriv]
        end

        def build_mib_manager!
          mib_manager = new_mib_manager

          if @mib_paths&.any?
            logger.info('Loading user-provided MIB files', :path => @mib_paths)
            @mib_paths.each do |path|
              mib_manager.add(path)
            end
          end

          if @use_provided_mibs
            logger.info('Loading provided MIB files', :path => MIB_PROVIDED_PATHS)
            MIB_PROVIDED_PATHS.each do |path|
              mib_manager.add(path)
            end
          end

          mib_manager
        end

        def build_snmp_client!(client_builder, validate_usm_user: false)
          validate_usm_user! if validate_usm_user

          unless @security_name.nil?
            client_builder.addUsmUser(@security_name, @auth_protocol, @auth_pass&.value, @priv_protocol, @priv_pass&.value)
          end

          client_builder.setMapOidVariableValues(@oid_map_field_values)
          client_builder.build
        end

        private

        def new_mib_manager
          MibManager.new(oid_field_mapper!)
        end

        def oid_field_mapper!
          validate_oid_field_mapper_params!

          if @oid_mapping_format == OID_MAPPING_FORMAT_DEFAULT
            DefaultOidFieldMapper.new(@oid_root_skip, @oid_path_length)
          elsif @oid_mapping_format == OID_MAPPING_FORMAT_RUBY_SNMP
            RubySnmpOidFieldMapper.new
          else
            DottedStringOidFieldMapper.new
          end
        end

        def validate_oid_field_mapper_params!
          if @oid_mapping_format == 'default'
            raise(LogStash::ConfigurationError, 'Use either `oid_root_skip` or `oid_path_length`') if @oid_root_skip.positive? && @oid_path_length.positive?
          else
            raise(LogStash::ConfigurationError, 'The `oid_root_skip` and `oid_path_length` requires setting `oid_mapping_format` to `default`') if @oid_root_skip.positive? || @oid_path_length.positive?
          end
        end

        def validate_usm_user!
          errors = []

          errors << '`security_name` is required when SNMP v3 is enabled' if @security_name.nil?
          validate_auth_protocol(errors)
          validate_priv_protocol(errors)

          raise(LogStash::ConfigurationError, errors.join(', ')) if errors.any?
        end

        def validate_auth_protocol(errors)
          validate_protocol_config(errors, 'auth_protocol', 'auth_pass')

          if @auth_protocol.nil? && (@security_level == 'authNoPriv' || @security_level == 'authPriv')
            errors << "Using `security_level` set to `#{@security_level}` requires the configuration of `auth_protocol`"
          end
        end

        def validate_priv_protocol(errors)
          validate_protocol_config(errors, 'priv_protocol', 'priv_pass')

          if @priv_protocol.nil? && @security_level == 'authPriv'
            errors << "Using `security_level` set to `#{@security_level}` requires the configuration of `priv_protocol`"
          end
        end

        def validate_protocol_config(errors, protocol_config_name, pass_config_name)
          protocol_config_value = instance_variable_get("@#{protocol_config_name}".intern)
          pass_config_value = instance_variable_get("@#{pass_config_name}".intern)

          if protocol_config_value && !pass_config_value
            errors << "Using `#{protocol_config_name}` requires the `#{pass_config_name}`"
          elsif pass_config_value && !protocol_config_value
            errors << "`#{protocol_config_name}` is required when using `#{pass_config_name}`"
          end

          if pass_config_value&.value && pass_config_value.value.length < 8
            errors << "`#{pass_config_name}` passphrase must be at least 8 bytes long"
          end
        end
      end
    end
  end
end
