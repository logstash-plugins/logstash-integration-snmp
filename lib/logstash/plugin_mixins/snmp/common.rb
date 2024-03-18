module LogStash
  module PluginMixins
    module Snmp
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
          base.config :use_provided_mibs, :validate => :boolean, :default => default_use_provided_mibs(base)

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
          base.config :oid_mapping_format, :validate => %w[default ruby_snmp dotted_string], :default => default_oid_mapping_format(base)

          # number of OID root digits to ignore in event field name. For example, in a numeric OID
          # like 1.3.6.1.2.1.1.1.0" the first 5 digits could be ignored by setting oid_root_skip => 5
          # which would result in a field name "1.1.1.0". Similarly when a MIB is used an OID such
          # as "1.3.6.1.2.mib-2.system.sysDescr.0" would become "mib-2.system.sysDescr.0"
          base.config :oid_root_skip, :validate => :number, :default => 0

          # number of OID tail digits to retain in event field name. For example, in a numeric OID
          # like 1.3.6.1.2.1.1.1.0" the last 2 digits could be retained by setting oid_path_length => 2
          # which would result in a field name "1.0". Similarly, when a MIB is used an OID such as
          # "1.3.6.1.2.mib-2.system.sysDescr.0" would become "sysDescr.0"
          base.config :oid_path_length, :validate => :number, :default => 0

          # Defines a target field for placing fields.
          # If this setting is omitted, data gets stored at the root (top level) of the event.
          # The target is only relevant while decoding data into a new event.
          base.config :target, :validate => :field_reference
        end

        def self.default_oid_mapping_format(base)
          if snmptrap_plugin?(base)
            OID_MAPPING_FORMAT_RUBY_SNMP
          else
            OID_MAPPING_FORMAT_DEFAULT
          end
        end

        def self.default_use_provided_mibs(base)
          !snmptrap_plugin?(base)
        end

        def build_mib_manager!
          mib_manager = new_mib_manager

          @mib_paths&.each do |path|
            logger.info("Using user provided MIB path #{path}")
            mib_manager.add(path)
          end

          if @use_provided_mibs
            MIB_PROVIDED_PATHS.each do |path|
              logger.info("Using plugin provided MIB path #{path}")
              mib_manager.add(path)
            end
          end

          mib_manager
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

        def self.snmptrap_plugin?(base)
          !defined?(LogStash::Inputs::Snmptrap).nil? && base == LogStash::Inputs::Snmptrap
        end
      end
    end
  end
end