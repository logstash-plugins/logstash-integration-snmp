## 4.0.4
  - [DOC] Update banners and set user expectations for general availability (GA) [#67](https://github.com/logstash-plugins/logstash-integration-snmp/pull/67)

## 4.0.3
  - [DOC] Restore links to importing MIBs info [#60](https://github.com/logstash-plugins/logstash-integration-snmp/pull/60)

## 4.0.2
  - Fixed `input-snmp` `tables` event mapping to remove the "index" value from the OID field (backward compatibility) [#61](https://github.com/logstash-plugins/logstash-integration-snmp/pull/61)

## 4.0.1
  - [DOC] Add technical preview banner and reimplement cross-doc links [#57](https://github.com/logstash-plugins/logstash-integration-snmp/pull/57)

## 4.0.0
  - Initial Release of SNMP Integration Plugin, incorporating [logstash-input-snmp](https://github.com/logstash-plugins/logstash-input-snmp) and [logstash-input-snmptrap](https://github.com/logstash-plugins/logstash-input-snmptrap).
    Independent changelogs for previous versions can be found:
      - [SNMP Input Plugin](https://github.com/logstash-plugins/logstash-input-snmp/blob/main/CHANGELOG.md)
      - [SNMP Trap Input Plugin](https://github.com/logstash-plugins/logstash-input-snmptrap/blob/main/CHANGELOG.md)
  - Migrated the SNMP4J clients to Java and unified the MIB file reader and field mapper to be used by all plugins.
  - Changed the read approach for `smilib` .dic MIBs files.
  - Changed to use the `MultiThreadedMessageDispatcher` by default.
  - Instead of using one client instance per host, it now uses a single multi-version client for all hosts.
  - Migrated `logstash-input-snmptrap` client from ruby-snmp to SNMP4J
    - The event `message` content was changed from the ruby `SNMP::SNMPv1_Trap` object `inspect` representation
      to a hash dump based on the RFC definition. It also adds the fields as `[@metadata][input][snmptrap][pdu][<name>]` metadata.
    - Added `supported_transports` and `supported_versions` options.
  - Standardized the `logstash-input-snmp` and `logstash-input-snmptrap` settings, supported MIB formats and features.
    - Both plugins now support .dic (`libsmi`) and .yaml (`ruby-snmp`) MIB formats.
    - Added the `oid_mapping_format` option to configure how the OID field is mapped in the Logstash event.
    - Added the `oid_map_field_values` option to enable/disable OID field values mapping. 
    - The `logstash-input-snmptrap` now supports the `logstash-input-snmp` features: `mib_paths`, `use_provided_mibs`, `oid_root_skip`, `oid_path_length`.
  - The `logstash-input-snmptrap` `yamlmibdir` was deprecated in favor of `mib_paths`.
  - Updated the `logstash-input-snmptrap` docs to include the same `logstash-input-snmp` instructions on how importing MIB files.
  - Added SNMPv3 support to `logstash-input-snmptrap`.
  - Added multi-thread support to `logstash-input-snmp` and `logstash-input-snmptrap` plugins.
    - Upgraded SNMP4J version to `3.8.0`, it has a better multi-threading support and has fixed several issues.
