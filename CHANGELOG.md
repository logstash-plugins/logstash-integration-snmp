## Unreleased (4.0.0)
  - Initial Release of SNMP Integration Plugin, incorporating [logstash-input-snmp](https://github.com/logstash-plugins/logstash-input-snmp) and [logstash-input-snmptrap](https://github.com/logstash-plugins/logstash-input-snmptrap).
    Independent changelogs for previous versions can be found:
      - [SNMP Input Plugin](https://github.com/logstash-plugins/logstash-input-snmp/blob/main/CHANGELOG.md)
      - [SNMP Trap Input Plugin](https://github.com/logstash-plugins/logstash-input-snmptrap/blob/main/CHANGELOG.md)
  - Migrate the SNMP4J clients to Java and unified the MIB file reader and field mapper to be used
    used by all plugins.
  - Changed the read approach for `smilib` .dic MIBs files.
  - Changed to use the `MultiThreadedMessageDispatcher` by default.
  - Instead of using one client instance per host, it now uses a single multi-version client for all hosts.