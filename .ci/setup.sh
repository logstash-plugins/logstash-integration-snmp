#!/bin/bash

set -ex

# Avoid gem naming conflicts as the logstash-input-snmp and logstash-input-snmptrap plugins
# are embedded with a few Logstash versions.
nohup /usr/share/logstash/bin/logstash-plugin remove logstash-input-snmp
nohup /usr/share/logstash/bin/logstash-plugin remove logstash-input-snmptrap