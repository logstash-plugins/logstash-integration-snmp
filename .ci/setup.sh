#!/bin/bash

set -ex

# Avoid gem naming conflicts as the logstash-input-snmp and logstash-input-snmptrap plugins
# are embedded is a few Logstash versions.
nohup /usr/share/logstash/bin/logstash-plugin remove logstash-input-snmp
nohup /usr/share/logstash/bin/logstash-plugin remove logstash-input-snmptrap