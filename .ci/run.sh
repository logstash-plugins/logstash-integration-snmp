#!/bin/bash
# This is intended to be run inside the docker container as the command of the docker-compose.
env

set -ex

# logstash-core compiles pipelines with google-java-format, which needs these
# jdk.compiler exports. `bin/logstash` sets them via jvm.options, but the tests
# run under a plain `bundle exec` JRuby that does not, so compiling a pipeline
# (notably the multi-input specs) raises:
#   IllegalAccessError: ... jdk.compiler does not export com.sun.tools.javac.parser
export JAVA_OPTS="${JAVA_OPTS} \
--add-exports=jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED \
--add-exports=jdk.compiler/com.sun.tools.javac.file=ALL-UNNAMED \
--add-exports=jdk.compiler/com.sun.tools.javac.parser=ALL-UNNAMED \
--add-exports=jdk.compiler/com.sun.tools.javac.tree=ALL-UNNAMED \
--add-exports=jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED"

if [[ "$INTEGRATION" == "true" ]]; then
  bundle exec rake test:integration
else
  bundle exec rake test:unit
fi