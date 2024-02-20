#!/bin/bash
# This is intended to be run inside the docker container as the command of the docker-compose.
env

set -ex

if [[ "$INTEGRATION" == "true" ]]; then
  bundle exec rake test:integration
else
  bundle exec rake test:unit
fi