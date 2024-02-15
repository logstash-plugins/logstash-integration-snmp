#!/bin/bash
# This is intended to be run inside the docker container as the command of the docker-compose.
env

set -ex

if [[ "$INTEGRATION" == "true" ]]; then
  bundle exec rspec --format=documentation --tag integration spec/integration
else
  bundle exec rspec --format=documentation spec/unit
fi