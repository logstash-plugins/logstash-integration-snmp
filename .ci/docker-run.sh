#!/bin/bash

# This is intended to be run inside the docker container as the command of the docker-compose.
set -ex

CURRENT_DIR=$(dirname "${BASH_SOURCE[0]}")

cd .ci

if [[ "$INTEGRATION" == "true" ]]; then
  docker_compose_override="-f docker-compose-integration.override.yml"
else
  docker_compose_override=""
fi

# docker will look for: "./docker-compose.yml" (and "./docker-compose.override.yml")
docker-compose up -f docker-compose.yml $docker_compose_override --exit-code-from logstash