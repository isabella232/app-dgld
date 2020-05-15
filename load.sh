#!/bin/bash
set -e
# keep track of the last executed command
trap 'last_command=$current_command; current_command=$BASH_COMMAND' DEBUG
# echo an error message before exiting
trap 'echo "\"${last_command}\" command filed with exit code $?."' EXIT

./docker-cp-dgld.sh
(cd apploader && ./deleteApp.sh DGLD && cd load_dgld && ./load.sh)


