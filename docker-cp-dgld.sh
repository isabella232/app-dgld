#!/bin/bash
docker run --name ledger-dgld-app -d ledger-dgld-app tail -f /dev/null
rm -rf apploader/load_dgld
docker cp ledger-dgld-app:/apploader/load_dgld apploader
docker container stop ledger-dgld-app
docker container rm ledger-dgld-app
