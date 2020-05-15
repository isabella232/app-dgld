#!/bin/bash
docker run --name ledger-dgld-app -t -i -d ledger-dgld-app /bin/bash 
rm -rf apploader/load_dgld
docker cp ledger-dgld-app:/apploader/load_dgld apploader
docker container stop ledger-dgld-app
