#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# The Docker Compose deployment starts up MinIO and creates quilt-example
# bucket in separate container with mc (minio client CLI)
docker-compose up -d

# Create and activate Python virtual environment, remove previous venv
# if necessary
VENV_DIR=.minio-compat-test-venv
if [ -d "$VENV_DIR" ]; then rm -r $VENV_DIR; fi
python -m venv $VENV_DIR && source $VENV_DIR/bin/activate

# Install quilt
cd $SCRIPT_DIR/..
    pip install .
cd $SCRIPT_DIR

# Configure quilt s3 connection details matching those in docker-compose config
quilt3 config --set-s3 access_key=user secret_key=helloworld endpoint_url=http://localhost:9000

# Push the dummy directory to MinIO as package
quilt3 push --dir dummy --registry s3://quilt-example  --message "Testing 123" --meta '{"hello": "world"}' test/test

# Shutdown deployment
docker-compose down

# Cleanup virtual environment
deactivate
if [ -d "$VENV_DIR" ]; then rm -r $VENV_DIR; fi
