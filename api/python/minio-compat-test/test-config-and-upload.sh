# The Docker Compose deployment starts up MinIO and creates quilt-example
# bucket in separate container with mc (minio client CLI)
docker-compose up -d

# Configure quilt s3 connection details matching those in docker-compose config
quilt3 config --set-s3 access_key=user secret_key=helloworld endpoint_url=http://localhost:9000

# Wait a second to make sure Docker deployment is up
sleep 2

# Push the dummy directory to MinIO as package
quilt3 push --dir dummy --registry s3://quilt-example  --message "Testing 123" --meta '{"hello": "world"}' test/test

# Shutdown deployment
docker-compose down
