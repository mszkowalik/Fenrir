curl -X POST "http://localhost:5003/generate_cert"\
     -H "Content-Type: application/json" \
     -d '{"device_name": "exampleDevice", "valid_for": 36500, "key_type": "EC"}'

curl -X POST "http://localhost:5003/getTLSKey"\
     -H "Content-Type: application/json" \
     -d '{"device_name": "exampleDevice", "valid_for": 36500}'

docker build . -t mszkowalik/fenrir:1.1  --platform linux/amd64
docker build . -t mszkowalik/fenrir:1.1
docker run -p 5003:5000 --env-file .env -v ./certs:/certs -v ./ca-certs:/ca-certs --name fenrir mszkowalik/fenrir:1.1
docker push mszkowalik/fenrir:1.1
