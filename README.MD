curl -X POST "http://localhost:5003/generate_cert"\
     -H "Content-Type: application/json" \
     -d '{"device_name": "dongle-885C34", "valid_for": 36500, "key_type": "EC"}'

curl -X POST "http://localhost:5003/generate_cert"\
     -H "Content-Type: application/json" \
     -d '{"device_name": "disfunction.cc", "valid_for": 36500, "key_type": "RSA"}'

curl -X POST "http://localhost:5003/getTLSKey"\
     -H "Content-Type: application/json" \
     -d '{"device_name": "dongle-885C34", "valid_for": 36500}'

curl -X POST "http://localhost:5003/getCembedding"\
     -H "Content-Type: application/json"

docker build . -t mszkowalik/fenrir:1.2  --platform linux/amd64
docker build . -t mszkowalik/fenrir:1.2
docker run -p 5003:5000 --env-file .env -v ./certs:/certs -v ./ca-certs:/ca-certs --name fenrir mszkowalik/fenrir:1.2
docker push mszkowalik/fenrir:1.2

## How to create a root certificate:
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -subj "/CN=disfunction.cc" -days 36500 -out ca.crt