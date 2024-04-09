curl -X POST "http://localhost:5003/generate_cert"\
     -H "Content-Type: application/json" \
     -d '{"device_name": "exampleDevice", "valid_for": 36500, "key_type": "EC"}'

curl -X POST "http://localhost:5003/getTLSKey"\
     -H "Content-Type: application/json" \
     -d '{"device_name": "exampleDevice", "valid_for": 36500, "key_type": "EC"}'