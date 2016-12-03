exec ./scald \
	-x json_dir=$PWD/examples/json \
	-x json_models=tr-181 \
	-x device_file=$PWD/examples/data/cwmp-device.json \
	-x uci_confdir=$PWD/examples/config \
	-x cwmp_local_addr=127.0.0.1:80 \
	-p $PWD/plugins/scapi_json.so "$@"
