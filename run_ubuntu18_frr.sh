echo "$HOME"
docker build -t frr-ubuntu18:latest  -f docker/ubuntu18-ci/Dockerfile .
docker run  --rm  -it  --init --privileged \
	-v "$HOME/frr/tools/etc/frr:/etc/frr:ro" \
	frr-ubuntu18:latest /bin/bash