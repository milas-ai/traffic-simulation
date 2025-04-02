all:
	docker build -t milas098/network-test-controller . && clear && docker run --rm -it --network="host" --cap-add=NET_RAW --cap-add=NET_ADMIN -v .:/app milas098/network-test-controller 3