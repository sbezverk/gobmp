# Setup

```
cd ../../..
make container
cd pkg/kafka/testbed
docker compose -f docker-compose-single-broker.yaml up -d
docker compose -f docker-compose-single-broker.yaml logs -f gobmp
# TEST!
docker compose -f docker-compose-single-broker.yaml exec kafka-1 sh
docker compose -f docker-compose-single-broker.yaml exec xr-1 sh
docker compose -f docker-compose-single-broker.yaml down
docker compose -f docker-compose-multi-broker.yaml up -d
docker compose -f docker-compose-multi-broker.yaml logs -f gobmp
docker compose -f docker-compose-multi-broker.yaml exec kafka-2 sh
docker compose -f docker-compose-multi-broker.yaml exec xr-1 sh
# TEST!
docker compose -f docker-compose-multi-broker.yaml down
```