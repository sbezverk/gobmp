# Setup

From within the `testbed` folder (note that there are separate files for gobgp and xrd tests):
```
cd ../../..
make container
cd pkg/kafka/testbed
cd gobgp
docker build -t test/gobgp:3.20.0 -f Dockerfile .
cd ..
# single-broker test
docker compose -f docker-compose-single-broker-gobgp.yaml up -d
docker compose -f docker-compose-single-broker-gobgp.yaml logs -f gobmp
docker compose -f docker-compose-single-broker-gobgp.yaml exec gobgp-1 sh
gobgp global rib add 192.168.1.0/24
exit
docker compose -f docker-compose-single-broker-gobgp.yaml exec kafka-1 sh
kafka-console-consumer --bootstrap-server kafka-1:9091 --topic gobmp.parsed.unicast_prefix_v4 --from-beginning
# make sure that kafka messages are present!
docker compose -f docker-compose-single-broker-gobgp.yaml down
# multi-broker test
docker compose -f docker-compose-multi-broker-gobgp.yaml up -d
docker compose -f docker-compose-multi-broker-gobgp.yaml logs -f gobmp
docker compose -f docker-compose-single-broker-gobgp.yaml exec gobgp-1 sh
gobgp global rib add 192.168.1.0/24
exit
docker compose -f docker-compose-multi-broker-gobgp.yaml exec kafka-4 sh
kafka-console-consumer --bootstrap-server kafka-1:9091,kafka-2:9092,kafka-3:9093,kafka-4:9094 --topic gobmp.pars
ed.unicast_prefix_v4 --from-beginning
# make sure that kafka messages are present!
docker compose -f docker-compose-multi-broker-gobgp.yaml down
```