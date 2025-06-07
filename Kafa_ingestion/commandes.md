# consumer kafka : 
```sh
sudo python3 labo/Kafa_ingestion/producer.py -i br-benign -b localhost:29092 

sudo python3 labo/Kafa_ingestion/producer.py -i br-attack -b localhost:29092

python3 labo/Kafa_ingestion/consumer.py 

docker compose -f labo/docker-compose.yml up 

docker compose  -f labo/Kafa_ingestion/docker-compose.yml up

docker compose -f labo/DataWarehouse/docker-compose.yml up

```