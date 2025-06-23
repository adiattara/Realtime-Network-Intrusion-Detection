# consumer kafka : 
```sh

docker compose -f labo/docker-compose.yml up 


docker compose  -f labo/Kafa_ingestion/docker-compose.yml up


sudo python3 labo/Kafa_ingestion/producer.py -i br-benign -b localhost:29092 



docker compose -f labo/DataWarehouse/docker-compose.yml up


sudo python3 labo/Kafa_ingestion/producer.py -i br-attack -b localhost:29092


python3 labo/Kafa_ingestion/consumer.py 

python3 labo/Kafa_ingestion/cloud/consumer_cloud.py


docker compose -f labo/DataWarehouse/docker-compose.yml up


docker compose -f labo/models/docker-compose.yml up

python3 labo/Kafa_ingestion/models_consumer.py



#### Cloud Consumer

docker compose -f labo/docker-compose.yml up 

python3 labo/Kafa_ingestion/cloud/consumer_cloud.py

python3 labo/Kafa_ingestion/cloud/models_consumer_cloud.py

sudo python3 labo/Kafa_ingestion/cloud/producer_cloud.py -i br-benign -b pkc-p11xm.us-east-1.aws.confluent.cloud:9092





```