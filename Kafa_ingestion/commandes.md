# consumer kafka : 
```sh
python sniffer_kafka.py -i br-benign -b localhost:29092 -l Normal

python3 producer.py -i br-benign -b localhost:29092 -l Normal

``