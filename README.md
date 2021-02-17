# IoT-Monitor-system

This project develops a monitoring system that reveals the health status of an IoT network, as well as to detect possible
anomalies within it. For this purpose, the captured MQTT or CoAP traffic is analyzed, generating log files, which will be stored in databases, so that they can be accessed in
order to graphically represent the results obtained. The purpose of this representation is
to allow a network manager to know the status of the IoT network analyzed in a clear and intuitive way, through a dashboard, using Grafana.

## How it works:
- First the traffic need to be analyced, for that manner we will need traffic captures from MQTT or CoAP protocols in pcap format.
  - For it, we need to compile and execute mqtt_hash_Final.c or coap_hash_Final.c. We compile with gcc -Wall -o mqtt mqtt_hash_Final.c -lpcap  or   gcc -Wall -o coap coap_hash_Final.c - lpcap  and execute ./mqtt(coap) -f traffic.pcap
- Then a CSV file will be created with the parameters we are going to use for monitoring.
- Once we have that we can take them to the database, in our case Elasticsearch, using Logstash.
  - For that we execute ./bin/logstash -g logstash_mqtt(coap).conf
- After that we can visualice the data from Grafana importing the json models
