# Secure DNS Server

This project was implemented as a part of the course ECS235A. In this project, we aim to develop a DNS Server architecture which can mitigate the effects of a DNS Denial of Service attack. Our architecture employs a DNS Gatekeeper server which acts as a proxy between the actual DNS Servers and the user. This Gatekeeper employs IP blocking and simple load-balancing techniques to improve scalability. The complete architecture is given below. 

![Alt text](architecture/architecture.jpg?raw=true)

## Getting Started

The following sections describe how to run the source code and the required setup

### Local Setup

#### Install Python

Install python in your local system, [see this](https://www.python.org/downloads/).

#### Install the required dependencies

```
pip install -r requirements.txt
```
#### Run the DNS Servers

THe following command can be used to run the primary and secondary DNS servers.
```
python3 dns_server.py --port=31111 --zone_file=zones/test_primary.zone --private_key_path=keys/primary.pem

python3 dns_server.py --port=31112 --zone_file=zones/test_secondary.zone --private_key_path=keys/secondary.pem
```
#### Run the DNS Gatekeeper

THe following command can be used to run the DNS Gatekeeper.
```
python3 dns_gatekeeper.py --primary_ns_host=127.0.0.1 --primary_ns_port=31111 --secondary_ns_host=127.0.0.1 --secondary_ns_port=31112 --port=31110
```
#### Testing out setup

Our DNS servers and gatekeeper is now running. To test the setup before setting up the attacker, run the required methods in **utils/dns_tester.py**. Then, simply run the script
```
cd utils
python3 dns_tester.py
```

#### Perform the attack
To start the attacker, simply run the **dns_DOS.py** script with the required params.
```
python3 dns_DOS.py --host=127.0.0.1 --port=31110 --timeout=100 --num_threads=10
```

### Containerized setup

#### Install Docker Desktop
Install Docker Desktop([see this](https://docs.docker.com/desktop/)) and enable Kubernetes in the settings. With this, you should be able to run the _docker_ and _kubectl_ commands in  your terminal.

#### Build Docker images
Build all the necessary Docker images using the Dockerfiles.

```
docker build -t dns_server_primary -f Dockerfile_primary
docker build -t dns_server_secondary . -f Dockerfile_secondary
docker build -t dns_gatekeeper . -f Dockerfile_gatekeeper
docker build -t dns_attacker . -f Dockerfile_attacker
```

#### Install the Nginx ingress controller
Apply the Nginx ingress controller configurations.

```
kubectl apply -f udp_configMap.yaml
kubectl apply -f ingress_nginx.yaml
kubectl apply -f service_ingress.yaml
```

#### Install the DNS Server and Gatekeeper configurations
Apply these configurations. Add the script params in the Dockerfiles and deployment configs before doing so.
```
kubectl apply -f deployment_primary.yaml
kubectl apply -f deployment_secondary.yaml
kubectl apply -f deployment_gatekeeper.yaml
kubectl apply -f deployment_attacker.yaml
kubectl apply -f service_primary.yaml
kubectl apply -f service_secondary.yaml
kubectl apply -f service_gatekeeper.yaml
```

### Utils

The **utils/dns_tester.py** contains functions for testing our DNS Server setup.

The **utils/key_generator.py** contains functions for generating the private and public keys required by our servers.
