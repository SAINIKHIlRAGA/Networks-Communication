
# DNS Client Implementation in Python

## Description
This script provides a basic implementation of a DNS client in Python. It includes functions to create and send DNS queries and interpret the responses.

## Prerequisites
- Python 3.x
- Required libraries: `random`, `socket`, `struct`, `sys`

## Usage
To run the DNS client, execute the following command:

python my-dns-client.py <hostname>

For example,
python my-dns-client.py gmu.edu
python my-dns-client.py google.com
python my-dns-client.py microsoft.com
python my-dns-client.py amazon.com
python my-dns-client.py apple.com





# Distance Vector Algorithm Implementation in Python

## Description
This script provides a basic implementation of a Distance Vector Algorithm in Python. It takes an Adjacency Matrix of any Network as an input and
creates required nodes and establishes communication between those nodes and allows those nodes to communicate each other in order to exchange their
DV Rows until the whole Network stabilizes.

## Prerequisites
- Python 3.x
- Required libraries: `json`, `os`, `socket`, `sys`, `time`, `threading`

## Usage
To run the Distance Vector Algorithm Implementation, execute the following command:

python distanceVector.py <network-file-name>

For example,
python distanceVector.py network1.txt
python distanceVector.py network2.txt
