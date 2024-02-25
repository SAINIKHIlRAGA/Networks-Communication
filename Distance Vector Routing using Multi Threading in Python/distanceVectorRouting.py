import json
import os
import sys
import time

from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread

LOCALHOST = '127.0.0.1'
nodes = []
nodeServerSockets = {}
nodeConnectionsToNeighborsPorts = {}

def getKeyUsingValue(dict, value):
    for key, val in dict.items():
        if isinstance(val, list):
            for v in val:
                if v == value:
                    return key
        elif val == value:
            return key
    return None


class Node(Thread):
    def __init__(self, name, neighbors):
        super(Node, self).__init__()
        self.name = name
        self.socket = nodeServerSockets[int(self.name)]
        self.neighbors = neighbors
        self.clientSockets = {}
        self.routingRow = {str(neighbor): weight for neighbor, weight in neighbors.items()}
        self.routingRow[str(self.name)] = 0
        self.haveUpdatesToSend = False

    def run(self):
        self.socket.listen()
        Thread(target=self.startAcceptingConnections).start()
        time.sleep(1)
        self.createClientConnectionsToNeighbors()

    def startAcceptingConnections(self):
        while True:
            connectionFromNeighbor, _ = self.socket.accept()
            Thread(target=self.handleClientConnections, args=(connectionFromNeighbor,)).start()

    def handleClientConnections(self, connectionFromNeighbor):
        while True:
            receivedData = connectionFromNeighbor.recv(1024).decode('utf-8')
            neighborNode = getKeyUsingValue(nodeConnectionsToNeighborsPorts, connectionFromNeighbor.getpeername()[1])
            print(f'Node {chr(int(self.name) + 65)} received DV from {chr(int(neighborNode) + 65)}')
            if receivedData:
                try:
                    neighborRoutingRow = json.loads(receivedData)
                    self.updateRoutingRow(neighborRoutingRow, neighborNode)
                except Exception:
                    pass

    def updateRoutingRow(self, neighborRoutingRow, neighborNode):
        neighborCost = self.routingRow[neighborNode]
        self.haveUpdatesToSend = False
        for dest, cost in neighborRoutingRow.items():
            if dest not in self.routingRow:
                self.routingRow[dest] = neighborCost + cost
                self.haveUpdatesToSend = True
            elif neighborCost + cost < self.routingRow[dest]:
                self.routingRow[dest] = neighborCost + cost
                self.haveUpdatesToSend = True

        if self.haveUpdatesToSend:
            print(f'Updating DV matrix at node {chr(int(self.name) + 65)}')
            print(f'New DV Matrix at node {chr(int(self.name) + 65)} = {getDVRow(self.routingRow)}')
        else:
            print(f'No change in DV at node {chr(int(self.name) + 65)}')

    def broadcastUpdatedRow(self):
        for neighbor, sock in self.clientSockets.items():
            print(f'\nSending DV to Node {chr(int(neighbor) + 65)}')
            message = json.dumps(self.routingRow)
            sock.send(message.encode('utf-8'))
            time.sleep(0.2)
        self.haveUpdatesToSend = False

    def createClientConnectionsToNeighbors(self):
        for neighbor in self.neighbors.keys():
            connected = False
            while not connected:
                try:
                    connectionToNeighbor = socket(AF_INET, SOCK_STREAM)
                    connectionToNeighbor.connect((LOCALHOST, nodeServerSockets[neighbor].getsockname()[1]))
                    self.clientSockets[neighbor] = connectionToNeighbor
                    if self.name in nodeConnectionsToNeighborsPorts:
                        nodeConnectionsToNeighborsPorts[self.name].append(connectionToNeighbor.getsockname()[1])
                    else:
                        nodeConnectionsToNeighborsPorts[self.name] = [connectionToNeighbor.getsockname()[1]]
                    connected = True
                except ConnectionRefusedError:
                    print(f"Node {self.name} could not connect to neighbor {neighbor}, retrying...")
                    time.sleep(1)


def getDVRow(routingRow):
    dvRow = [999 for i in range(len(nodes))]
    for key, value in routingRow.items():
        dvRow[int(key)] = value
    return dvRow


def getRoutingTable(file_path):
    with open(file_path, 'r') as f:
        routingTable = [list(map(int, line.split(" "))) for line in f]
    return routingTable


def finalOutput(n):
    print()
    print('-' * 100)
    print()
    for node in nodes:
        print(f'Node {chr(int(node.name)+65)} DV = {getDVRow(node.routingRow)}')
    print(f'\nNumber of rounds till convergence (Round # when one of the nodes last updated its DV) = {n}\n\n')
    print('-' * 100)


def monitor():
    round = 0
    lastDV = {}
    for node in nodes:
        lastDV[node.name] = node.routingRow.copy()

    while True:
        for node in nodes:
            round += 1
            print()
            print('-' * 100)
            print(f'\nRound {round}: {chr(int(node.name) + 65)}')
            print(f'\nCurrent DV Matrix: {getDVRow(node.routingRow)}')
            print(f'\nLast DV Matrix:    {getDVRow(lastDV[node.name])}')
            status = 'Updated' if node.routingRow != lastDV[node.name] else 'Not Updated'
            print(f'\nUpdated from last DV matrix or the same? {status}')
            if status == 'Updated' or round == 1 or node.haveUpdatesToSend:
                node.broadcastUpdatedRow()
            else:
                updates_pending = sum([1 for node in nodes if node.haveUpdatesToSend])
                if updates_pending == 0:
                    finalOutput(round)
                    os._exit(0)

            lastDV[node.name] = node.routingRow.copy()


def network_init(file):
    adjacencyMatrix = getRoutingTable(file)
    for nodeName in range(len(adjacencyMatrix)):
        serverSocket = socket(AF_INET, SOCK_STREAM)
        serverSocket.bind((LOCALHOST, 0))
        serverSocket.listen()
        nodeServerSockets[nodeName] = serverSocket

    for nodeName, adjacencyList in enumerate(adjacencyMatrix):
        nodeNeighbors = {}
        for neighborName, weight in enumerate(adjacencyList):
            if nodeName != neighborName and weight > 0:
                nodeNeighbors[neighborName] = weight

        node = Node(nodeName, nodeNeighbors)
        nodes.append(node)
        node.start()

    for node in nodes:
        node.join()

    monitor()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Please provide a single file name that contains Adjancency Matrix of the Network')
    else:
        file = sys.argv[1]
        network_init(file)
