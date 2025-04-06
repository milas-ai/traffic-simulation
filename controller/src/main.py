from simple_term_menu import TerminalMenu
from subprocess import Popen, DEVNULL
from threading import Thread
import pyshark
import socket
import time
import sys
import os

RECORD_TIMEOUT = 5
DEFAULT_FEATURES = {
    "pkSeqID": 1,
    "stime": -1,
    "flgs": -1,
    "proto": -1,
    "saddr": -1,
    "sport": -1,
    "daddr": -1,
    "dport": -1,
    "pkts": -1,
    "bytes": -1,
    "ltime": -1,
    "seq": -1,
    "dur": -1,
    "mean": -1,
    "stddev": -1,
    "sum": 0,
    "min": -1,
    "max": -1,
    "spkts": -1,
    "dpkts": -1,
    "sbytes": -1,
    "dbytes": -1,
    "rate": -1,
    "srate": -1,
    "drate": -1,
    "attack": 0,
    "category": "Normal",
    "subcategory": "Normal",
}
DEBUG = False

class Controller:
    workers = []
    capture_process = None
    monitor_process_terminate = False
    packet_features = {}

    def __init__(self, num_workers):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                self.server.bind(('', 1234))
                break
            except:
                time.sleep(1) # Wait for the port to be released
        self.server.listen(num_workers)
        print("Controller started")

    def search(self):
        conn, addr = self.server.accept()
        print(f"Worker found at {addr}")
        self.workers.append({
            "connection": conn,
            "address": addr
        })

    def loadFeatures(self):
        if not os.path.exists("/home/features.csv"):
            with open("/home/features.csv", "w") as output_file:
                output_file.write("feature,default_value,output_name,locked\n")
                for default_key, value in DEFAULT_FEATURES.items():
                    output_file.write(f"{default_key},{value},{default_key},False\n")

        with open("/home/features.csv", "r") as output_file:
            for line in output_file.readlines()[1:]:
                key, value, name, locked = line.strip().split(",")
                if key in ["stime","ltime","dur","mean","stddev","sum","min","max","rate","srate","drate"]:
                    value = float(value)
                else:
                    try:
                        value = int(value)
                    except:
                        pass

                self.packet_features[key] = {
                    "value": value,
                    "default_value": value,
                    "name": name,
                    "locked": locked == "True"
                }
            for key, value in DEFAULT_FEATURES.items():
                if key not in self.packet_features:
                    self.packet_features[key] = {
                        "value": value,
                        "default_value": value,
                        "name": "",
                        "locked": False
                    }

    def lockFeatures(self, features_index):
        for i, feature in enumerate(self.packet_features.values()):
            if i in features_index:
                feature["locked"] = True
            else:
                feature["locked"] = False

        with open("/home/features.csv", "w") as output_file:
            output_file.write("feature,default_value,output_name,locked\n")
            for key, feature in self.packet_features.items():
                output_file.write(f"{key},{feature['default_value']},{feature['name']},{feature['locked']}\n")
    
    def startCapture(self):
        self.capture_process = Popen(["tshark", "-i", "any", "-w", "/app/capture.pcapng"], stdout=DEVNULL, stderr=DEVNULL)
        print("Capture started")
        self.capture_process.wait()

    def normalTraffic(self, duration, verbose):
        node_1 = self.workers[0]
        node_2 = self.workers[1]

        if DEBUG:
            start_time = time.time()
            # monitor_thread = Thread(target=self.startMonitor)
            # monitor_thread.start()
        capture_thread = Thread(target=self.startCapture)
        capture_thread.start()
        
        print(f"Normal traffic test started for {duration} seconds")
        
        # Inicia o servidor no node 1 e o cliente no node 2
        node_1["connection"].send("\\start iperf-server".encode())
        node_2["connection"].send(f"\\start iperf-client {node_1["address"][0]} -b 10M -u -t {duration/2}".encode())
        client_response = node_2["connection"].recv(1024).decode()
        self.capture_process.terminate()
        if verbose:
            print("Client response:\n" + client_response)
        node_1["connection"].send("\\terminate_process".encode())

        # Inicia o servidor no node 2 e o cliente no node 1
        node_2["connection"].send("\\start iperf-server".encode())
        node_1["connection"].send(f"\\start iperf-client {node_2["address"][0]} -b 10M -u -t {duration/2}".encode())
        client_response = node_1["connection"].recv(1024).decode()
        self.capture_process.terminate()
        if verbose:
            print("Client response:\n" + client_response)
        node_2["connection"].send("\\terminate_process".encode())

        print("Generating output...")
        data_collector = DataCollector("/app/capture.pcapng", "/home/traffic-capture.csv", "normal", self.packet_features)
        data_collector.createOutput()
        os.remove("/app/capture.pcapng")
        capture_thread.join()
        if DEBUG:
            # self.monitor_process_terminate = True
            # monitor_thread.join()
            print(f"Execution time: {time.time() - start_time:.2f} seconds")
        print("Normal traffic test completed\n")
    
    def synfloodAttack(self, duration, verbose):
        server = self.workers[0]
        client = self.workers[1]
        attacker = self.workers[2]

        if DEBUG:
            start_time = time.time()
            # monitor_thread = Thread(target=self.startMonitor)
            # monitor_thread.start()
        server["connection"].send("\\start iperf-server".encode())
        attacker["connection"].send(f"\\start synflood {server['address'][0]} -p 5201".encode())
        capture_thread = Thread(target=self.startCapture)
        capture_thread.start()
        time.sleep(1)
        client["connection"].send(f"\\start iperf-client {server["address"][0]} -b 10M -u -t {duration}".encode())
        print(f"Synflood traffic test started for {duration} seconds")
        client_response = client["connection"].recv(1024).decode()
        self.capture_process.terminate()
        if verbose:
            print("Client response:\n" + client_response)
        server["connection"].send("\\terminate_process".encode())
        attacker["connection"].send("\\terminate_process".encode())
        print("Generating output...")
        data_collector = DataCollector("/app/capture.pcapng", "/home/traffic-capture.csv", "synflood", self.packet_features)
        data_collector.createOutput()
        os.remove("/app/capture.pcapng")
        if DEBUG:
            # self.monitor_process_terminate = True
            # monitor_thread.join()
            print(f"Execution time: {time.time() - start_time:.2f} seconds")
        print("Synflood traffic test completed\n")

    def startMonitor(self):
        awk_command = f'gsub(/%/,"",$2); gsub(/MiB/,"",$3); print strftime("%Y-%m-%d %H:%M:%S"),$2 >> "cpu_stats.txt"; print strftime("%Y-%m-%d %H:%M:%S"),$3 >> "memory_stats.txt"'
        monitor_command = 'docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" | grep network_test_controller | awk \''+ awk_command +'\';'
        while not self.monitor_process_terminate:
            monitor_process = Popen(monitor_command, shell=True)
            monitor_process.wait()
            time.sleep(0.5)
        os.mv("cpu_stats.txt", "/home/cpu_stats.txt")
        os.mv("memory_stats.txt", "/home/memory_stats.txt")
        self.monitor_process_terminate = False

    def close(self):
        for worker in self.workers:
            worker["connection"].send("\\stop".encode())
            worker["connection"].close()
        self.server.close()
        print("\b\bController closed")

class DataCollector:
    newRecord = False
    output_file = None
    packet_features = {}
    durations = []
    
    def __init__(self, capture_file, output_file, test_type, packet_features):
        self.capture = pyshark.FileCapture(capture_file)
        self.packet_features = packet_features
        self.output_file = open(output_file, "w")
        if test_type == "synflood":
            self.packet_features["attack"]["value"] = 1
            self.packet_features["category"]["value"] = "SynFlood"
            self.packet_features["subcategory"]["value"] = "Netwox"

    def createOutput(self):
        for feature in self.packet_features.values():
            self.output_file.write(f"{feature['name']},")
        self.output_file.write("\n")
        for packet in self.capture:
            if "IP" not in packet:
                continue

            if packet.IP.src != self.packet_features["saddr"]["value"] or packet.IP.dst != self.packet_features["daddr"]["value"] or packet.IP.proto != self.packet_features["proto"]["value"]:
                if packet.IP.src != self.packet_features["daddr"]["value"] and packet.IP.dst != self.packet_features["saddr"]["value"]:
                    self.newRecord = True # Registro novo
                else:
                    self.updateRecord(packet) # Transação de resposta
            else:
                self.updateRecord(packet) # Transação existente

            if self.newRecord:
                if self.packet_features["stime"]["value"] != -1:
                    self.wrapUpRecord()
                    self.writeRecord()
                self.createRecord(packet)
        self.wrapUpRecord()
        self.writeRecord()
        self.capture.close()
        self.output_file.close()

    def writeRecord(self):
        for key, feature in self.packet_features.items():
            if feature["name"] != "":
                if not feature["locked"]:
                    self.output_file.write(f"{feature['value']},")
                else:
                    self.output_file.write(f"{feature['default_value']},")
        self.output_file.write("\n")
        self.packet_features["pkSeqID"]["value"] += 1

    def createRecord(self, packet):
        self.packet_features["stime"]["value"] = (float)(packet.sniff_timestamp)
        self.packet_features["flgs"]["value"] = packet.IP.flags
        self.packet_features["proto"]["value"] = packet.IP.proto
        self.packet_features["saddr"]["value"] = packet.IP.src
        self.packet_features["daddr"]["value"] = packet.IP.dst
        if "TCP" in packet:
            self.packet_features["sport"]["value"] = packet.TCP.srcport
            self.packet_features["dport"]["value"] = packet.TCP.dstport
        elif "UDP" in packet:
            self.packet_features["sport"]["value"] = packet.UDP.srcport
            self.packet_features["dport"]["value"] = packet.UDP.dstport
        else:
            self.packet_features["sport"]["value"] = ""
            self.packet_features["dport"]["value"] = ""
        self.packet_features["pkts"]["value"] = 1
        self.packet_features["bytes"]["value"] = (int)(packet.length)
        # state
        self.packet_features["ltime"]["value"] = (float)(packet.sniff_timestamp)
        # seq
        self.packet_features["spkts"]["value"] = 1
        self.packet_features["dpkts"]["value"] = 0
        self.packet_features["sbytes"]["value"] = (int)(packet.length)
        self.packet_features["dbytes"]["value"] = 0

    def updateRecord(self, packet):
        self.packet_features["pkts"]["value"] += 1
        self.packet_features["flgs"]["value"] = packet.IP.flags
        self.packet_features["proto"]["value"] = packet.IP.proto
        self.packet_features["bytes"]["value"] += (int)(packet.length)
        if packet.IP.src == self.packet_features["saddr"]["value"]:
            self.packet_features["spkts"]["value"] += 1
            self.packet_features["sbytes"]["value"] += (int)(packet.length)
        else:
            self.packet_features["dpkts"]["value"] += 1
            self.packet_features["dbytes"]["value"] += (int)(packet.length)
        self.packet_features["ltime"]["value"] = (float)(packet.sniff_timestamp)
        if self.packet_features["ltime"]["value"] - self.packet_features["stime"]["value"] > RECORD_TIMEOUT:
            self.newRecord = True

    def wrapUpRecord(self):
        self.packet_features["dur"]["value"] = self.packet_features["ltime"]["value"] - self.packet_features["stime"]["value"]
        self.packet_features["sum"]["value"] += self.packet_features["dur"]["value"]
        self.durations.append(self.packet_features["dur"]["value"])
        self.packet_features["min"]["value"] = self.packet_features["dur"]["value"] if self.packet_features["dur"]["value"] < self.packet_features["min"]["value"] or self.packet_features["min"]["value"] == -1 else self.packet_features["min"]["value"]
        self.packet_features["max"]["value"] = self.packet_features["dur"]["value"] if self.packet_features["dur"]["value"] > self.packet_features["max"]["value"] or self.packet_features["max"]["value"] == -1 else self.packet_features["max"]["value"]
        self.packet_features["mean"]["value"] = self.packet_features["sum"]["value"] / self.packet_features["pkts"]["value"]

        stddevSum = 0
        for duration in self.durations:
            stddevSum += (duration - self.packet_features["mean"]["value"]) ** 2
        self.packet_features["stddev"]["value"] = (stddevSum / self.packet_features["pkts"]["value"]) ** 0.5

        self.packet_features["rate"]["value"] = self.packet_features["pkts"]["value"] / self.packet_features["dur"]["value"] if self.packet_features["dur"]["value"] != 0 else 0
        self.packet_features["srate"]["value"] = self.packet_features["spkts"]["value"] / self.packet_features["dur"]["value"] if self.packet_features["dur"]["value"] != 0 else 0
        self.packet_features["drate"]["value"] = self.packet_features["dpkts"]["value"] / self.packet_features["dur"]["value"] if self.packet_features["dur"]["value"] != 0 else 0

if __name__ == "__main__":
    if len(sys.argv) not in [2, 3]:
        print("Usage: python main.py [--debug] <total_workers>")
        sys.exit(1)
    if sys.argv[1] == "--debug":
        DEBUG = True
        num_workers = int(sys.argv[2])
    else:
        num_workers = int(sys.argv[1])
    controller = Controller(num_workers)
    print("Searching for workers...")
    for _ in range(num_workers):
        controller.search()
    print("Workers found!\n")

    controller.loadFeatures()

    while True:
        terminal_menu = TerminalMenu(["Normal traffic", "Synflood attack", "Reload features", "Exit"], title="Select a test environment:")
        menu_entry_index = terminal_menu.show()
        match menu_entry_index:
            case 0:
                test_size_selection = TerminalMenu(["10s", "20s", "30s", "1m"], title="Select test size:")
                test_size_index = test_size_selection.show()
                test_size = [10, 20, 30, 60][test_size_index]
                verbose_selection = TerminalMenu(["Yes", "No"], title="Verbose output?")
                verbose_index = verbose_selection.show()
                controller.normalTraffic(duration=test_size, verbose=(not verbose_index))
            case 1:
                if num_workers < 3:
                    print("Not enough workers, 3 required for synflood attack")
                else:
                    test_size_selection = TerminalMenu(["1s", "5s", "10s", "30s"], title="Select test size:")
                    test_size_index = test_size_selection.show()
                    test_size = [1, 5, 10, 30][test_size_index]
                    verbose_selection = TerminalMenu(["Yes", "No"], title="Verbose output?")
                    verbose_index = verbose_selection.show()
                    controller.synfloodAttack(duration=test_size, verbose=(not verbose_index))
            case 2:
                controller.loadFeatures()
                options = []
                locked_index = []
                for key, feature in controller.packet_features.items():
                    options.append(f"{feature['name']} ({key})")
                    if feature["locked"]: locked_index.append(len(options) - 1)
                features_selection = TerminalMenu([feature["name"] for feature in controller.packet_features.values()], title="Select features to lock:", multi_select=True, multi_select_select_on_accept=False, preselected_entries=locked_index)
                features_index = features_selection.show()
                controller.lockFeatures(features_index)
            case 3:
                controller.close()
                sys.exit(0)
