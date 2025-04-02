from threading import Thread
from subprocess import Popen, PIPE, DEVNULL
import socket
import time
import sys
import re
import os

DEBUG = False

running_process = None

def log(log_message):
    print(f"[{time.strftime("%H:%M:%S", time.localtime())}] {log_message}")

class Worker:
    def __init__(self, controller_address):
        self.thread = None
        self.monitor_process_terminate = False
        self.controller = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.searchController(controller_address)

    def searchController(self, controller_address):
        log("Searching for controller...")
        while True:
            try:
                log(f"Trying to connect to {controller_address}...")
                self.controller.connect((controller_address, 1234))
                break
            except:
                time.sleep(1)
        log("Controller found")
    
    def read(self):
        return self.controller.recv(1024).decode()
    
    def start(self, command):
        if self.thread:
            self.thread.join()
        # if DEBUG:
        #     self.monitor_thread = Thread(target=self.startMonitor)
        #     self.monitor_thread.start()
        match command[0]:
            case "synflood":
                self.thread = Thread(target=self.startSynflood, kwargs={"args": command[1:]})
            case "iperf-server":
                self.thread = Thread(target=self.startIperfServer, kwargs={"args": command[1:]})
            case "iperf-client":
                self.thread = Thread(target=self.startIperfClient, kwargs={"args": command[1:]})
            case _:
                log("Invalid command")
                return
        self.thread.start()
    
    def terminateProcess(self):
        global running_process
            
        if running_process is not None:
            # if DEBUG:
            #     self.monitor_process_terminate = True
            #     self.monitor_thread.join()
            if running_process.poll() is None:
                running_process.terminate()
                log("Process terminated")

    def startIperfServer(self, args):
        global running_process
        command = ["iperf3", "-s", *args]
        log(f"Starting iperf server with command: {' '.join(command)}")
        running_process = Popen(command, stdout=PIPE, stderr=PIPE)
        running_process.wait()
    
    def startIperfClient(self, args):
        global running_process
        success = False
        command = ["iperf3", "-c", *args]
        log(f"Starting iperf client with command: {' '.join(command)}")
        while not success:
            running_process = Popen(command, stdout=PIPE)
            output, _ = running_process.communicate()
            running_process.wait()
            if running_process.returncode != 0:
                log("Iperf client failed to connect, retrying...")
                time.sleep(1)
            else:
                success = True
        self.controller.send(output)
        log("Process completed")

    def startSynflood(self, args):
        global running_process
        command = ["netwox", "76", "-i", *args]
        log(f"Starting synflood attack with command: {' '.join(command)}")
        running_process = Popen(command, stdout=DEVNULL, stderr=DEVNULL)
        running_process.wait()

    def startMonitor(self):
        awk_command = f'gsub(/%/,"",$2); gsub(/MiB/,"",$3); print strftime("%Y-%m-%d %H:%M:%S"),$2 >> "cpu_stats.txt"; print strftime("%Y-%m-%d %H:%M:%S"),$3 >> "memory_stats.txt"'
        monitor_command = 'docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" | grep network_test_node | awk \''+ awk_command +'\';'
        while not self.monitor_process_terminate:
            monitor_process = Popen(monitor_command, shell=True)
            monitor_process.wait()
            time.sleep(0.5)
        os.mv("cpu_stats.txt", "/home/cpu_stats.txt")
        os.mv("memory_stats.txt", "/home/memory_stats.txt")
        self.monitor_process_terminate = False

    def close(self):
        log("Controller disconnected")
        self.controller.close()
        if self.thread:
            self.thread.join()
        sys.exit(0)
        
if __name__ == "__main__":
    if len(sys.argv) not in [1, 2]:
        if sys.argv[1] == "--debug":
            DEBUG = True
            controller_ip = sys.argv[2]
        else:
            controller_ip = sys.argv[1]
        if re.match(r"(^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$)|localhost", controller_ip) is None:
            log("Invalid IP address")
            sys.exit(1)
        worker = Worker(controller_ip)
    else:
        log("Usage: python main.py [--debug] <controller_address>")
        sys.exit(1)

    while True:
        command = worker.read()
        match command.split()[0]:
            case "\\start":
                worker.start(command.split()[1:])
            case "\\stop":
                worker.close()
            case "\\terminate_process":
                worker.terminateProcess()
            case _:
                log(f"Controller sent: {command}")