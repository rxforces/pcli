#!/usr/bin/python
import threading
from Queue import Queue
import os,sys
import traceback
import json
import logging
import signal
import time
import random
import string
import paramiko
import argparse
import getpass


# Define variables
num_of_parallel_jobs = 0
max_timeout = 0
opt_username = ""
opt_password = ""
opt_hosts = ""
opt_commands = ""
opt_case_id = ""

logger = logging.getLogger("collector")

# Create the queue and the threader
cisco_queue = Queue()

def setup_logging():
    """
    Setup logging for the current module and dependent libraries based on
    values available in config.
    """
    # set a format which is simpler for console use
    formatter = logging.Formatter('%(asctime)s: %(name)-12s[%(process)d|%(threadName)-10s]: %(levelname)-8s %(message)s')
    logger.setLevel(logging.DEBUG)

    # Create a console handler
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    console.setFormatter(formatter)
    # add the handler to the root logger
    logger.addHandler(console)

def send_string_and_wait_for_string(shell, command, wait_string):
    # Send the su command
    shell.send(command)

    # Create a new receive buffer
    receive_buffer = ""

    while not wait_string in receive_buffer:
        # Flush the receive buffer
        receive_buffer += shell.recv(1024)

    return receive_buffer

def cisco_commands(cisco_devices):

    device = json.loads(cisco_devices)
    hostname = device["hostname"]
    username = device["username"]
    password = device["password"]
    commands = device["commands"]
    timeout = device["timeout"]
    output = device["output"]

    logger.info("Starting ssh to %s." % hostname)
    try:
        remoteConnectionSetup = paramiko.SSHClient()
        remoteConnectionSetup.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        remoteConnectionSetup.connect(hostname, username=username, password=password, allow_agent=False,
                                      look_for_keys=False, timeout=timeout)
        logger.info("SSH connection established to %s" % hostname)
        remoteConnection = remoteConnectionSetup.invoke_shell()

    except:
        logger.error("Failed to connect to %s@%s." % (username, hostname))
        return

    try:
        # Wait for the prompt
        servername = send_string_and_wait_for_string(remoteConnection, "", "#")
        servername = servername.strip('\n').strip('\r').strip(' ').strip('\t')
        servername = servername.split('#')[0]
        list = servername.split(":")
        if len(list) > 1:
            servername = list[-1]

        logger.info("Found actual hostname: %s" % (servername))

        filename = os.path.join(output, "%s_%s.log" % (hostname, servername))

        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))

        f = open(filename, 'a')

        # Disable more
        f.write(send_string_and_wait_for_string(remoteConnection, "terminal length 0\n", "#"))

        for command in commands:
            if command.startswith(','):
                second = int(command[1:])
                logger.info("Sleep %s seconds" % second)
                time.sleep(second)
            else:
                logger.info("Run command '%s' on to %s." % (command, hostname))
                command = command.strip() + "\n"
                f.write(send_string_and_wait_for_string(remoteConnection, command, "#"))

        remoteConnection.close()

    except:
        if f:
            f.close()
        logger.error("Failed run commands on to %s@%s." % (username, hostname))
        return

    f.close()
    logger.info("Successfully run commands on to %s@%s." % (username, hostname))
    return


# Function to take the member in the queue.
def threader():
    while True:
        # Get a device from the cisco_queue
        cisco_devices = cisco_queue.get()
        # Run the job
        cisco_commands(cisco_devices)
        # completed with the job
        cisco_queue.task_done()


# Function handle the key board interrupt
def keyboardHandler(signal, frame):
    logger.info('[Critical]: Pressed ctrl c, exit')
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, keyboardHandler)

    timestr = time.strftime("%Y%m%d-%H%M%S")

    # Record start time of the first job
    start_time = time.time()

    # Run jobs in parallel
    logger.debug("Starting %s work threads." % num_of_parallel_jobs)
    for x in range(num_of_parallel_jobs):
        t = threading.Thread(target=threader)

        # classifying as a daemon, so threads will terminate when the main program terminates
        t.daemon = True

        # start
        t.start()

    try:
        #read commands file
        with open(opt_commands, "r") as file:
            commands = [line.rstrip('\n').strip(' ') for line in file]
            commands = [c for c in commands if not c.startswith('#') and not c == '']

        # Read host file
        with open(opt_hosts, 'r') as hostfile:
            hosts = [line.rstrip('\n').strip(' ') for line in hostfile]
            hosts = [h for h in hosts if not h.startswith('#') and not h == '']

            for host in hosts:
                    device = {}
                    device["hostname"] = host
                    device["username"] = opt_username
                    device["password"] = opt_password
                    device["commands"] = commands
                    device["timeout"] = max_timeout
                    device["output"] = "output_%s_%s" % (opt_case_id, timestr)
                    pass_args = json.dumps(device)
                    cisco_queue.put(pass_args)

                    device["password"] = "********"
                    pass_args = json.dumps(device)
                    logger.debug("Queuing task: %s" % pass_args)
    except:
        traceback.print_exc(file=sys.stdout)

    """
    Instead of connecting to a database to populate the list of devices you can also have a list of devices in a txt
    file and load it into the queue using a for or while loop if that is easier.
    """

    # Wait till all threads to be completed before exiting
    cisco_queue.join()
    logger.info('Entire job timespan:%s' % (time.time() - start_time))


def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

if __name__ == "__main__":
    setup_logging()

    curr_user = getpass.getuser()
    id = id_generator()

    parser = argparse.ArgumentParser(description='SSH Client.')
    parser.add_argument('-u', '--user', help='username')
    parser.add_argument('-p', '--pwd', help='password')
    parser.add_argument('-i', '--id', help='unique identifier')
    parser.add_argument('-s', '--hosts', help='hosts file')
    parser.add_argument('-c', '--commands', help='commands file')
    parser.add_argument('-d', '--default', help='use default value', action='store_true')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.user:
        opt_username = args.user
    else:
        opt_username = raw_input("Default Username[%s]:" % curr_user) or curr_user

    if args.pwd:
        opt_password = args.pwd
    else:
        opt_password = getpass.getpass("Default Password for " + opt_username + ":")

    if args.id:
        opt_case_id = args.id
    else:
        opt_case_id = raw_input("Please enter case num or use random num[%s]:" % id) or id

    if args.hosts:
        opt_hosts = args.hosts
    else:
        opt_hosts = raw_input("Hosts file[hosts.txt]:") or "hosts.txt"

    if args.commands:
        opt_commands = args.commands
    else:
        opt_commands = raw_input("Commands file[commands.txt]:") or "commands.txt"

    if args.default:
        num_of_parallel_jobs = 10
        max_timeout = 30
    else:
        num_of_parallel_jobs = int(raw_input("Number of Threads[10]:") or "10")
        max_timeout = int(raw_input("Timeout for commands[30]:") or "30")

    main()

