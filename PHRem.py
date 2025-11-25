import psutil
import argparse

EXCLUDED_REMOTE_ADDRESS = "10.1.64.2:445"
def setup_logging():
    global log_file
    log_file = open('YarWatch_Data.txt', 'a')
def log_matches(data):
    global log_file
    log_file.write("* IPs Found *\n")
    log_file.write("--------------------------------\n")
    for conn in data:
        for key, value in conn.items():
            log_file.write(f"{key}: {value}\n")
        log_file.write("-" * 30 + "\n")
    log_file.write("\n")
def get_active_connections(pid=None):
    active_connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_ESTABLISHED:
            if conn.raddr.ip + ":" + str(conn.raddr.port) == EXCLUDED_REMOTE_ADDRESS:
                continue  # Skip connections with the excluded remote address

            if pid is None or conn.pid == pid:
                remote_address = f"{conn.raddr.ip}:{conn.raddr.port}"
                pid = conn.pid or "N/A"
                process_name = psutil.Process(pid).name() if pid != "N/A" else "N/A"

                connection_info = {
                    "Process Name": process_name,
                    "Remote Address": remote_address,
                }
                active_connections.append(connection_info)
                

    return active_connections

if __name__ == "__main__":
    setup_logging()
    parser = argparse.ArgumentParser(description="Get Process Name and Remote Address for a given PID.")
    parser.add_argument("--pid", type=int, help="Specify a PID to filter connections.")
    args = parser.parse_args()

    pid = args.pid
    active_connections = get_active_connections(pid)

    if not active_connections:
        if pid is not None:
            print(f"No active connections found for PID {pid}.")
        else:
            print("No active connections found.")
    else:
        for idx, conn in enumerate(active_connections, start=1):
            print(f"Connection {idx}:")
            for key, value in conn.items():
                print(f"{key}: {value}")
            print("-" * 30)
        log_matches(active_connections)
        