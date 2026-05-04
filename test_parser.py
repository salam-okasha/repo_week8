from log_parser import LogParser

def run_test():
    parser = LogParser()
    raw = "May 4 11:35:01 server1 sshd[1234]: Failed password for root from 192.168.1.50 port 22"
    result = parser.parse_auto(raw)
    
    print("Parsed Data:")
    print(result)

if __name__ == "__main__":
    run_test()