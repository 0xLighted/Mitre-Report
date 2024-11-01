from reporter import *

from json import loads
from os import getenv, path
from dotenv import load_dotenv
load_dotenv()

# Load configs
if not path.exists('reporter/config.json'): raise Exception('Config file doesnt exist.')
with open('reporter/config.json', 'r') as raw_conf:
    conf = loads(raw_conf.read())


def main():
    # Connect and get processed Wazuh alert data 
    client = Wazuh(conf)
    print('[-] Collecting data')
    json = client.get_json()
    print('[-] Recieved data')

    # Connect and generate rough report of the provided Wazuh data
    res = report(getenv('groq_key'))
    print('[-] Generating report')
    res.generate(json)
    print('[-] Report completed.')


if __name__ == '__main__':
    main()