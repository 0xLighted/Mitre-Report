from typer import Typer, Context, Argument
from typing_extensions import Annotated
from modules.wazuh import Wazuh
from modules.report import report
from os import path, getenv
from json import loads, dump
from dotenv import load_dotenv, set_key
load_dotenv()

__version__ = '0.1.1'
__description__ = 'Automatically creates the daily MITRE ATT&CK report for the last 24 hours or any specified duration based on a template used for MSU SOC purposes.'

logo = r"""
   __  ________________  ____  ___                    __         
  /  |/  /  _/_  __/ _ \/ __/ / _ \___ ___  ___  ____/ /____ ____
 / /|_/ // /  / / / , _/ _/  / , _/ -_) _ \/ _ \/ __/ __/ -_) __/
/_/  /_/___/ /_/ /_/|_/___/ /_/|_|\__/ .__/\___/_/  \__/\__/_/   
                                    /_/  v"""

print(logo + __version__ + '\n')

# Load configs
if not path.exists('reporter/config.json'): raise Exception('Config file doesnt exist.')
with open('reporter/config.json', 'r') as raw_conf:
    conf = loads(raw_conf.read())

app = Typer()


@app.command()
def check(min_level: Annotated[int, Argument(help="The minimum rule level to check for alerts.")],
          duration: Annotated[int, Argument(help="The duration in hours to check from till current time (default: 24 hours).")] = 24):
    """Display all data available from a range. Mainly used to check data validity before producing report."""
    conf['filters'][0]['range']['rule.level']['gte'] = min_level

    client = Wazuh(conf)
    print('[-] Collecting data')
    data = client.get_data(duration)
    print(f'[-] Recieved {len(data)} alerts.')

    print(data)


@app.command()
def generate(min_level: Annotated[int, Argument(help="The minimum rule level to check for alerts.")],
             duration: Annotated[int, Argument(help="The duration in hours to check from (default: 24 hours) till now.", show_default=True)] = 24):
    """Generate and open the report"""
    conf['filters'][0]['range']['rule.level']['gte'] = min_level

    client = Wazuh(conf)
    print('[-] Collecting data.')
    json = client.get_json(duration)
    print(f'[-] Recieved {len(json.keys())} alerts.')

    if json == {}:
        print("No data to generate report on.")
        return
    
    # Generate the report with not empty data
    res = report(getenv('groq_key'))
    print('[-] Generating report')
    res.generate(json)
    print('[-] Report completed.')


@app.command()
def set_env(username: Annotated[str, Argument(help="Wazuh username to access data")],
        password: Annotated[str, Argument(help="Wazuh password to access data")],
        groq_key: Annotated[str, Argument(help="Groq API key for report generation")]):
    """Sets environment variables for login details and API key"""
    set_key('.env', '_username', username)
    set_key('.env', '_password', password)
    set_key('.env', '_groq_key', groq_key)

    print("Successfully set environment variables")


@app.command()
def set_agents(agents: Annotated[list[str], Argument(help="List of agents to filter by")]):
    """Sets environment variables for login details and API key"""
    
    conf['filters'][1]['bool']['should'] = [{ "match_phrase": { "agent.id": i } } for i in agents]

    if not path.exists('reporter/config.json'): raise Exception('Config file doesnt exist.')
    with open('reporter/config.json', 'w') as raw_conf:
        dump(conf, raw_conf)


@app.callback(invoke_without_command=True)
def main(ctx: Context):
    if not ctx.invoked_subcommand:
        print(__description__ + '\n')
        print('Missing command. Use --help for a list of commands and options.')
        print('Usage: python reporter [command] [reporter]')


if __name__ == '__main__':
    app()
    