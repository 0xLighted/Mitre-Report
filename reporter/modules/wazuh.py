import pandas as pd
from requests import post
from os import getenv
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
load_dotenv()

HEADERS = {'osd-xsrf': 'osd-fetch'}

class Wazuh():
    def __init__(self, conf: dict):
        self.conf = conf

        self.now = datetime.now(timezone.utc)
        self.yesterday = self.now - timedelta(days=1)
        self.range = [
            self.now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3],
            self.yesterday.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
        ]
        
        self.auth_token = self.__login()
        self.payload = self.__load_payload()

    def __login(self):
        """Login to Wazuh with login details in config file"""
        _usr, _pwd = getenv('usr'), getenv('pwd')
        with post("https://soc.msu.edu.my/auth/login", headers=HEADERS, data={"username": _usr, "password": _pwd}) as raw_auth:
            if raw_auth.cookies: return dict(raw_auth.cookies)

        raise Exception("Invalid login details.")

    def __load_payload(self):
        payload = self.conf.get('payload')
        for i in self.conf.get('filters'):
            payload['params']['body']['query']['bool']['filter'].append(i)

        timeframe = { "range": { "timestamp": {
            "gte": self.range[1] + 'Z', # previous
            "lte": self.range[0] + 'Z', # current
            "format": "strict_date_optional_time"
        }}}
        payload['params']['body']['query']['bool']['filter'].append(timeframe)

        return payload


    def __clean_data(self, raw_data: dict):
        """Filters and organizes the raw data into a DataFrame for further processing"""
        hits = raw_data['rawResponse']['hits']['hits']
        headers = ['rule_id', 'agent_ip', 'agent_name', 'agent_id', 'url_affected', 'source_ip', 'full_log', 'syscheck_path', 'geo_country', 'geo_lon', 'geo_lat']
        data = []

        for h in hits:
            d = h['_source']
            row = [
                d['rule'].get('id', None),
                d['agent'].get('ip', None),
                d['agent'].get('name', None),
                d['agent'].get('id', None),

                d.get('data', {}).get('url', None),
                d.get('data', {}).get('srcip', None),

                d.get('full_log', ''),       
                d.get('syscheck', {}).get('path', None),

                d.get('GeoLocation', {}).get('country_name', None),
                d.get('GeoLocation', {}).get('location', {}).get('lon', None),
                d.get('GeoLocation', {}).get('location', {}).get('lat', None)
            ]

            data.append(row)
        
        df = pd.DataFrame(data, columns=headers)
        return df


    def get_data(self) -> pd.DataFrame:
        """Returns Wazuh data as a Pandas DataFrame for further processing.\n
        output: str | File to read if load_new_data is false, File to write to if load_new_data is true. Dont include extention or directory"""

        with post("https://soc.msu.edu.my/internal/search/opensearch", cookies=self.auth_token, headers=HEADERS, json=self.payload) as raw_data:
            data = raw_data.json()

        return self.__clean_data(data)


    def get_json(self) -> list:
        """Returns a list of hits for each unique event. Probably only for AI processing. \n
        output: str | File to read if load_new_data is false, File to write to if load_new_data is true. Dont include extention or directory"""

        with post("https://soc.msu.edu.my/internal/search/opensearch", cookies=self.auth_token, headers=HEADERS, json=self.payload) as raw_data:
            data = raw_data.json()

        hits = data['rawResponse']['hits']['hits']
        filtered = self.__clean_data(data)

        # Get first index of all unique rules 
        indexes = {value: filtered[filtered['rule_id'] == value].first_valid_index() for value in filtered['rule_id'].unique()}
        data = {k: hits[indexes[k]]['_source'] for k in indexes} # Get the hit data of corresponding unique index
        
        # Group relevant data by the rule into an array 
        grouped_data = filtered.groupby('rule_id').agg({
            'agent_ip': lambda x: list(x.unique()),
            'agent_name': lambda x: list(x.unique()),
            'agent_id': lambda x: list(x.unique()),
            'url_affected': lambda x: list(x.unique()),
            'source_ip': lambda x: list(x.unique()),
            'full_log': lambda x: {agent: log for agent, log in zip(filtered.loc[x.index, 'agent_name'], x)},
            'syscheck_path': lambda x: {agent: path for agent, path in zip(filtered.loc[x.index, 'agent_name'], x)},
            'geo_country': lambda x: list(x.unique()),
            'geo_lon': lambda x: list(x.unique()),
            'geo_lat': lambda x: list(x.unique())  
        })

        # Replace the relevant data entries with grouped data
        #['agent_ip', 'agent_name', 'agent_id', 'url_affected', 'source_ip', 'full_log', 'syscheck_path', 'geo_country', 'geo_lon', 'geo_lat']
        for h in data.keys():
            data[h]['agent']['ip'] = grouped_data.loc[h]['agent_ip']
            data[h]['agent']['name'] = grouped_data.loc[h]['agent_name']
            data[h]['agent']['id'] = grouped_data.loc[h]['agent_id']

            if data[h].get('data', None):
                data[h]['data']['url'] = grouped_data.loc[h]['url_affected']
                data[h]['data']['srcip'] = grouped_data.loc[h]['source_ip']

            data[h]['full_log'] = grouped_data.loc[h]['full_log']
            
            if data[h].get('syscheck', None):
                data[h]['syscheck']['path'] = grouped_data.loc[h]['syscheck_path']

            if data.get('GeoLocation', None):
                data[h]['GeoLocation']['country_name'] = grouped_data.loc[h]['geo_country']
                data[h]['GeoLocation']['location']['lon'] = grouped_data.loc[h]['geo_lon']
                data[h]['GeoLocation']['location']['lat'] = grouped_data.loc[h]['geo_lat']

            # Delete unecessary data
            del data[h]['predecoder']
            del data[h]['input']
            del data[h]['manager']
            del data[h]['id']
            del data[h]['timestamp']
            del data[h]['rule']['mitre']
            del data[h]['rule']['firedtimes']

        return data


if __name__ == "__main__":
    raise Exception("Attempted to run module file. Run main.py in parent directory.")
    # print(get_json(False, 'output-2024-10-22'))