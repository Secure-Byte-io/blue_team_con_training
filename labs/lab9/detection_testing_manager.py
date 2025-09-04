import urllib
import requests
import json
import time
import splunklib.client as client


from urllib3 import disable_warnings
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend


class DetectionTestingManager:

    def __init__(self, host, username, password, hec_token):
        self.conn = client.connect(
            host=host,
            port=8089,
            username=username,
            password=password,
        )
        self.hec_token = hec_token

    def sigma_to_splunk_conversion(self, sigma_detection: dict):
        sigma_collection = SigmaCollection.from_dicts([sigma_detection])
        splunk_backend = SplunkBackend()
        splunk_search = splunk_backend.convert(sigma_collection)[0]
        return splunk_search

    def send_attack_data(
        self,
        file_path: str,
        source: str,
        sourcetype: str,
        splunk_host: str,
        event_host: str = "test",
        verify_ssl: bool = False,
    ):
        if verify_ssl is False:
            disable_warnings()

        headers = {
            "Authorization": f"Splunk {self.hec_token}",
        }

        url_params = {
            "index": "test",
            "source": source,
            "sourcetype": sourcetype,
            "host": event_host,
        }

        url = urllib.parse.urljoin(
            f"https://{splunk_host}:8088",
            "services/collector/raw"
        )

        with open(file_path, "rb") as datafile:
            try:
                res = requests.post(
                    url,
                    params=url_params,
                    data=datafile.read(),
                    allow_redirects=True,
                    headers=headers,
                    verify=verify_ssl,
                )
                
                # Check if request was successful
                res.raise_for_status()
                
                # For basic HEC without acknowledgments, success response is typically {"text":"Success","code":0}
                return

            except Exception as e:
                raise Exception(f"There was an exception sending attack_data to HEC: {str(e)}")
    
    def delete_attack_data(self):
        index = "test"
        splunk_search = f'search index={index} | delete'
        kwargs = {"exec_mode": "blocking"}
        try:
            job = self.conn.jobs.create(splunk_search, **kwargs)
            job.results(output_mode="json")

        except Exception as e:
            raise (
                Exception(
                    f"Trouble deleting data using the search {splunk_search}: {str(e)}"
                )
            )
        
    def run_detection(self, search: str):
        # Ensure searches that do not begin with '|' must begin with 'search '
        if not search.strip().startswith("|"):
            if not search.strip().startswith("search "):
                search = f"search {search}"

        kwargs = {"exec_mode": "blocking"}
        job = self.conn.search(query=search, **kwargs)
        
        if int(job.content.get("resultCount", "0")) > 0:
            return True
        return False
    