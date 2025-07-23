import uuid
import urllib
import requests
import json
import time
import splunklib.client as client


from urllib3 import disable_warnings
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend


class DetectionTestingManager:

    def __init__(self, host, username, password):
        self.conn = client.connect(
            host=host,
            port=8089,
            username=username,
            password=password,
        )

    def sigma_to_splunk_conversion(self, sigma_detection: dict, index: str = None):
        sigma_collection = SigmaCollection.from_dicts([sigma_detection])
        splunk_backend = SplunkBackend()
        splunk_search = splunk_backend.convert(sigma_collection)[0]
        
        # Add index filter for false positive testing
        if index:
            # Handle different search formats
            search_trimmed = splunk_search.strip()
            if search_trimmed.startswith("|"):
                # For pipe commands, add a base search before the pipe
                splunk_search = f"index={index} | {search_trimmed[1:].strip()}"
            elif search_trimmed.startswith("search "):
                # Replace "search " with "search index=<index> "
                splunk_search = f"search index={index} {search_trimmed[7:].strip()}"
            else:
                # Add index filter to the beginning
                splunk_search = f"index={index} {search_trimmed}"
        
        return splunk_search

    def run_false_positive_test(self, sigma_detection: dict):
        """
        Run false positive testing using index=test1 which contains non-malicious data.
        Returns True if no false positives (0 events), False if false positives detected.
        """
        # Convert sigma to splunk search with test1 index
        splunk_search = self.sigma_to_splunk_conversion(sigma_detection, index="test1")
        
        # Run the detection - we expect 0 results (no false positives)
        result = self.run_detection(splunk_search)
        
        # For false positive testing, we want NO results (result should be False)
        # Return True if no false positives detected, False if false positives found
        return not result

    def configure_hec(self):
        self.hec_channel = str(uuid.uuid4())
        try:
            res = self.conn.input(
                path="/servicesNS/nobody/splunk_httpinput/data/inputs/http/"
                     "http:%2F%2FDETECTION_TESTING_HEC"
            )
            self.hec_token = str(res.token)
            return
        except Exception:
            pass

        try:
            res = self.conn.inputs.create(
                name="DETECTION_TESTING_HEC",
                kind="http",
                index="test",
                indexes="test",
                useACK=True,
            )
            self.hec_token = str(res.token)
            return

        except Exception:
            pass

    def send_attack_data(
        self,
        file_path: str,
        source: str,
        sourcetype: str,
        host: str,
        verify_ssl: bool = False,
    ):
        if verify_ssl is False:
            disable_warnings()

        headers = {
            "Authorization": f"Splunk {self.hec_token}",  
            "X-Splunk-Request-Channel": self.hec_channel,
        }

        url_params = {
            "index": "test",
            "source": source,
            "sourcetype": sourcetype,
            "host": "test",
        }

        url = urllib.parse.urljoin(
            f"https://{host}:8088",
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
                jsonResponse = json.loads(res.text)

            except Exception as e:
                raise (
                    Exception(
                        f"There was an exception sending attack_data to HEC: {str(e)}"
                    )
                )

        if "ackId" not in jsonResponse:
            raise (
                Exception(
                    f"key 'ackID' not present in response from HEC server: "
                    f"{jsonResponse}"
                )
            )

        ackId = jsonResponse["ackId"]
        url_with_hec_ack_path = urllib.parse.urljoin(
            f"https://{host}:8088", "services/collector/ack"
        )

        requested_acks = {"acks": [jsonResponse["ackId"]]}
        attempt_count = 0
        max_attempts = 10
        
        while attempt_count < max_attempts:
            try:
                res = requests.post(
                    url_with_hec_ack_path,
                    json=requested_acks,
                    allow_redirects=True,
                    headers=headers,
                    verify=verify_ssl,
                )

                jsonResponse = json.loads(res.text)

                if "acks" in jsonResponse and str(ackId) in jsonResponse["acks"]:
                    if jsonResponse["acks"][str(ackId)] is True:
                        # ackID has been found for our request, 
                        # we can return as the data has been replayed
                        return
                    else:
                        # ackID is not yet true, we will wait some more
                        attempt_count += 1
                        if attempt_count < max_attempts:
                            time.sleep(2)

                else:
                    raise (
                        Exception(
                            f"Proper ackID structure not found for ackID {ackId} "
                            f"in {jsonResponse}"
                        )
                    )
            except Exception as e:
                raise (Exception(f"There was an exception in the post: {str(e)}"))
        
        raise Exception(
            f"Failed to receive HEC acknowledgment after {max_attempts} attempts"
        )
    
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
    