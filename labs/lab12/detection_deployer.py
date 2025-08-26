import splunklib.client as client
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend


class DetectionDeployer:
    
    def __init__(self, host, username, password, lab_host="lab1"):
        """
        Initialize the DetectionDeployer.
        
        Args:
            host: Splunk server host
            username: Splunk username
            password: Splunk password
            lab_host: Lab host identifier (e.g., "lab1", "lab2", etc.)
        """
        self.conn = client.connect(
            host=host,
            port=8089,
            username=username,
            password=password,
        )
        self.lab_host = lab_host

    def sigma_to_splunk_conversion(self, sigma_detection: dict):
        """
        Convert a Sigma detection to Splunk search query.
        
        Args:
            sigma_detection: Dictionary containing Sigma detection rule
            
        Returns:
            str: Splunk search query
        """
        sigma_collection = SigmaCollection.from_dicts([sigma_detection])
        splunk_backend = SplunkBackend()
        splunk_search = splunk_backend.convert(sigma_collection)[0]
        return splunk_search

    def deploy_splunk_detection(self, sigma_detection: dict, detection_name: str):
        """
        Deploy a Sigma detection to Splunk as a saved search.
        
        Args:
            sigma_detection: Dictionary containing Sigma detection rule
            detection_name: Name for the saved search in Splunk
            
        Returns:
            bool: True if deployment successful, False otherwise
        """
        try:
            # Convert Sigma to Splunk search
            splunk_search = self.sigma_to_splunk_conversion(sigma_detection)
            
            # Prepend index and host filters
            modified_search = f"index=win host={self.lab_host} {splunk_search}"
            
            # Deploy as saved search
            saved_searches = self.conn.saved_searches
            
            # Check if saved search already exists and delete it
            try:
                existing_search = saved_searches[detection_name]
                existing_search.delete()
            except KeyError:
                # Saved search doesn't exist, which is fine
                pass
            
            # Create new saved search
            saved_searches.create(
                name=detection_name,
                search=modified_search,
                **{
                    'is_scheduled': True,
                    'cron_schedule': '*/5 * * * *',  # Run every 5 minutes
                    'dispatch.earliest_time': '-5m',
                    'dispatch.latest_time': 'now',
                    'request.ui_dispatch_app': 'search',
                    'request.ui_dispatch_view': 'search',
                    'alert_type': 'number of events',
                    'alert_comparator': 'greater than',
                    'alert_threshold': '0',
                    'alert.track': '1',  # Add to triggered alerts
                }
            )
            
            return True
            
        except Exception as e:
            print(f"Error deploying detection {detection_name}: {str(e)}")
            return False

    def list_deployed_detections(self):
        """
        List all deployed detections (saved searches).
        
        Returns:
            list: List of saved search names
        """
        try:
            saved_searches = self.conn.saved_searches
            return [search.name for search in saved_searches]
        except Exception as e:
            print(f"Error listing deployed detections: {str(e)}")
            return []

    def remove_detection(self, detection_name: str):
        """
        Remove a deployed detection from Splunk.
        
        Args:
            detection_name: Name of the saved search to remove
            
        Returns:
            bool: True if removal successful, False otherwise
        """
        try:
            saved_searches = self.conn.saved_searches
            search = saved_searches[detection_name]
            search.delete()
            return True
        except KeyError:
            print(f"Detection {detection_name} not found")
            return False
        except Exception as e:
            print(f"Error removing detection {detection_name}: {str(e)}")
            return False
