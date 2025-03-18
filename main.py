"""
Search API Client
-----------------------
A modular client for interacting with the YOUR_COMPANY_NAME Search API.
"""

import requests
import json
import time
import jwt
import math
import datetime
import re
import urllib.parse
import os
import csv
import logging
import argparse
import configparser
from typing import Dict, List, Tuple, Optional, Any


class AuthenticationManager:
    """Handles authentication with your Search API."""
    
    def __init__(self, client_id: str, client_secret: str, hostname: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.hostname = hostname
        self.access_token = None
        self.token_expiry = 0
        self.logger = logging.getLogger(__name__)
    
    def _generate_jwt_token(self) -> str:
        """Generate a JWT token for authentication."""
        header = {
            'typ': 'JWT',
            'alg': 'HS256'
        }
        
        current_timestamp = math.floor(datetime.datetime.now().timestamp())
        
        payload = {
            'iss': self.client_id,
            'sub': self.client_id,
            'aud': f'https://{self.hostname}/oauth/token',
            'exp': current_timestamp + 120  # expiry time is 120 seconds from creation
        }
        
        token = jwt.encode(payload, self.client_secret, algorithm='HS256', headers=header)
        
        if isinstance(token, bytes):
            token = token.decode('utf-8')
            
        return token
    
    def get_access_token(self) -> str:
        """Get an access token or return the existing one if still valid."""
        current_time = math.floor(datetime.datetime.now().timestamp())
        
        if not self.access_token or current_time >= self.token_expiry:
            self.logger.info("Getting new access token...")
            self._refresh_token()
            
        return self.access_token
    
    def _refresh_token(self) -> None:
        """Refresh the access token."""
        client_assertion = self._generate_jwt_token()
        
        url = f'https://{self.hostname}/oauth/token'
        headers = {'Content-Type': 'application/json'}
        payload = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials',
            'client_assertion_type': 'urn:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': client_assertion
        }
        
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code == 200:
            response_data = response.json()
            self.access_token = response_data.get('access_token')
            self.token_expiry = math.floor(datetime.datetime.now().timestamp()) + 120
        else:
            self.logger.error(f"Failed to get access token: {response.status_code} - {response.text}")
            raise Exception(f"Failed to get access token: {response.status_code} - {response.text}")


class ResponseProcessor:
    """Processes API responses and extracts relevant information."""
    
    @staticmethod
    def extract_solr_url(response_json: Dict) -> Optional[str]:
        """Extract the SOLR query URL from the forensics logs."""
        if 'forensics' in response_json and isinstance(response_json['forensics'], list):
            forensics_logs = response_json['forensics']
            
            for log_entry in forensics_logs:
                if 'SOLRQUERY ::' in log_entry:
                    solr_url = log_entry.split('SOLRQUERY :: ')[1].strip()
                    return solr_url
        return None
    
    @staticmethod
    def extract_fq_parameters(url: Optional[str]) -> List[str]:
        """Extract all fq parameters from a given URL and URL decode them."""
        if not url:
            return []
        
        fq_params = re.findall(r'fq=([^&]+)', url)
        decoded_params = [urllib.parse.unquote(param) for param in fq_params]
        
        return decoded_params
    
    def process_response(self, response_json: Dict, state: str) -> Dict:
        """Process the response and extract fq parameters for a given state."""
        solr_url = self.extract_solr_url(response_json)
        fq_params = self.extract_fq_parameters(solr_url)
        
        return {
            'state': state,
            'fq_parameters': fq_params
        }


class DataWriter:
    """Handles data output operations."""
    
    @staticmethod
    def write_to_csv(result: Dict, output_file: str = 'fq_parameters.csv') -> None:
        """Append results to a CSV file, creating the file with headers if it doesn't exist."""
        file_exists = os.path.isfile(output_file)
        
        with open(output_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            if not file_exists:
                writer.writerow(['State', 'Filter Generated'])
            
            state = result['state']
            fq_params = result['fq_parameters']
            
            fq_string = ' '.join([f"fq={param}" for param in fq_params])
            
            writer.writerow([state, fq_string])
    
    @staticmethod
    def save_json_results(results: List[Dict], output_file: str = 'state_results.json') -> None:
        """Save results to a JSON file."""
        with open(output_file, 'w') as outfile:
            json.dump(results, outfile, indent=4)


class SearchAPI:
    """Main class for interacting with the Search API."""
    
    def __init__(
        self, 
        client_id: str, 
        client_secret: str, 
        hostname: str, 
        endpoint_url: str,
        output_csv: str = 'fq_parameters.csv',
        output_json: str = 'state_results.json'
    ):
        self.endpoint_url = endpoint_url
        self.output_csv = output_csv
        self.output_json = output_json
        self.auth_manager = AuthenticationManager(client_id, client_secret, hostname)
        self.response_processor = ResponseProcessor()
        self.data_writer = DataWriter()
        self.logger = logging.getLogger(__name__)
    
    def _load_payload_template(self, template_file: str) -> Dict:
        """Load the payload template from a JSON file."""
        with open(template_file, 'r') as file:
            return json.load(file)
    
    def _update_payload_state(self, payload: Dict, state: str) -> Dict:
        """Update the state in the payload template."""
        payload_copy = json.loads(json.dumps(payload))
        
        for filter_item in payload_copy.get("filters", []):
            if isinstance(filter_item, dict) and "value" in filter_item:
                if "location" in filter_item["value"]:
                    filter_item["value"]["location"]["text"] = state
        
        return payload_copy
    
    def _make_api_request(self, payload: Dict) -> Dict:
        """Make an API request with the given payload."""
        access_token = self.auth_manager.get_access_token()
        
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json;version=4.0',
            'Authorization': f'Bearer {access_token}'
        }
        
        response = requests.post(self.endpoint_url, headers=headers, json=payload)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            # Token expired, refresh and retry once
            self.logger.warning("Token expired. Getting a new one and retrying...")
            self.auth_manager._refresh_token()
            
            # Update headers with new token
            headers['Authorization'] = f'Bearer {self.auth_manager.access_token}'
            
            # Retry request
            retry_response = requests.post(self.endpoint_url, headers=headers, json=payload)
            
            if retry_response.status_code == 200:
                return retry_response.json()
            else:
                self.logger.error(f"API request failed on retry: {retry_response.status_code} - {retry_response.text}")
                raise Exception(f"API request failed: {retry_response.status_code} - {retry_response.text}")
        else:
            self.logger.error(f"API request failed: {response.status_code} - {response.text}")
            raise Exception(f"API request failed: {response.status_code} - {response.text}")
    
    def process_states(self, states_file: str, payload_file: str, delay: int = 1) -> List[Dict]:
        """Process states from a file and make API requests."""
        # Read states from file
        with open(states_file, 'r') as file:
            states = [line.strip() for line in file if line.strip()]
        
        # Load payload template
        payload_template = self._load_payload_template(payload_file)
        
        results = []
        
        # Process each state
        for state in states:
            self.logger.info(f"Processing state: {state}")
            
            try:
                # Update payload with current state
                payload = self._update_payload_state(payload_template, state)
                
                # Make API request
                response_json = self._make_api_request(payload)
                
                # Process response
                result = self.response_processor.process_response(response_json, state)
                
                # Write result to CSV
                self.data_writer.write_to_csv(result, self.output_csv)
                
                # Add to results list
                results.append(result)
                
                self.logger.info(f"Successfully processed state: {state}")
                
            except Exception as e:
                self.logger.error(f"Exception occurred for state {state}: {str(e)}")
                
            # Add a delay to avoid overwhelming the API
            time.sleep(delay)
        
        # Save all results to JSON
        self.data_writer.save_json_results(results, self.output_json)
        
        return results


def setup_logging(log_file: str = 'search_api.log', level: int = logging.INFO) -> None:
    """Set up logging configuration."""
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )


def load_config(config_file: str = 'config.ini') -> Dict:
    """Load configuration from INI file."""
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Configuration file not found: {config_file}")
    
    config = configparser.ConfigParser()
    config.read(config_file)
    
    # Ensure API section exists
    if 'api' not in config:
        raise ValueError("Configuration file missing [api] section")
    
    api_config = config['api']
    
    # Check for required fields
    required_fields = ['client_id', 'client_secret', 'hostname', 'endpoint_url']
    missing = [field for field in required_fields if field not in api_config]
    
    if missing:
        raise ValueError(f"Missing required configuration fields: {', '.join(missing)}")
    
    # Return configuration as dictionary
    return {
        'client_id': api_config['client_id'],
        'client_secret': api_config['client_secret'],
        'hostname': api_config['hostname'],
        'endpoint_url': api_config['endpoint_url'],
        'states_file': api_config.get('states_file', 'us_states.txt'),
        'payload_file': api_config.get('payload_file', 'payload_template.json'),
        'output_csv': api_config.get('output_csv', 'fq_parameters.csv'),
        'output_json': api_config.get('output_json', 'state_results.json')
    }


def main(config_file: str):
    """Main function to run the script."""
    # Set up logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    try:
        # Load configuration
        logger.info(f"Loading configuration from {config_file}")
        config = load_config(config_file)
        
        # Initialize API client
        api_client = SearchAPI(
            client_id=config['client_id'],
            client_secret=config['client_secret'],
            hostname=config['hostname'],
            endpoint_url=config['endpoint_url'],
            output_csv=config['output_csv'],
            output_json=config['output_json']
        )
        
        # Process states
        results = api_client.process_states(
            states_file=config['states_file'],
            payload_file=config['payload_file']
        )
        
        logger.info(f"Processed {len(results)} states successfully")
        logger.info(f"Results saved to {config['output_csv']} and {config['output_json']}")
        
    except FileNotFoundError as e:
        logger.error(f"File not found: {str(e)}")
        return 1
    except ValueError as e:
        logger.error(f"Configuration error: {str(e)}")
        return 1
    except Exception as e:
        logger.error(f"Script execution failed: {str(e)}")
        return 1
    
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Search API Client')
    parser.add_argument('--config', default='config.ini', help='Path to configuration file (default: config.ini)')
    args = parser.parse_args()
    
    exit_code = main(args.config)
    exit(exit_code)