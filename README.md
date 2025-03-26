# SearchAPIClient

A modular Python client for interacting with a REST Search API. This library simplifies authentication, request handling, and data extraction when working with HTTP search endpoints.

## Features

- OAuth 2.0 authentication with automatic token refresh
- Extraction of SOLR query parameters from API responses
- Batch processing of geographical locations/states filters
- CSV and JSON output options
- Comprehensive error handling and logging

## Installation

```bash
pip3 install -r packages.txt
```

## Quick Start

```bash
python3 main.py --mode <mode>
```

### Mode Flag

The `--mode` argument specifies what to process. The available options are:

- `states`: Process states filter by sending them as a payload to POST http endpoint
- `countries`: Process countries filter by sending them as a payload to POST http endpoint
- `documentids`: Process document IDs by sending them to a GET http endpoint
- `address`: Process address filter by sending them as a payload to POST http endpoint


## Configuration

The client requires the following configuration in the config.ini file:

- `client_id`: Your API client ID
- `client_secret`: Your API client secret
- `hostname`: API hostname for JWT generation
- `endpoint_url`: Full URL to the endpoint for requests

## Input Files

- `states_file`: Text file with one state/location per line
- `payload_template.json`: Template for the API request payload

## Output Files

- CSV file (`fq_parameters.csv` by default) with state and filter parameters
- JSON file (`state_results.json` by default) with complete extraction results

## Advanced Usage

Modify the following lines of code for custom parsing 

### Custom Response Processing

```python
def process_response(self, response_json: Dict, state: str) -> Dict:
        """Process the response and extract fq parameters for a given state."""
        solr_url = self.extract_solr_url(response_json)
        fq_params = self.extract_fq_parameters(solr_url)
        
        return {
            'state': state,
            'fq_parameters': fq_params
        }
```

## Future Improvements

- Package entire authentication manager and SearchAPI into their own modules
- Implement async/await with aiohttp to process multiple states concurrently to improve throughput
- Implement exponential back-off mechanism to prevent overloading with retries API
- Improve result json logging
- Improve output logging to be more visually appealing than CSV
- Additional input variations in the payload for testing and easier usage without CLI inputs
- Create a simple dashboard using Dash or Streamlit to visualize results
- Package the application as a Docker container for consistent deployment
- Add comprehensive test coverage


## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.