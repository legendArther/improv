import os
import requests
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

# --- Configuration ---
# !!! SECURITY: Get sensitive keys from environment variables !!!
# Set these in your Render service environment settings
IMPROVMX_API_KEY = os.getenv('IMPROVMX_API_KEY')
APP_SECRET_KEY = os.getenv('APP_SECRET_KEY') # Secret to protect your own API endpoints

# --- Hardcoded Values ---
# Domain and forward email are fixed in this version
DOMAIN_NAME = "writebear.tech"
FORWARD_EMAIL = "7harshdeep@gmail.com"
BASE_URL = "https://api.improvmx.com/v3"

# --- Helper Function to Check Server Configuration ---
def check_config():
    """Checks if required environment variables are set."""
    if not IMPROVMX_API_KEY:
        print("CRITICAL SERVER ERROR: IMPROVMX_API_KEY environment variable not set.")
        # Return tuple: (config_ok, error_response_object, status_code)
        return False, jsonify({"success": False, "error": "Server configuration error: ImprovMX API Key missing."}), 500
    if not APP_SECRET_KEY:
        print("CRITICAL SERVER ERROR: APP_SECRET_KEY environment variable not set.")
        return False, jsonify({"success": False, "error": "Server configuration error: App Secret Key missing."}), 500
    # Config is OK
    return True, None, None

# --- Default Route ---
@app.route('/')
def home():
    """Simple welcome message for the root URL."""
    return jsonify({"message": "ImprovMX Alias Adder Service Ready."}), 200

# --- Secure POST Route (Recommended) ---
@app.route('/add_alias', methods=['POST'])
def add_alias_post_route():
    """
    Adds an alias via a POST request.
    Requires 'X-App-Secret' header for authentication.
    Expects JSON body: {"alias": "your_alias_prefix"}
    Returns JSON response.
    """
    config_ok, error_response, status_code = check_config()
    if not config_ok:
        return error_response, status_code

    # --- Authenticate Request to this Flask App (via Header) ---
    provided_secret = request.headers.get('X-App-Secret')
    if not provided_secret or provided_secret != APP_SECRET_KEY:
        print(f"WARN (/add_alias POST): Unauthorized attempt. Secret in header: '{provided_secret}'")
        return jsonify({"success": False, "error": "Unauthorized: Missing or invalid X-App-Secret header."}), 401

    # --- Get Alias Name from JSON Request Body ---
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "Bad Request: Missing JSON body."}), 400

        alias_name = data.get('alias')

        if not alias_name or not isinstance(alias_name, str) or not alias_name.strip():
             return jsonify({"success": False, "error": "Bad Request: Missing or invalid 'alias' key in JSON body (must be non-empty string)."}), 400

        # Basic sanitization
        alias_name = alias_name.strip().lower()

    except Exception as e:
        print(f"ERROR (/add_alias POST): Failed to parse JSON body. Error: {e}")
        return jsonify({"success": False, "error": f"Bad Request: Invalid JSON format. {e}"}), 400

    # --- Call the Core Logic ---
    # The core logic function returns a Flask Response object (jsonify result) and status code
    response_object, response_status_code = _add_alias_logic(alias_name)
    return response_object, response_status_code

# --- Less Secure GET Route (Via URL) ---
# !!! WARNING: Exposing secret key in URL is insecure !!!
@app.route('/add_alias_via_url', methods=['GET'])
def add_alias_get_route():
    """
    Adds an alias via a GET request (e.g., browser URL).
    Requires 'secret' query parameter for authentication. (Less Secure!)
    Requires 'alias' query parameter for the alias prefix.
    Returns simple HTML response.
    Example URL: /add_alias_via_url?secret=YOUR_SECRET&alias=test
    """
    config_ok, error_response, status_code = check_config()
    if not config_ok:
        # For GET, return HTML error if config fails server-side
         return f"<h1>Server Configuration Error ({status_code})</h1><p>Please check server logs.</p>", status_code

    # --- Authenticate Request to this Flask App (via Query Parameter) ---
    provided_secret = request.args.get('secret') # Get secret from ?secret=...
    if not provided_secret or provided_secret != APP_SECRET_KEY:
        print(f"WARN (/add_alias_via_url GET): Unauthorized attempt. Secret in query: '{provided_secret}'")
        # Return HTML for browser users
        return f"<h1>401 Unauthorized</h1><p>Missing or invalid 'secret' query parameter.</p>", 401

    # --- Get Alias Name from Query Parameter ---
    alias_name = request.args.get('alias') # Get alias from &alias=...
    if not alias_name or not isinstance(alias_name, str) or not alias_name.strip():
         # Return HTML for browser users
        return f"<h1>400 Bad Request</h1><p>Missing or invalid 'alias' query parameter (must be non-empty string).</p>", 400

    # Basic sanitization
    alias_name = alias_name.strip().lower()

    # --- Call the Core Logic ---
    response_object, response_status_code = _add_alias_logic(alias_name)

    # --- Format Response as Simple HTML for Browser ---
    try:
        response_data = response_object.get_json() # Extract JSON data from the response object
        success = response_data.get("success", False)

        if response_status_code == 200 and success:
            alias_details = response_data.get("improvmx_response", {}).get("alias", {})
            # Safely get details with defaults
            alias_val = alias_details.get('alias', 'N/A')
            forward_val = alias_details.get('forward', 'N/A')
            id_val = alias_details.get('id', 'N/A')
            return f"""
            <!DOCTYPE html><html><head><title>Success</title></head><body>
            <h1>✅ Success!</h1>
            <p>Alias added successfully via ImprovMX.</p>
            <hr>
            <p><b>Domain:</b> {DOMAIN_NAME}</p>
            <p><b>Alias Created:</b> {alias_val}</p>
            <p><b>Forwarding To:</b> {forward_val}</p>
            <p><b>ImprovMX ID:</b> {id_val}</p>
            </body></html>
            """, 200
        else:
            # Handle failure cases
            error_msg = response_data.get("message", "Unknown error during processing.")
            improvmx_error_details = response_data.get("improvmx_error", response_data.get("improvmx_raw_response", "No details available."))
            # Pretty print if it's likely JSON/dict, otherwise show raw
            if isinstance(improvmx_error_details, (dict, list)):
                error_details_formatted = f"<pre>{json.dumps(improvmx_error_details, indent=2)}</pre>"
            else:
                 error_details_formatted = f"<pre>{improvmx_error_details}</pre>"

            return f"""
            <!DOCTYPE html><html><head><title>Error</title></head><body>
            <h1>❌ Error ({response_status_code})</h1>
            <p><b>Failed to add alias:</b> {error_msg}</p>
            <hr>
            <p><b>ImprovMX API Response Details:</b></p>
            {error_details_formatted}
            </body></html>
            """, response_status_code

    except Exception as e:
        # Fallback if getting JSON or formatting fails
        print(f"ERROR (/add_alias_via_url GET): Failed to format HTML response. Error: {e}")
        return f"<h1>Internal Server Error</h1><p>Failed to format response.</p>", 500


# --- Core Logic Function (Called by both routes) ---
def _add_alias_logic(alias_name):
    """
    Handles the actual ImprovMX API call to create an alias.

    Args:
        alias_name (str): The validated alias prefix to create.

    Returns:
        tuple: (Flask Response Object (jsonify result), HTTP Status Code)
    """
    # Prepare ImprovMX API Call details
    # Correct endpoint for CREATING aliases requires POST
    api_endpoint = f"{BASE_URL}/domains/{DOMAIN_NAME}/aliases"
    auth = ('api', IMPROVMX_API_KEY) # Basic Auth
    # Payload must include both 'alias' and 'forward' for creation
    payload = {
        "alias": alias_name,
        "forward": FORWARD_EMAIL # Using the hardcoded forward email
    }
    headers = {'Content-Type': 'application/json'}

    print(f"Attempting ImprovMX API call to ADD alias: {alias_name}@{DOMAIN_NAME} -> {FORWARD_EMAIL}")
    try:
        # Make the POST request to ImprovMX to create the alias
        response = requests.post(api_endpoint, auth=auth, headers=headers, json=payload, timeout=15)

        # --- Process ImprovMX Response ---
        status_code = response.status_code
        try:
            # Try to parse the response as JSON
            response_json = response.json()
            print(f"ImprovMX Response Status: {status_code}, Body: {response_json}")

            # Check ImprovMX's specific success flag along with HTTP status
            if status_code == 200 and response_json.get("success"):
                # Successful creation
                return jsonify({
                    "success": True,
                    "message": "Alias added successfully via ImprovMX.",
                    "improvmx_response": response_json
                }), 200
            else:
                # Handle cases where ImprovMX returns 200 OK but "success": false,
                # or when ImprovMX returns a non-200 status code (e.g., 400 for duplicate alias).
                # Extract specific error message if available
                error_message = response_json.get("errors", f"ImprovMX returned status {status_code} with success=false or error.")
                print(f"ERROR: ImprovMX API call indicated failure. Status: {status_code}, Response: {response_json}")
                return jsonify({
                    "success": False,
                    "message": f"Failed to add alias via ImprovMX.",
                    "improvmx_response": response_json,
                    "improvmx_error": error_message # Provide specific ImprovMX error if possible
                }), status_code if status_code >= 400 else 400 # Return ImprovMX's error code or default to 400

        except json.JSONDecodeError:
            # Handle cases where ImprovMX response is not valid JSON
            print(f"ERROR: ImprovMX returned non-JSON response. Status: {status_code}, Body: {response.text}")
            return jsonify({
                "success": False,
                "message": f"ImprovMX API request failed with status {status_code}. Could not decode JSON response.",
                "improvmx_raw_response": response.text
                }), status_code if status_code >= 400 else 502 # Use ImprovMX code or 502 Bad Gateway

    except requests.exceptions.Timeout:
        print(f"ERROR: Request to ImprovMX timed out.")
        return jsonify({"success": False, "error": "Request to ImprovMX API timed out."}), 504 # Gateway Timeout
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Network error communicating with ImprovMX: {e}")
        return jsonify({"success": False, "error": f"Network error communicating with ImprovMX API: {e}"}), 503 # Service Unavailable


# --- Optional: Local run section (Gunicorn is used on Render) ---
# Use this block to run the app locally for testing
# Make sure to set the environment variables locally as well
# (e.g., export IMPROVMX_API_KEY='...' ; export APP_SECRET_KEY='...')
# if __name__ == '__main__':
#     print("Attempting to run Flask app locally...")
#     # Check for environment variables locally for easier debugging
#     if not os.getenv('IMPROVMX_API_KEY'): print("WARNING: IMPROVMX_API_KEY env var not set locally.")
#     if not os.getenv('APP_SECRET_KEY'): print("WARNING: APP_SECRET_KEY env var not set locally.")
#     # Run on port 5001, enable debug mode for development
#     app.run(debug=True, port=5001, host='0.0.0.0')