import os
import requests
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

# --- Configuration ---
IMPROVMX_API_KEY = "sk_cac826dc31c0474dafc89eef3dbaa04e"
# APP_SECRET_KEY = os.getenv('APP_SECRET_KEY') # Removed app secret key

BASE_URL = "https://api.improvmx.com/v3"

@app.route('/')
def home():
    # Simple welcome message for the root URL
    return jsonify({"message": "ImprovMX Alias Adder Service Ready. Use POST /add_alias"}), 200

@app.route('/add_alias', methods=['POST'])
def add_alias_route():
    # --- 1. Check Environment Variables ---
    if not IMPROVMX_API_KEY:
        return jsonify({"success": False, "error": "Server configuration error: ImprovMX API Key not set."}), 500

    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "Bad Request: Missing JSON body."}), 400

        # domain_name = data.get('domain') # Removed: Will be hardcoded
        alias_name = data.get('alias')
        # forward_email = data.get('forward') # Removed: Will be hardcoded

        # Adjusted check: only 'alias' is now required in JSON
        if not alias_name:
            return jsonify({"success": False, "error": "Bad Request: Missing 'alias' in JSON body."}), 400

    except Exception as e:
        return jsonify({"success": False, "error": f"Bad Request: Invalid JSON format. {e}"}), 400

    # --- 4. Prepare ImprovMX API Call ---
    domain_name = "writebear.tech" # Hardcoded domain name
    # Alias is now part of the URL path
    # API Key removed from URL, will use Basic Auth
    api_endpoint = f"{BASE_URL}/domains/{domain_name}/aliases/{alias_name}"
    auth = ('api', IMPROVMX_API_KEY) # Reinstated Basic Auth
    forward_email = "7harshdeep@gmail.com" # Hardcoded forward email
    payload = {
        # "alias": alias_name, # Alias is now in the URL path, might not be needed in payload for creation - check ImprovMX docs if issues arise
        "forward": forward_email
    }
    headers = {
        'Content-Type': 'application/json'
    }

    # --- 5. Make the ImprovMX API Call ---
    # Use f-string interpolation for the print message
    print(f"Attempting ImprovMX API call for {alias_name}@{domain_name} -> {forward_email}") # For server logs
    try:
        # Reinstated auth parameter
        response = requests.post(api_endpoint, auth=auth, headers=headers, json=payload, timeout=15)

        # --- 6. Process ImprovMX Response ---
        status_code = response.status_code
        try:
            response_json = response.json()
            print(f"ImprovMX Response Status: {status_code}, Body: {response_json}") # For server logs

            # Return the response from ImprovMX directly, but ensure our own success status is consistent
            if status_code == 200 and response_json.get("success"):
                 # Successfully added by ImprovMX
                return jsonify({
                    "success": True,
                    "message": "Alias added successfully via ImprovMX.",
                    "improvmx_response": response_json
                }), 200
            elif status_code == 200 and not response_json.get("success"):
                # ImprovMX returned 200 but indicated failure in the body
                 return jsonify({
                    "success": False,
                    "message": "ImprovMX reported failure.",
                    "improvmx_response": response_json
                }), 400 # Use a client error code like 400
            else:
                # ImprovMX returned an error status code (4xx, 5xx)
                return jsonify({
                    "success": False,
                    "message": f"ImprovMX API request failed with status {status_code}.",
                    "improvmx_response": response_json
                }), status_code # Propagate ImprovMX's error code

        except json.JSONDecodeError:
            # Handle cases where ImprovMX response is not valid JSON
            print(f"ImprovMX Response Status: {status_code}, Body (Not JSON): {response.text}") # For server logs
            return jsonify({
                "success": False,
                "message": f"ImprovMX API request failed with status {status_code}. Could not decode JSON response.",
                "improvmx_raw_response": response.text
                }), status_code

    except requests.exceptions.Timeout:
        print(f"Error: Request to ImprovMX timed out.")
        return jsonify({"success": False, "error": "Request to ImprovMX API timed out."}), 504 # Gateway Timeout
    except requests.exceptions.RequestException as e:
        print(f"Error making request to ImprovMX: {e}") # For server logs
        return jsonify({"success": False, "error": f"Network error communicating with ImprovMX API: {e}"}), 503 # Service Unavailable


# --- Run for local testing (optional) ---
# Gunicorn will run the app in production on Render
# if __name__ == '__main__':
#     # Warn if keys aren't set locally (won't stop execution)
#     if not IMPROVMX_API_KEY: print("Warning: IMPROVMX_API_KEY not set locally.")
#     # Removed app secret key warning
#     # if not APP_SECRET_KEY: print("Warning: APP_SECRET_KEY not set locally.")
#     app.run(debug=True, port=5001) # Use a port other than default 5000 if needed 