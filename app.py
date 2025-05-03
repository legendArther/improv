import os
import requests
import json
import imaplib # Added
import email   # Added
import re      # Added
from bs4 import BeautifulSoup # Added
from flask import Flask, request, jsonify

app = Flask(__name__)

# --- Configuration ---
# !!! SECURITY: Get sensitive keys from environment variables !!!
# Set these in your Render service environment settings
IMPROVMX_API_KEY = os.getenv('IMPROVMX_API_KEY')
APP_SECRET_KEY = os.getenv('APP_SECRET_KEY') # Secret to protect your own API endpoints
ZOHO_IMAP_USER = os.getenv('ZOHO_IMAP_USER') # e.g., 'varunn@writebear.tech'
ZOHO_IMAP_PASSWORD = os.getenv('ZOHO_IMAP_PASSWORD') # Your Zoho App Password or Account Password

# --- Hardcoded Values ---
# Domain and forward email are fixed in this version
DOMAIN_NAME = "writebear.tech"
FORWARD_EMAIL = "markdavis939@zohomail.com"
BASE_URL = "https://api.improvmx.com/v3"
ZOHO_IMAP_SERVER = "imap.zoho.com" # Added
ZOHO_IMAP_PORT = 993              # Added (IMAP SSL port)
OTP_TARGET_EMAIL = "varunn@writebear.tech" # Added - specify which email account to read

# --- Helper Function to Check Server Configuration ---
def check_config():
    """Checks if required environment variables are set."""
    errors = []
    if not IMPROVMX_API_KEY:
        errors.append("IMPROVMX_API_KEY environment variable not set.")
    if not APP_SECRET_KEY:
        errors.append("APP_SECRET_KEY environment variable not set.")
    if not ZOHO_IMAP_USER:
        errors.append("ZOHO_IMAP_USER environment variable not set.")
    if not ZOHO_IMAP_PASSWORD:
        errors.append("ZOHO_IMAP_PASSWORD environment variable not set.")

    if errors:
        full_error_message = "Server configuration error: " + "; ".join(errors)
        print(f"CRITICAL SERVER ERROR: {full_error_message}")
        # Return tuple: (config_ok, error_response_object, status_code)
        return False, jsonify({"success": False, "error": full_error_message}), 500

    # Config is OK
    return True, None, None

# --- Default Route ---
@app.route('/')
def home():
    """Simple welcome message for the root URL."""
    return jsonify({"message": "ImprovMX Alias Adder & OTP Service Ready."}), 200

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

# --- NEW: Secure GET Route for OTP ---
@app.route('/get_otp', methods=['GET'])
def get_otp_route():
    """
    Reads the latest email for OTP_TARGET_EMAIL and extracts a 6-digit OTP.
    !!! WARNING: This endpoint is currently PUBLIC and has NO AUTHENTICATION !!!
    Returns JSON response: {"success": true, "otp": "123456"} or error.
    Example URL: https://your-app-name.onrender.com/get_otp
    """
    config_ok, error_response, status_code = check_config()
    if not config_ok:
        # Still return JSON for API consistency, even for config errors
        return error_response, status_code

    # --- Authentication Removed ---
    # The following lines that checked X-App-Secret header are removed:
    # provided_secret = request.headers.get('X-App-Secret')
    # if not provided_secret or provided_secret != APP_SECRET_KEY:
    #     print(f"WARN (/get_otp GET): Unauthorized attempt. Secret in header: '{provided_secret}'")
    #     return jsonify({"success": False, "error": "Unauthorized: Missing or invalid X-App-Secret header."}), 401
    # --- End of Removed Authentication Block ---

    print("INFO (/get_otp GET): Public endpoint accessed.") # Log access

    # --- Call the Core OTP Logic ---
    otp, error_message = _get_latest_otp_from_email()

    if otp:
        print(f"INFO (/get_otp GET): Successfully retrieved OTP: {otp}")
        return jsonify({"success": True, "otp": otp}), 200
    else:
        print(f"ERROR (/get_otp GET): Failed to retrieve OTP. Reason: {error_message}")
        # Determine appropriate status code
        if "Could not find OTP" in error_message:
             status_code = 404 # Not Found
        elif "Inbox empty" in error_message:
             status_code = 404 # Not Found
        else:
            status_code = 500 # Internal Server Error / Service Unavailable
        return jsonify({"success": False, "error": error_message}), status_code
    """
    Reads the latest email for OTP_TARGET_EMAIL and extracts a 6-digit OTP.
    Requires 'X-App-Secret' header for authentication.
    Returns JSON response: {"success": true, "otp": "123456"} or error.
    """
    config_ok, error_response, status_code = check_config()
    if not config_ok:
        return error_response, status_code

    # --- Authenticate Request to this Flask App (via Header) ---
    provided_secret = request.headers.get('X-App-Secret')
    if not provided_secret or provided_secret != APP_SECRET_KEY:
        print(f"WARN (/get_otp GET): Unauthorized attempt. Secret in header: '{provided_secret}'")
        return jsonify({"success": False, "error": "Unauthorized: Missing or invalid X-App-Secret header."}), 401

    # --- Call the Core OTP Logic ---
    otp, error_message = _get_latest_otp_from_email()

    if otp:
        print(f"INFO (/get_otp GET): Successfully retrieved OTP: {otp}")
        return jsonify({"success": True, "otp": otp}), 200
    else:
        print(f"ERROR (/get_otp GET): Failed to retrieve OTP. Reason: {error_message}")
        # Determine appropriate status code
        if "Could not find OTP" in error_message:
             status_code = 404 # Not Found
        elif "Inbox empty" in error_message:
             status_code = 404 # Not Found
        else:
            status_code = 500 # Internal Server Error / Service Unavailable
        return jsonify({"success": False, "error": error_message}), status_code


# --- Core Logic Function (ImprovMX Alias Addition) ---
def _add_alias_logic(alias_name):
    """
    Handles the actual ImprovMX API call to create an alias.

    Args:
        alias_name (str): The validated alias prefix to create.

    Returns:
        tuple: (Flask Response Object (jsonify result), HTTP Status Code)
    """
    # Prepare ImprovMX API Call details
    api_endpoint = f"{BASE_URL}/domains/{DOMAIN_NAME}/aliases"
    auth = ('api', IMPROVMX_API_KEY) # Basic Auth
    payload = {
        "alias": alias_name,
        "forward": FORWARD_EMAIL
    }
    headers = {'Content-Type': 'application/json'}

    print(f"Attempting ImprovMX API call to ADD alias: {alias_name}@{DOMAIN_NAME} -> {FORWARD_EMAIL}")
    try:
        response = requests.post(api_endpoint, auth=auth, headers=headers, json=payload, timeout=15)
        status_code = response.status_code
        try:
            response_json = response.json()
            print(f"ImprovMX Response Status: {status_code}, Body: {response_json}")

            if status_code == 200 and response_json.get("success"):
                return jsonify({
                    "success": True,
                    "message": "Alias added successfully via ImprovMX.",
                    "improvmx_response": response_json
                }), 200
            else:
                error_message = response_json.get("errors", f"ImprovMX returned status {status_code} with success=false or error.")
                print(f"ERROR: ImprovMX API call indicated failure. Status: {status_code}, Response: {response_json}")
                return jsonify({
                    "success": False,
                    "message": f"Failed to add alias via ImprovMX.",
                    "improvmx_response": response_json,
                    "improvmx_error": error_message
                }), status_code if status_code >= 400 else 400

        except json.JSONDecodeError:
            print(f"ERROR: ImprovMX returned non-JSON response. Status: {status_code}, Body: {response.text}")
            return jsonify({
                "success": False,
                "message": f"ImprovMX API request failed with status {status_code}. Could not decode JSON response.",
                "improvmx_raw_response": response.text
                }), status_code if status_code >= 400 else 502

    except requests.exceptions.Timeout:
        print(f"ERROR: Request to ImprovMX timed out.")
        return jsonify({"success": False, "error": "Request to ImprovMX API timed out."}), 504
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Network error communicating with ImprovMX: {e}")
        return jsonify({"success": False, "error": f"Network error communicating with ImprovMX API: {e}"}), 503


# --- NEW: Core Logic Function (Read OTP from Email) ---
def _get_latest_otp_from_email():
    """
    Connects to Zoho IMAP, fetches the latest up to TWO emails for ZOHO_IMAP_USER,
    checks them newest first, and extracts the first 6-digit OTP found.

    Returns:
        tuple: (otp_string, error_message_string)
               Returns (None, error_message) on failure.
               Returns (otp, None) on success.
    """
    mail = None
    try:
        print(f"Attempting IMAP connection to {ZOHO_IMAP_SERVER}:{ZOHO_IMAP_PORT} for user {ZOHO_IMAP_USER}")
        mail = imaplib.IMAP4_SSL(ZOHO_IMAP_SERVER, ZOHO_IMAP_PORT)
        typ, account_details = mail.login(ZOHO_IMAP_USER, ZOHO_IMAP_PASSWORD)
        if typ != 'OK':
            print(f"ERROR: IMAP login failed for {ZOHO_IMAP_USER}. Response: {account_details}")
            return None, f"IMAP login failed for {ZOHO_IMAP_USER}"
        print("IMAP login successful.")

        typ, data = mail.select("inbox")
        if typ != 'OK':
            print(f"ERROR: Failed to select inbox. Response: {data}")
            # Ensure logout happens even on early failures
            if mail and mail.state != 'LOGOUT': mail.logout()
            return None, "Failed to select inbox."
        print("Inbox selected.")

        # Search for all emails and get IDs
        # Consider adding UNSEEN or SUBJECT filter if needed later
        result, data = mail.search(None, "ALL")
        if result != 'OK':
            print(f"ERROR: Failed to search inbox. Response: {data}")
            if mail and mail.state != 'LOGOUT': mail.logout() # Logout on search failure
            return None, "Failed to search inbox."

        all_ids_bytes = data[0].split()
        if not all_ids_bytes:
            print("INFO: Inbox is empty.")
            # Logout before returning
            if mail and mail.state != 'LOGOUT': mail.logout()
            return None, "Inbox empty, no email found."

        # --- MODIFICATION START ---
        # Get the last two IDs (or fewer if less than 2 emails exist)
        # Slicing handles cases with 0 or 1 email gracefully
        ids_to_check_bytes = all_ids_bytes[-2:]

        # Process newest first
        ids_to_check_bytes.reverse() # Now it's [latest, second_latest] or [latest]

        print(f"INFO: Checking up to {len(ids_to_check_bytes)} latest email(s)... IDs: {[id_b.decode() for id_b in ids_to_check_bytes]}")

        for email_id_bytes in ids_to_check_bytes:
            email_id_str = email_id_bytes.decode() # For logging
            print(f"\n--- Processing Email ID: {email_id_str} ---")

            # Fetch the email content
            result, msg_data = mail.fetch(email_id_bytes, "(RFC822)")
            if result != 'OK':
                print(f"ERROR: Failed to fetch email ID {email_id_str}. Response: {msg_data}. Skipping this email.")
                continue # Try the next email ID in the list

            msg = email.message_from_bytes(msg_data[0][1])

            print(f"Email ID {email_id_str} Subject:", msg["subject"])
            # print(f"Email ID {email_id_str} From:", msg["from"]) # Optional logging

            body_text = None
            # --- Email parsing logic (identical to before) ---
            if msg.is_multipart():
                # print("Parsing multipart email...") # Less verbose logging
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    if "attachment" in content_disposition: continue
                    try:
                        payload = part.get_payload(decode=True)
                        if not payload: continue
                        charset = part.get_content_charset() or 'utf-8'
                        part_text = payload.decode(charset, errors='replace')

                        if content_type == "text/plain":
                            # print("Found text/plain part.")
                            body_text = part_text
                            # Prioritize plain text if available FOR THIS EMAIL
                            break # Stop checking parts for *this* email
                        elif content_type == "text/html":
                            # print("Found text/html part.")
                            soup = BeautifulSoup(part_text, "html.parser")
                            # Only assign HTML if plain text wasn't already found
                            if body_text is None:
                                body_text = soup.get_text()

                    except Exception as e:
                        print(f"WARN: Could not decode/process part {content_type} for email {email_id_str}. Error: {e}")
                        continue
            else: # Not multipart
                # print("Parsing non-multipart email...") # Less verbose logging
                content_type = msg.get_content_type()
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        charset = msg.get_content_charset() or 'utf-8'
                        msg_text = payload.decode(charset, errors='replace')
                        if "text/" in content_type: # Broader check for text types
                           # print(f"Found {content_type} content.")
                           if content_type == "text/html":
                               soup = BeautifulSoup(msg_text, "html.parser")
                               body_text = soup.get_text()
                           else: # Assume plain text or treat others as plain
                               body_text = msg_text
                        # else: # Ignore non-text types
                        #    print(f"WARN: Non-multipart email has non-text content type: {content_type}")
                except Exception as e:
                    print(f"WARN: Could not decode/process non-multipart body for email {email_id_str}. Error: {e}")

            # --- Check if body was extracted for this email ---
            if not body_text:
                print(f"INFO: No readable email body found for email ID {email_id_str}. Checking next (if any).")
                continue # Try the next email ID

            # --- DEBUG: Log the extracted body text ---
            print(f"--- Body Text Extracted (Email ID: {email_id_str}) ---")
            print(f"Type: {type(body_text)}, Length: {len(body_text)}")
            print(repr(body_text[:1000]) + ('...' if len(body_text) > 1000 else '')) # Print repr snippet
            print("--- End Body Text ---")

            # --- Extract 6-digit OTP using regex (using the robust lookaround version) ---
            # Use r'\b(\d{6})' if you preferred that one and it worked locally
            otp_match = re.search(r'(?<!\d)(\d{6})(?!\d)', body_text) # Recommended

            if otp_match:
                otp = otp_match.group(1)
                print(f"SUCCESS: Found 6-digit OTP: {otp} in email ID {email_id_str}")
                # --- OTP Found - Logout and Return Success ---
                if mail and mail.state != 'LOGOUT': mail.logout()
                return otp, None # SUCCESS!
            else:
                print(f"INFO: Could not find 6-digit OTP in email ID {email_id_str}. Checking next (if any).")
                # Loop continues to the next email_id automatically

        # --- MODIFICATION END ---

        # --- If loop finishes without finding OTP ---
        print(f"ERROR: OTP not found after checking the last {len(ids_to_check_bytes)} email(s).")
        if mail and mail.state != 'LOGOUT': mail.logout() # Logout before returning error
        return None, f"Could not find 6-digit OTP in the last {len(ids_to_check_bytes)} email(s)."

    except imaplib.IMAP4.error as e:
        print(f"ERROR: IMAP error occurred: {e}")
        # Attempt logout even after IMAP errors if connection object exists
        if mail and mail.state != 'LOGOUT':
             try: mail.logout()
             except: pass # Ignore errors during logout after another error
        return None, f"IMAP error: {e}"
    except ConnectionRefusedError as e:
         print(f"ERROR: IMAP connection refused: {e}")
         # No connection, so no logout needed
         return None, f"IMAP connection refused ({ZOHO_IMAP_SERVER}:{ZOHO_IMAP_PORT})"
    except Exception as e:
        print(f"ERROR: An unexpected error occurred during email processing: {e}")
        print(traceback.format_exc()) # Print stack trace
        # Attempt logout on general exceptions
        if mail and mail.state != 'LOGOUT':
             try: mail.logout()
             except: pass
        return None, f"An unexpected server error occurred: {e}"

    finally:
        # This finally block might be redundant now as logout is handled in return paths,
        # but it acts as a final safety net if an exception occurs before a return
        # or if a return path misses the logout.
        if mail and mail.state != 'LOGOUT':
            print("INFO: Ensuring IMAP logout in finally block.")
            try:
                if mail.state == 'SELECTED': mail.close()
                mail.logout()
                print("IMAP final logout successful.")
            except Exception as e:
                 print(f"WARN: Error during final IMAP logout/close: {e}")   
                 """
    Connects to Zoho IMAP, fetches the latest email for ZOHO_IMAP_USER,
    and extracts a 6-digit OTP.

    Returns:
        tuple: (otp_string, error_message_string)
               Returns (None, error_message) on failure.
               Returns (otp, None) on success.
    """
    mail = None # Initialize mail object outside try block for finally
    try:
        print(f"Attempting IMAP connection to {ZOHO_IMAP_SERVER}:{ZOHO_IMAP_PORT} for user {ZOHO_IMAP_USER}")
        mail = imaplib.IMAP4_SSL(ZOHO_IMAP_SERVER, ZOHO_IMAP_PORT)
        
        # Use ZOHO_IMAP_USER and ZOHO_IMAP_PASSWORD from environment variables
        typ, account_details = mail.login(ZOHO_IMAP_USER, ZOHO_IMAP_PASSWORD)
        if typ != 'OK':
            print(f"ERROR: IMAP login failed for {ZOHO_IMAP_USER}. Response: {account_details}")
            return None, f"IMAP login failed for {ZOHO_IMAP_USER}"
        print("IMAP login successful.")

        typ, data = mail.select("inbox")
        if typ != 'OK':
             print(f"ERROR: Failed to select inbox. Response: {data}")
             return None, "Failed to select inbox."
        print("Inbox selected.")

        # Search for all emails and get IDs
        # Consider searching for specific subjects/senders if needed: '(SUBJECT "Stake.com Verification")'
        result, data = mail.search(None, "ALL")
        if result != 'OK':
            print(f"ERROR: Failed to search inbox. Response: {data}")
            return None, "Failed to search inbox."

        ids = data[0].split()
        if not ids:
            print("INFO: Inbox is empty.")
            return None, "Inbox empty, no email found."

        latest_id = ids[-1]
        print(f"Fetching latest email with ID: {latest_id.decode()}")

        # Fetch the email content
        result, msg_data = mail.fetch(latest_id, "(RFC822)")
        if result != 'OK':
            print(f"ERROR: Failed to fetch email ID {latest_id.decode()}. Response: {msg_data}")
            return None, f"Failed to fetch email ID {latest_id.decode()}"

        msg = email.message_from_bytes(msg_data[0][1])

        print("Email Subject:", msg["subject"])
        print("Email From:", msg["from"])
        # print("Email To:", msg["to"]) # Usually varunn@writebear.tech

        body_text = None

        if msg.is_multipart():
            print("Parsing multipart email...")
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                # Skip attachments
                if "attachment" in content_disposition:
                    continue

                try:
                    payload = part.get_payload(decode=True)
                    if not payload: # Skip empty parts
                         continue
                    # Decode payload using charset if specified, otherwise try common ones
                    charset = part.get_content_charset() or 'utf-8' # Default to utf-8
                    part_text = payload.decode(charset, errors='replace') # Use replace for robustness

                    if content_type == "text/plain":
                        print("Found text/plain part.")
                        body_text = part_text # Prefer plain text
                        break # Found plain text, stop searching parts
                    elif content_type == "text/html":
                        print("Found text/html part (will parse if no plain text found).")
                        soup = BeautifulSoup(part_text, "html.parser")
                        body_text = soup.get_text() # Extract text from HTML

                except Exception as e:
                    print(f"WARN: Could not decode/process part {content_type}. Error: {e}")
                    continue # Try next part

        else: # Not multipart
            print("Parsing non-multipart email...")
            content_type = msg.get_content_type()
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    msg_text = payload.decode(charset, errors='replace')

                    if content_type == "text/plain":
                        print("Found text/plain content.")
                        body_text = msg_text
                    elif content_type == "text/html":
                        print("Found text/html content.")
                        soup = BeautifulSoup(msg_text, "html.parser")
                        body_text = soup.get_text()
                    else:
                        print(f"WARN: Non-multipart email has unsupported content type: {content_type}")

            except Exception as e:
                 print(f"WARN: Could not decode/process non-multipart body. Error: {e}")


        if not body_text:
            print("ERROR: No readable email body found after parsing.")
            return None, "No readable email body found."

        # print("\n--- Extracted Body Text ---")
        # print(body_text[:500] + "..." if len(body_text) > 500 else body_text) # Print snippet for debugging
        # print("--- End Body Text ---")

        # --- Extract 6-digit OTP using regex ---
        # \b ensures we match whole numbers (word boundary)
        # \d{6} matches exactly 6 digits
        otp_match = re.search(r'(\d{6})', body_text)

        if otp_match:
            otp = otp_match.group(1)
            print(f"SUCCESS: Found 6-digit OTP: {otp}")
            return otp, None
        else:
            print("ERROR: Could not find 6-digit OTP in the email body.")
            # Log more of the body text if OTP isn't found, for debugging
            print("--- Body Text Searched (Full) ---")
            print(body_text)
            print("--- End Body Text Searched ---")
            return None, "Could not find 6-digit OTP in the email body."

    except imaplib.IMAP4.error as e:
        print(f"ERROR: IMAP error occurred: {e}")
        return None, f"IMAP error: {e}"
    except ConnectionRefusedError as e:
         print(f"ERROR: IMAP connection refused: {e}")
         return None, f"IMAP connection refused ({ZOHO_IMAP_SERVER}:{ZOHO_IMAP_PORT})"
    except Exception as e:
        # Catch other potential errors (network, parsing, etc.)
        import traceback
        print(f"ERROR: An unexpected error occurred during email processing: {e}")
        print(traceback.format_exc()) # Print stack trace for debugging
        return None, f"An unexpected server error occurred: {e}"

    finally:
        # Ensure logout happens even if errors occurred
        if mail and mail.state == 'SELECTED':
            try:
                mail.close()
                print("IMAP inbox closed.")
            except Exception as e:
                 print(f"WARN: Error closing IMAP inbox: {e}")
        if mail and mail.state != 'LOGOUT':
             try:
                 mail.logout()
                 print("IMAP logout successful.")
             except Exception as e:
                 print(f"WARN: Error during IMAP logout: {e}")