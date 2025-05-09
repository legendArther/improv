import os
import requests # Not used in the OTP part, but kept if you have other routes
import json     # Not explicitly used in OTP part, but good to have for Flask
import imaplib
import email
import re
import traceback # For detailed error logging
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
from flask_cors import CORS # Import CORS

app = Flask(__name__)

# --- Configure CORS ---
# Allows all origins. For production, be more specific:
# Example: cors = CORS(app, resources={r"/get_otp": {"origins": "chrome-extension://YOUR_EXTENSION_ID"}})
CORS(app)

# --- Configuration ---
# Get sensitive keys from environment variables
APP_SECRET_KEY = os.getenv('APP_SECRET_KEY')
ZOHO_IMAP_USER = os.getenv('ZOHO_IMAP_USER')
ZOHO_IMAP_PASSWORD = os.getenv('ZOHO_IMAP_PASSWORD') # Ensure this is set in your environment

# --- Hardcoded Values ---
ZOHO_IMAP_SERVER = "imap.zoho.com"
ZOHO_IMAP_PORT = 993

# --- Helper Function to Check Server Configuration ---
def check_config():
    """Checks if required environment variables are set."""
    errors = []
    if not APP_SECRET_KEY:
        errors.append("APP_SECRET_KEY environment variable not set.")
    if not ZOHO_IMAP_USER:
        errors.append("ZOHO_IMAP_USER environment variable not set.")
    if not ZOHO_IMAP_PASSWORD: # Added this check
        errors.append("ZOHO_IMAP_PASSWORD environment variable not set.")

    if errors:
        full_error_message = "Server configuration error: " + "; ".join(errors)
        print(f"CRITICAL SERVER ERROR: {full_error_message}")
        return False, jsonify({"success": False, "error": full_error_message}), 500
    return True, None, None

# --- Default Route ---
@app.route('/')
def home():
    """Simple welcome message for the root URL."""
    return jsonify({"message": "OTP Service Ready."}), 200

# --- Secure GET Route for OTP ---
@app.route('/get_otp', methods=['GET'])
def get_otp_route():
    config_ok, error_response, status_code = check_config()
    if not config_ok:
        return error_response, status_code

    # --- Authenticate Request to this Flask App (via Query Parameter) ---
    provided_secret = request.args.get('secret') # Get secret from query parameter
    if not provided_secret or provided_secret != APP_SECRET_KEY:
        print(f"WARN (/get_otp GET): Unauthorized attempt. Secret in query: '{provided_secret}'")
        return jsonify({"success": False, "error": "Unauthorized: Missing or invalid secret key."}), 401

    print(f"INFO (/get_otp GET): Authorized request for {ZOHO_IMAP_USER}. Fetching OTP.")
    # --- Call the Core OTP Logic ---
    otp, error_message = _get_latest_otp_from_email()

    if otp:
        print(f"SUCCESS (/get_otp GET): OTP found: {otp}")
        return jsonify({"success": True, "otp": otp}), 200
    else:
        print(f"ERROR (/get_otp GET): Failed to retrieve OTP. Reason: {error_message}")
        # Determine appropriate status code
        response_status_code = 500 # Default Internal Server Error
        if error_message: # Check if error_message is not None
            if "login failed" in error_message.lower() or "connection refused" in error_message.lower():
                response_status_code = 503 # Service Unavailable (IMAP problem)
            elif "inbox empty" in error_message.lower() or "could not find 6-digit otp" in error_message.lower() or "otp not found" in error_message.lower():
                response_status_code = 404 # Not Found
        return jsonify({"success": False, "error": error_message or "Failed to retrieve OTP due to an unknown server error."}), response_status_code


# --- Core Logic Function (Read OTP from Email) ---
# Using the more robust version that checks the last two emails.
def _get_latest_otp_from_email():
    mail = None
    try:
        print(f"Attempting IMAP connection to {ZOHO_IMAP_SERVER}:{ZOHO_IMAP_PORT} for user {ZOHO_IMAP_USER}")
        mail = imaplib.IMAP4_SSL(ZOHO_IMAP_SERVER, ZOHO_IMAP_PORT)
        typ, account_details = mail.login(ZOHO_IMAP_USER, ZOHO_IMAP_PASSWORD) # Use ZOHO_IMAP_PASSWORD
        if typ != 'OK':
            print(f"ERROR: IMAP login failed for {ZOHO_IMAP_USER}. Response: {account_details}")
            return None, f"IMAP login failed for {ZOHO_IMAP_USER}"
        print("IMAP login successful.")

        typ, data = mail.select("inbox")
        if typ != 'OK':
            print(f"ERROR: Failed to select inbox. Response: {data}")
            if mail and mail.state != 'LOGOUT': mail.logout()
            return None, "Failed to select inbox."
        print("Inbox selected.")

        result, data = mail.search(None, "ALL") # Search all emails
        if result != 'OK':
            print(f"ERROR: Failed to search inbox. Response: {data}")
            if mail and mail.state != 'LOGOUT': mail.logout()
            return None, "Failed to search inbox."

        all_ids_bytes = data[0].split()
        if not all_ids_bytes:
            print("INFO: Inbox is empty.")
            if mail and mail.state != 'LOGOUT': mail.logout()
            return None, "Inbox empty, no email found."

        ids_to_check_bytes = all_ids_bytes[-2:] # Get the last two IDs (or fewer if less than 2 emails exist)
        ids_to_check_bytes.reverse() # Process newest first

        print(f"INFO: Checking up to {len(ids_to_check_bytes)} latest email(s)... IDs: {[id_b.decode() for id_b in ids_to_check_bytes]}")

        for email_id_bytes in ids_to_check_bytes:
            email_id_str = email_id_bytes.decode()
            print(f"\n--- Processing Email ID: {email_id_str} ---")

            result, msg_data = mail.fetch(email_id_bytes, "(RFC822)")
            if result != 'OK':
                print(f"ERROR: Failed to fetch email ID {email_id_str}. Response: {msg_data}. Skipping.")
                continue

            msg = email.message_from_bytes(msg_data[0][1])
            print(f"Email ID {email_id_str} Subject:", msg["subject"])

            body_text = None
            if msg.is_multipart():
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
                            body_text = part_text
                            break # Prefer plain text, stop processing parts for this email
                        elif content_type == "text/html":
                            if body_text is None: # Only use HTML if plain text not found yet
                                soup = BeautifulSoup(part_text, "html.parser")
                                body_text = soup.get_text()
                    except Exception as e:
                        print(f"WARN: Could not decode/process part {content_type} for email {email_id_str}. Error: {e}")
            else: # Not multipart
                content_type = msg.get_content_type()
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        charset = msg.get_content_charset() or 'utf-8'
                        msg_text = payload.decode(charset, errors='replace')
                        if "text/" in content_type: # Broad check for text types
                           if content_type == "text/html":
                               soup = BeautifulSoup(msg_text, "html.parser")
                               body_text = soup.get_text()
                           else: # Assume plain text or treat others as plain
                               body_text = msg_text
                except Exception as e:
                    print(f"WARN: Could not decode/process non-multipart body for email {email_id_str}. Error: {e}")

            if not body_text:
                print(f"INFO: No readable email body found for email ID {email_id_str}. Checking next (if any).")
                continue

            # print(f"--- Body Text Extracted (Email ID: {email_id_str}) ---")
            # print(repr(body_text[:1000]) + ('...' if len(body_text) > 1000 else ''))
            # print("--- End Body Text ---")

            otp_match = re.search(r'(?<!\d)(\d{6})(?!\d)', body_text) # Look for 6 digits not surrounded by other digits
            if otp_match:
                otp = otp_match.group(1)
                print(f"SUCCESS: Found 6-digit OTP: {otp} in email ID {email_id_str}")
                if mail and mail.state != 'LOGOUT': mail.logout()
                return otp, None
            else:
                print(f"INFO: Could not find 6-digit OTP in email ID {email_id_str}. Checking next (if any).")

        print(f"ERROR: OTP not found after checking the last {len(ids_to_check_bytes)} email(s).")
        if mail and mail.state != 'LOGOUT': mail.logout()
        return None, f"Could not find 6-digit OTP in the last {len(ids_to_check_bytes)} email(s)."

    except imaplib.IMAP4.error as e:
        print(f"ERROR: IMAP error occurred: {e}")
        if mail and mail.state != 'LOGOUT':
             try: mail.logout()
             except: pass # Ignore errors during logout after another error
        return None, f"IMAP error: {e}"
    except ConnectionRefusedError as e:
         print(f"ERROR: IMAP connection refused: {e}")
         return None, f"IMAP connection refused ({ZOHO_IMAP_SERVER}:{ZOHO_IMAP_PORT})"
    except Exception as e:
        print(f"ERROR: An unexpected error occurred during email processing: {e}")
        print(traceback.format_exc()) # Print stack trace
        if mail and mail.state != 'LOGOUT':
             try: mail.logout()
             except: pass
        return None, f"An unexpected server error occurred: {e}"
    finally:
        if mail and mail.state != 'LOGOUT':
            print("INFO: Ensuring IMAP logout in finally block.")
            try:
                if mail.state == 'SELECTED': mail.close() # Close selected mailbox if open
                mail.logout()
                print("IMAP final logout successful.")
            except Exception as e:
                 print(f"WARN: Error during final IMAP logout/close: {e}")


if __name__ == '__main__':
    config_ok, _, _ = check_config()
    if not config_ok:
        print("CRITICAL: Server cannot start due to missing configuration. Please set environment variables and restart.")
        # import sys
        # sys.exit(1) # Optionally exit if config is bad

    port = int(os.environ.get("PORT", 5000))
    # For production, use a WSGI server like Gunicorn: gunicorn -w 4 -b 0.0.0.0:5000 app:app
    app.run(host='0.0.0.0', port=port, debug=True) # Set debug=False for production