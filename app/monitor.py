import os
import argparse
import dropbox
from dropbox.exceptions import AuthError, BadInputError
from twilio.rest import Client
import time
import datetime

# Load environment variables
DROPBOX_TOKEN = os.getenv('DROPBOX_TOKEN')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
PHONE_NUMBERS = os.getenv('PHONE_NUMBERS').split(',')
ALERT_THRESHOLD = float(os.getenv('ALERT_THRESHOLD', '80'))  # Default value: 80
WARNING_THRESHOLD = float(os.getenv('WARNING_THRESHOLD', '90'))  # Default value: 90
CRITICAL_THRESHOLD = float(os.getenv('CRITICAL_THRESHOLD', '95'))  # Default value: 95
MAX_ALERTS = int(os.getenv('MAX_ALERTS', '10'))  # Default value: 10

# Variables used for rate limiting and to control number of alerts/warnings sent
hourly_counter = 0
hour_start_time = datetime.datetime.now().hour
alert_sent = 0
warning_sent = 0


def convert_bytes_to_readable(bytes_number):
    """
    Convert given number of bytes to a human-readable format.
    """
    for unit in ['', 'KB', 'MB', 'GB', 'TB']:
        if bytes_number < 1024.0:
            return f"{bytes_number:3.1f}{unit}"
        bytes_number /= 1024.0
    return f"{bytes_number:.1f}PB"



def authenticate_dropbox(token):
    """
    Authenticate to Dropbox with the given token.
    Exit the script if authentication fails.
    """
    dbx = dropbox.Dropbox(token)
    try:
        # This will fail if the token is incorrect or is team scoped
        dbx.users_get_current_account()
    except BadInputError:
        # Handle team-scoped token
        print("Detected team-scoped token. Proceeding with admin privileges...")
        team = dropbox.DropboxTeam(token)
        
        # Find the admin of the team
        result = team.team_members_list()
        admin_id = [member.profile.team_member_id for member in result.members 
                        if member.role.is_team_admin()][0]
        dbx = team.as_user(admin_id)
    
    except AuthError as e:
        print("ERROR: Invalid access token; try re-generating an access token.")
        exit()
    
    return dbx



def authenticate_twilio(account_sid, auth_token):
    """
    Authenticate to Twilio with the given credentials.
    """
    return Client(account_sid, auth_token)


def retrieve_storage_info(dropbox_client, verbose):
    if verbose:
        print("Retrieving storage info...")

    # Fetching space usage details
    usage = dropbox_client.users_get_space_usage()

    if usage.allocation.is_individual():
        allocated = usage.allocation.get_individual().allocated
    else: # team scope
        allocated = usage.allocation.get_team().allocated
    
    if verbose:
        print(f"Fetched details: Used = {convert_bytes_to_readable(usage.used)}, Allocated = {convert_bytes_to_readable(allocated)}")
    return usage


def run_once(dropbox_client, twilio_client, verbose):
    """
    Run the script once:
    - Read the Dropbox storage usage
    - Compare against thresholds and send Twilio alerts if appropriate
    """
    # Current storage details fetched from Dropbox
    storage_info = retrieve_storage_info(dropbox_client, verbose)
    # Calculate percentage
    delta = None
    alert_if_needed(storage_info, delta, twilio_client, verbose)


def run_daemon(dropbox_client, twilio_client, verbose):
    """
    Run the script as a daemon:
    - Continuously (every 5 minutes) read the Dropbox storage usage
    - Compare usage against thresholds and send Twilio alerts if appropriate
    """
    prev_storage_info = None  # store the previous storage info to calculate delta
    while True:
        curr_storage_info = retrieve_storage_info(dropbox_client, verbose)
        if prev_storage_info is not None:
            delta = calculate_delta(prev_storage_info, curr_storage_info)
        else:
            delta = None
        
        prev_storage_info = curr_storage_info
        alert_if_needed(curr_storage_info, delta, twilio_client, verbose)
        time.sleep(300)


def calculate_delta(prev_storage_info, curr_storage_info):
    return curr_storage_info.used - prev_storage_info.used


def send_alert(twilio_client, alert_type, delta_msg, storage_used_readable, usage_pc):
    """
    Send the alert message using Twilio API
    """

    # Include storage in percentage and human-readable format
    if alert_type == 'critical':
        msg_body = f"CRITICAL ALERT: Dropbox storage usage is at or above {usage_pc}% ({storage_used_readable}).{delta_msg}"
    elif alert_type == 'warning':
        msg_body = f"WARNING: Dropbox storage usage is at or above {usage_pc}% ({storage_used_readable}).{delta_msg}"
    else:  # alert_type == 'alert'
        msg_body = f"ALERT: Dropbox storage usage is at or above {usage_pc}% ({storage_used_readable}).{delta_msg}"

    for phone_number in PHONE_NUMBERS:
        message = twilio_client.messages.create(
            body=msg_body,
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        print(f"Alert sent to {phone_number}.")


def alert_if_needed(storage_info, delta, twilio_client, verbose):
    global hourly_counter, hour_start_time, alert_sent, warning_sent

    if storage_info.allocation.is_individual():
        allocated = storage_info.allocation.get_individual().allocated
    else: # team scope
        allocated = storage_info.allocation.get_team().allocated

    usage_pc = (float(storage_info.used) / allocated) * 100

    # Convert usage to human-readable format
    storage_used_readable = convert_bytes_to_readable(storage_info.used)

    if verbose:
        print(f"Current storage usage is {usage_pc}% ({storage_used_readable}).")

    # reset counters if new hour
    current_hour = datetime.datetime.now().hour
    if current_hour != hour_start_time:
        hourly_counter = 0
        hour_start_time = current_hour
        alert_sent = 0
        warning_sent = 0

    if hourly_counter >= MAX_ALERTS:
        if verbose:
            print("Maximum number of messages per hour reached. Not sending more alerts this hour.")
        return

    # Send alerts based on threshold values
    delta_msg = f". Storage use change from last check: {delta}" if delta else ""

    if usage_pc >= CRITICAL_THRESHOLD:  # critical, sends every time
        if verbose:
            print("Current storage usage exceeds critical threshold. Sending critical alert...")
        send_alert(twilio_client, "critical", delta_msg, storage_used_readable, usage_pc)
        hourly_counter += 1
    elif usage_pc >= WARNING_THRESHOLD:  # warning, sends twice
        if warning_sent < 2:
            if verbose:
                print("Current storage usage exceeds warning threshold. Sending warning...")
            send_alert(twilio_client, "warning", delta_msg, storage_used_readable, usage_pc)
            hourly_counter += 1
            warning_sent += 1
    elif usage_pc >= ALERT_THRESHOLD:  # alert, sends once
        if not alert_sent:
            if verbose:
                print("Current storage usage exceeds alert threshold. Sending alert...")
            send_alert(twilio_client, "alert", delta_msg, storage_used_readable, usage_pc)
            hourly_counter += 1
            alert_sent = 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--one-shot",
        action='store_true',
        default=False,
        help='Run the script once and exit')
    parser.add_argument(
        "-v",
        action='store_true',
        default=False,
        help="Show verbose output")
    args = parser.parse_args()

    dropbox_client = authenticate_dropbox(DROPBOX_TOKEN)
    twilio_client = authenticate_twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

    if args.one_shot:
        run_once(dropbox_client, twilio_client, args.v)
    else:
        run_daemon(dropbox_client, twilio_client, args.v)


if __name__ == '__main__':
    main()
