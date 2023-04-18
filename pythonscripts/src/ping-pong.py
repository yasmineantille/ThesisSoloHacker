"""
Connects to the solo key device (starts to look for it from USB, then NFC),
and then calls the ping-pong extension.
For Windows, the native WebAuthn API is used.
"""
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, WindowsClient, UserInteraction
from fido2.server import Fido2Server
from getpass import getpass
import sys
import ctypes


# Handle user interaction
class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        return getpass("Enter PIN: ")

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True


# Use the Windows WebAuthn API if available, and we're not running as admin
if WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin():
    client = WindowsClient("https://example.com")
else:
    # Locate a device
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is not None:
        print("Use USB HID channel.")
    else:
        print("No FIDO USB device found")
        sys.exit(1)

    # Set up a FIDO 2 client using the origin https://example.com
    client = Fido2Client(dev, "https://example.com", user_interaction=CliInteraction())

    # Prefer UV if supported and configured
    # if client.info.options.get("uv") or client.info.options.get("pinUvAuthToken"):
    #     uv = "preferred"
    #     print("Authenticator supports User Verification")


server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="direct")

user = {"id": b"user_id", "name": "SoloKeys User"}

result = client.ping_pong()

# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user, user_verification="discouraged", authenticator_attachment="cross-platform"
)

# Create a credential
result = client.make_credential(create_options["publicKey"])

# Complete registration
auth_data = server.register_complete(
    state, result.client_data, result.attestation_object
)
credentials = [auth_data.credential_data]

print("New credential created!")

print("CLIENT DATA:", result.client_data)
print("ATTESTATION OBJECT:", result.attestation_object)
print()
print("CREDENTIAL DATA:", auth_data.credential_data)


# Prepare parameters for getAssertion
request_options, state = server.authenticate_begin(credentials, user_verification=uv)

# Authenticate the credential
result = client.get_assertion(request_options["publicKey"])

# Only one cred in allowCredentials, only one response.
result = result.get_response(0)

# Complete authenticator
server.authenticate_complete(
    state,
    credentials,
    result.credential_id,
    result.client_data,
    result.authenticator_data,
    result.signature,
)
