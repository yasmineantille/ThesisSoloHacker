"""
Connects to the solo key USB device. For Windows, the native WebAuthn API is used.
"""
from fido2.ctap2.extensions import Ctap2Extension
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, WindowsClient, UserInteraction
from fido2.server import Fido2Server
from getpass import getpass
import sys
import ctypes


class PingPongExtension(Ctap2Extension):
    NAME = "ping-pong"

    def __init__(self, ctap, pin_protocol=None):
        super().__init__(ctap)
        self.pin_protocol = pin_protocol

    def process_create_input(self, inputs):
        return self.is_supported() and inputs.get(self.NAME)

    def process_create_output(self, auth_data):
        if self.NAME in auth_data.extensions:
            return {"ping-pong": auth_data.extensions.get(self.NAME)}


# Handle user interaction
class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        return getpass("Enter PIN: ")

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True

# TODO: Try on ubuntu if extensions is shown when connected to device

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

    print("got here")
    print(client.info.extensions)
    if "hmac-secret" in client.info.extensions:
        print("found hmac-secret extension")
    elif "ping-pong" in client.info.extensions:
        print("found hmac-secret extension")
    else:
        print("No Authenticator with the HmacSecret extension found!")

server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="direct")

# Prepare parameters for makeCredential
rp = {"id": "localhost", "name": "FIDO2 Extension Test"}
user = {"id": b"user_id", "name": "testUser", "displayName": "TestUser"}
pkcp = [{"type": "public-key", "alg": -7}]
challenge = b"Y2hhbGxlbmdl"

# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user,
    user_verification="discouraged",
    authenticator_attachment="cross-platform"
)

# Add CredBlob extension, attach data
options = dict(create_options["publicKey"])
options["extensions"] = {"ping-pong": "ping"}

# Request generation of a new credential in the authenticator
# with ping-pong extension
result = client.make_credential(options)

# # Complete registration
# auth_data = server.register_complete(
#     state, result.client_data, result.attestation_object
# )
# credentials = [auth_data.credential_data]
#
# print(result)
# print()
# print("EXTENSION RESULT")
# print(result.extension_results)
#
# # HmacSecret result:
# if not result.extension_results.get("ping-pong"):
#     print("Failed to create credential with ping-pong")
#     sys.exit(1)
