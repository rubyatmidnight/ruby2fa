import base64
import urllib.parse
import sys
from google.protobuf import json_format
import addtl.OtpMigration_pb2 as OtpMigration_pb2

# --- Helper to parse otpauth-migration URI ---
def parseMigrationUri(uri):
    if uri.startswith('otpauth-migration://'):
        data = urllib.parse.parse_qs(urllib.parse.urlparse(uri).query).get('data', [None])[0]
        if not data:
            raise ValueError('No data param!')
        raw = base64.urlsafe_b64decode(data + '==')
        payload = OtpMigration_pb2.MigrationPayload()
        payload.ParseFromString(raw)
        return payload
    raise ValueError('Not a migration URI!')

# --- Main: print all secrets ---
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python importGoogleAuth.py <otpauth-migration-uri>')
        sys.exit(1)
    uri = sys.argv[1]
    payload = parseMigrationUri(uri)
    for acc in payload.otp_parameters:
        secret = base64.b32encode(acc.secret).decode('utf-8').replace('=', '')
        print(f'Label: {acc.name}\nIssuer: {acc.issuer}\nSecret: {secret}\nType: {OtpMigration_pb2.OtpType.Name(acc.type)}\nDigits: {OtpMigration_pb2.DigitCount.Name(acc.digits)}\nAlgo: {OtpMigration_pb2.Algorithm.Name(acc.algorithm)}\n---')