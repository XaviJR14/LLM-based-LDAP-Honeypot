import requests
import json

# Replace with the actual ngrok URL provided by your session, but mantain /receive_data
NGROK_URL = "https://d5aff180ae3b.ngrok-free.app/receive_data"

def send_ldap_to_colab(ldap_message):
    """
    Send an LDAP message (in JSON format) to the LLM endpoint.
    Reads the response as a stream of JSON objects, one per line.
    """
    entries: list[str] = []
    try:
        # Enable streaming so we can iterate line by line
        response = requests.post(NGROK_URL, json=ldap_message, timeout=600, stream=True)
        print("✅ HTTP status code:", response.status_code)

        # Iterate over each line in the streamed response
        for raw_line in response.iter_lines(decode_unicode=True):
            if not raw_line:
                continue

            try:
                entry = json.loads(raw_line)
                json_entry = json.dumps(entry, indent=2, ensure_ascii=False)
                entries.append(json_entry)
                print("📥 Received entry:")
                print(json_entry)
            except json.JSONDecodeError:
                print("⚠ Could not parse line as JSON:", raw_line)

    except Exception as e:
        print("❌ Error sending to server:", e)


    return entries

def main():
    """
    Example usage: send a sample LDAP searchRequest.
    """
    sample_search = {
        "messageID": 5,
        "protocolOp": {
            "searchRequest": {
                "baseObject": "",
                "scope": 0,
                "derefAliases": 0,
                "sizeLimit": 0,
                "timeLimit": 0,
                "typesOnly": False,
                "filter": {"present": "objectClass"},
                "attributes": ["*"]
            }
        }
    }
    send_ldap_to_colab(sample_search)

if __name__ == "__main__":
    main()
