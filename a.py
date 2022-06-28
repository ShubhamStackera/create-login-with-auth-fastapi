import requests

id = "62badcc4c2c4ee20f83ba6a0"
url = "https://api-eu1.tatum.io/v3/offchain/account/" + id + "/address"

query = {
  "index": "2"
}

headers = {"x-api-key": "f8473d55-e8ed-4b94-9e4e-d9de9f7b8466"}

response = requests.post(url, headers=headers, params=query)

data = response.json()
print(data)