import json, requests, config

class ReverseIT_API():
    # API Settings
    API_KEY = config.API_KEY
    API_URL = config.API_URL
    # User Agent Settings

    USER_AGENT = "BHI Reverse IT Tool"
    USER_AGENT_HEADER = {'User-Agent': USER_AGENT}


    headers = {
        'User-Agent': USER_AGENT,
        'Content-Type': "application/x-www-form-urlencoded",
        'api-key': API_KEY
        }

    def search(self, hash):
        URL = self.API_URL+"/search/hash"
        params = {'hash': hash}
        r = requests.post(URL, data=params, headers=self.headers)
        return(r.text)

        
        

if 'name' == '__main__':
    ReverseIT_API()