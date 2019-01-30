import hashlib, sys, os, os.path, argparse, json
from api import ReverseIT_API

parser = argparse.ArgumentParser(description="Generate SHA256 hashes and optionally check them against the Reverse.it API")
parser.add_argument('file', help="Path to file to hash")
parser.add_argument('-a', '--api', default=False, action="store_true", help="Check SHA256 against API")
parser.add_argument('-m', '--mitre', default=False, action="store_true", help="Show MITRE info")
args = parser.parse_args()


def main_func():

    file_ = args.file
    API = args.api
    if not os.path.isfile(file_):
        print("The file does not exist")
        sys.exit(1)
    else:
        with open(file_, "rb") as hash_file:
            bytes = hash_file.read()
            sha256_hash = hashlib.sha256(bytes).hexdigest()
            hash_file.close()
        print("\n")
        print("[/] {} is a valid file".format(file_))
        print("\n")
        print("[/] SHA256 of file: {}".format(sha256_hash))
        print("\n")
        if API:
            check_api = ReverseIT_API()
            print("[/] Checking against API")
            api_response = check_api.search(sha256_hash)
            if api_response == []:
                print("No results for hash: {}".format(sha256_hash))
            else:
                json_respose = json.loads(api_response)
                for item in json_respose:
                    job_id = item['job_id']
                    rit_env = item['environment_description']
                    malware_type = item['type']
                    malware_name = item['submit_name']
                    threat_score = item['threat_score']
                    threat_level = item['threat_level']
                    verdict = item['verdict']
                    domains = ""
                    for domain in item['domains']:
                        domains += domain
                        domains += "\n"
                    processes_spawned = item['total_processes']

                    if args.mitre:
                        msg = """
Analysis for {} || SHA256: {}

Overall Stats:
==================================

Verdict: {}

Threat Score: {}

Threat Level: {}

==================================
Details:

Malware Name: {}

Malware Type: {}

Reverse IT Environment: {}

Total Number of Processes Spawned: {}

Domains Contacted:
{}

===================================

MITRE INFO:

                        """.format(str(file_), str(sha256_hash), verdict, str(threat_score), str(threat_level),\
                            str(malware_name), str(malware_type), str(rit_env), str(processes_spawned), str(domains))
                        for attack_type in item['mitre_attcks']:
                            tactic = attack_type['tactic']
                            technique = attack_type['technique']
                            attack_link = attack_type['attck_id_wiki']
                            formatted_msg = """

Tactic: {}

Technique: {}

Wiki Link: {}

                            """.format(str(tactic), str(technique), str(attack_link))
                            msg += formatted_msg
                        
                        print(msg)

                        
                    else:
                        msg = """
Analysis for {} || SHA256: {}

Overall Stats:
==================================

Verdict: {}

Threat Score: {}

Threat Level: {}

==================================
Details:

Malware Name: {}

Malware Type: {}

Reverse IT Environment: {}

Total Number of Processes Spawned: {}

Domains Contacted:

{}

                        """.format(str(file_), str(sha256_hash), verdict, str(threat_score), str(threat_level),\
                            str(malware_name), str(malware_type), str(rit_env), str(processes_spawned), str(domains))
                        
                        print(msg)



        else:
            print("[X] Not checking against API")


main_func()

