import hashlib, sys, os, os.path, argparse
from api import ReverseIT_API

parser = argparse.ArgumentParser(description="Generate SHA256 hashes and optionally check them against the Reverse.it API")
parser.add_argument('file', help="Path to file to hash")
parser.add_argument('-a', '--api', default=False, action="store_true", help="Check SHA256 against API")
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
            print(check_api.search(sha256_hash))
        else:
            print("[X] Not checking against API")


main_func()


"""
if len(sys.argv) < 2:
    print(help_message())

elif len(sys.argv) > 1 and sys.argv[1] == "--help":
    print(help_message())

elif len(sys.argv) > 1 and sys.argv[1] == "-h":
    print(help_message())

elif len(sys.argv) > 1 and sys.argv[1] and sys.argv[2] != "-a" or sys.argv[2] != "--api":
    file_path = sys.argv[1]

    print(check_file(file_path))
"""