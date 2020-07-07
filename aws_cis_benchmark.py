from constants.argumentsparser import arg_parse
from benchmark import iam, logging, monitoring, networking


def main():
    parsed = arg_parse.parse_args()

    if parsed.json:
        # print(iam.get_cred_report()[0])
        print(iam.control_1_21_intial_access_keys_setup())


if __name__ == "__main__":
    main()
