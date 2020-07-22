from argparse import ArgumentParser, RawTextHelpFormatter

arg_parse = ArgumentParser(prog='aws-cis-benchmarker',
                           description='Tool to benchmark your AWS environment against CIS',
                           usage='python3 %(prog)s [optional arguments]',
                           formatter_class=RawTextHelpFormatter)

arg_group = arg_parse.add_mutually_exclusive_group(required=True)

arg_group.add_argument('-c', '--csv', action='store_true',
                       help='Produces report in CSV format')

arg_group.add_argument('-ht', '--html', action='store_true',
                       help='Produces report in HTML format')

arg_group.add_argument('-j', '--json', action='store_true',
                       help='Produces report in JSON format')

arg_group.add_argument('-v', '--version', action='store_true',
                       help='Display version of the tool')

arg_parse.add_argument('-f', '--file_name', action='store', default='aws_cis_benchmark_output', type=str,
                       help='To store output with given file name')

arg_parse.add_argument('-p', '--path', action='store', default='.', type=str,
                       help='To store output in specified file path')
