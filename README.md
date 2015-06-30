# checkVT
This is Python script to calculate SH256 for all files under the defined file path and check the scanning results on VirusTotal.com

Usage: 

    checkVT.py [options]

Options:

    -h, --help                           Show basic help message and exit
    -s path, --sha256=path               Show hash(SHA256) values for file(s) to be analyzed
    -v file, --vt=file                   Show VT results for hash value(s) to be analyzed
    -c path, --checkVT=path              Show VT results for file(s) to be analyzed

Examples:

    checkVT.py -s c:\windows
    checkVT.py -v c:\users\administrator\desktop\hash_sha256.txt
    checkVT.py -c c:\windows

[!] to see help message of options run with '-h'

Before you run this script, you need to install a Python library "Beautiful Soup"
https://beautiful-soup-4.readthedocs.org/en/latest/
