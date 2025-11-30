import argparse
import base64
import gzip
import hashlib
import uuid
import lorem
import os
import croniter
import json
import yaml
import jwt
import re
import time
import urllib.parse
import html
import difflib
from colorama import init, Fore

# Initialize colorama for colored output
init(autoreset=True)

def anakin_logo():
    logo = r"""
  ______          _______              _
 |  ____|   /\   |__   __|            (_)
 | |__     /  \     | |_ __ __ _ _ __  _ _ __   __ _
 |  __|   / /\ \    | | '__/ _` | '_ \| | '_ \ / _` |
 | |____ / ____ \   | | | | (_| | | | | | | | | (_| |
 |______/_/    \_\  |_|_|  \__,_|_| |_|_|_| |_|\__, |
                                               __/ |
                                              |___/
    """
    print(Fore.GREEN + logo)

def base64_encode(text):
    return base64.b64encode(text.encode()).decode()

def base64_decode(encoded_text):
    return base64.b64decode(encoded_text).decode()

def gzip_compress(text):
    return gzip.compress(text.encode()).decode()

def gzip_decompress(compressed_text):
    return gzip.decompress(compressed_text.encode()).decode()

def generate_hash(text, algorithm='sha256'):
    hash_object = hashlib.new(algorithm, text.encode())
    return hash_object.hexdigest()

def generate_uuid():
    return str(uuid.uuid4())

def generate_lorem_ipsum(words=0, sentences=0, paragraphs=0):
    lorem_text = ""
    if words:
        lorem_text += " ".join(lorem.words(words))
    elif sentences:
        lorem_text += " ".join(lorem.sentences(sentences))
    elif paragraphs:
        lorem_text += "\n\n".join(lorem.paragraphs(paragraphs))
    return lorem_text

def calculate_checksum(filename):
    if not os.path.exists(filename):
        return "File not found."
    with open(filename, "rb") as file:
        checksum = hashlib.md5()
        while chunk := file.read(8192):
            checksum.update(chunk)
    return checksum.hexdigest()

def parse_cron(cron_expression):
    cron = croniter.croniter(cron_expression)
    schedule = []
    for _ in range(5):  # Get the next 5 scheduled occurrences
        schedule.append(cron.get_next())
    return schedule

def format_json(input_file, output_file):
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        return "JSON formatted and saved successfully."
    except Exception as e:
        return f"Error: {e}"

def convert_json_yaml(input_file, output_file):
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
        with open(output_file, 'w') as f:
            yaml.dump(data, f)
        return "JSON to YAML conversion successful."
    except Exception as e:
        return f"Error: {e}"

def convert_yaml_json(input_file, output_file):
    try:
        with open(input_file, 'r') as f:
            data = yaml.safe_load(f)
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        return "YAML to JSON conversion successful."
    except Exception as e:
        return f"Error: {e}"

def decode_jwt(token):
    try:
        decoded_token = jwt.decode(token, verify=False)
        return decoded_token
    except jwt.exceptions.DecodeError:
        return "Invalid JWT token."

def compress_image(input_file, output_file):
    try:
        from PIL import Image
        img = Image.open(input_file)
        img.save(output_file, optimize=True)
        return "Image compressed successfully."
    except Exception as e:
        return f"Error: {e}"

def test_regex(pattern, text):
    matches = re.findall(pattern, text)
    return matches if matches else "No matches found."

def convert_unix_timestamp(time_str):
    try:
        timestamp = int(time_str)
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))
    except ValueError:
        return "Invalid Unix timestamp."

def string_utilities(text, case=None):
    if case == "lower":
        return text.lower()
    elif case == "upper":
        return text.upper()
    else:
        return "Invalid case specified. Use 'lower' or 'upper'."

def url_encode(text):
    return urllib.parse.quote(text)

def url_decode(text):
    return urllib.parse.unquote(text)

def html_encode(input_file, output_file):
    try:
        with open(input_file, 'r') as f:
            html_text = f.read()
        encoded_html = html.escape(html_text)
        with open(output_file, 'w') as f:
            f.write(encoded_html)
        return "HTML encoded successfully."
    except Exception as e:
        return f"Error: {e}"

def compare_text(text1, text2):
    text1_lines = text1.splitlines(keepends=True)
    text2_lines = text2.splitlines(keepends=True)
    d = difflib.Differ()
    diff = d.compare(text1_lines, text2_lines)
    return ''.join(diff)

def escape_text(text):
    return text.encode('unicode_escape').decode()

def unescape_text(text):
    return bytes(text, 'utf-8').decode('unicode_escape')

def number_base_converter(number, from_base, to_base):
    try:
        number = int(str(number), int(from_base))
        return format(number, f'0{str(to_base)}X').lower()
    except ValueError:
        return "Invalid input."

def init_directory_structure(base_dir=None):
    """Create the standard directory structure in ~/code/ or current directory if base_dir is provided"""
    if base_dir is None:
        home_dir = os.path.expanduser("~")
        code_dir = os.path.join(home_dir, "code")
    else:
        code_dir = os.path.abspath(base_dir)

    # Define the directory structure
    structure = {
        "work": {
            "company-a": ["mobile-app", "backend-api"],
            "company-b": ["infra-k8s", "web-portal"]
        },
        "clients": {
            "client-x": ["pos-system"],
            "client-y": ["automation"]
        },
        "personal": ["portfolio", "learn-rust", "cv"],
        "freelance": {},
        "oss": {},
        "shared": {
            "infra": {},
            "scripts": {},
            "templates": {},
            "dotfiles": {}
        },
        "archive": {},
        "playground": {
            "test-nginx": {}
        }
    }

    created_dirs = []
    skipped_dirs = []

    def create_dirs(base_path, dir_structure):
        """Recursively create directories from structure"""
        for dir_name, subdirs in dir_structure.items():
            dir_path = os.path.join(base_path, dir_name)

            if os.path.exists(dir_path):
                skipped_dirs.append(dir_path)
            else:
                try:
                    os.makedirs(dir_path, exist_ok=True)
                    created_dirs.append(dir_path)
                except OSError as e:
                    print(f"Error creating {dir_path}: {e}")
                    continue

            # If subdirs is a dict, recurse; if it's a list, create those dirs
            if isinstance(subdirs, dict):
                create_dirs(dir_path, subdirs)
            elif isinstance(subdirs, list):
                for subdir in subdirs:
                    subdir_path = os.path.join(dir_path, subdir)
                    if os.path.exists(subdir_path):
                        skipped_dirs.append(subdir_path)
                    else:
                        try:
                            os.makedirs(subdir_path, exist_ok=True)
                            created_dirs.append(subdir_path)
                        except OSError as e:
                            print(f"Error creating {subdir_path}: {e}")

    # Create the base code directory if it doesn't exist (only for ~/code/, not for --here)
    if base_dir is None and not os.path.exists(code_dir):
        os.makedirs(code_dir, exist_ok=True)
        created_dirs.append(code_dir)

    # Create the directory structure
    create_dirs(code_dir, structure)

    # Print results
    print(Fore.GREEN + f"Directory structure initialized in {code_dir}")
    if created_dirs:
        print(Fore.CYAN + f"\nCreated {len(created_dirs)} directories:")
        for dir_path in created_dirs:
            print(Fore.CYAN + f"  ✓ {dir_path}")
    if skipped_dirs:
        print(Fore.YELLOW + f"\nSkipped {len(skipped_dirs)} existing directories:")
        for dir_path in skipped_dirs[:10]:  # Show first 10
            print(Fore.YELLOW + f"  - {dir_path}")
        if len(skipped_dirs) > 10:
            print(Fore.YELLOW + f"  ... and {len(skipped_dirs) - 10} more")

def handle_legacy_commands(args):
    """Handle all the legacy positional argument commands"""
    if args.base64:
        if args.base64 == "-e":
            print(base64_encode(args.string))
        elif args.base64 == "-d":
            print(base64_decode(args.string))

    if args.image64:
        if args.image64 == "-e":
            print("Image encoding is not implemented yet.")
        elif args.image64 == "-d":
            print("Image decoding is not implemented yet.")

    if args.gzip:
        if args.gzip == "-e":
            print(gzip_compress(args.gzip_string))
        elif args.gzip == "-d":
            print(gzip_decompress(args.gzip_string))

    if args.hash:
        print(generate_hash(args.hash_string, args.hash))

    if args.uuid is not None:
        print(generate_uuid())

    if args.words or args.sentences or args.paragraphs:
        print(generate_lorem_ipsum(args.words, args.sentences, args.paragraphs))

    if args.checksum:
        print(calculate_checksum(args.checksum))

    if args.cron:
        print(parse_cron(args.cron))

    if args.json and len(args.json) >= 2:
        print(format_json(args.json[0], args.json[1]))

    if args.jy and len(args.jy) >= 2:
        if args.jy[0].endswith('.json') and args.jy[1].endswith('.yml'):
            print(convert_json_yaml(args.jy[0], args.jy[1]))
        elif args.jy[0].endswith('.yml') and args.jy[1].endswith('.json'):
            print(convert_yaml_json(args.jy[0], args.jy[1]))
        else:
            print("Invalid file extensions. Use either json/yml or yml/json.")

    if args.jwt:
        print(decode_jwt(args.jwt))

    if args.img and len(args.img) >= 2:
        print(compress_image(args.img[0], args.img[1]))

    if args.regex and len(args.regex) >= 2:
        print(test_regex(args.regex[0], args.regex[1]))

    if args.unix:
        if args.unix == "-e":
            print(int(time.mktime(time.strptime(args.time_string, '%Y-%m-%d %H:%M:%S'))))
        elif args.unix == "-d":
            print(convert_unix_timestamp(args.time_string))

    if args.string:
        print(string_utilities(args.string_value, args.string[1:]))

    if args.url:
        if args.url == "-e":
            print(url_encode(args.url_string))
        elif args.url == "-d":
            print(url_decode(args.url_string))

    if args.html and len(args.html) >= 2:
        print(html_encode(args.html[0], args.html[1]))

    if args.escape:
        if args.escape == "-e":
            print(escape_text(args.escape_text))
        elif args.escape == "-d":
            print(unescape_text(args.escape_text))

    if args.number and args.from_base and args.to_base:
        print(number_base_converter(args.number, args.from_base, args.to_base))

def main():
    import sys

    # Check if "init" is the first argument (after script name)
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        # Handle init command with argparse for --here flag
        parser = argparse.ArgumentParser(description="Anakin Init - Initialize directory structure", formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument("init", help="Initialize directory structure")
        parser.add_argument("--here", action="store_true", help="Create directories in current directory instead of ~/code/")
        args = parser.parse_args()

        anakin_logo()
        if args.here:
            init_directory_structure(base_dir=".")
        else:
            init_directory_structure()
        return

    # Legacy command handling - use the original parser
    parser = argparse.ArgumentParser(description="Anakin Command Line Utility", formatter_class=argparse.RawTextHelpFormatter)

    # Anakin logo
    anakin_logo()

    # Base64 Text Encoder/Decoder
    base64_group = parser.add_argument_group("Base64 Text Encoder/Decoder")
    base64_group.add_argument("base64", nargs='?', choices=["-e", "-d"], help="Base64 encode (-e) or decode (-d) a string")
    base64_group.add_argument("string", nargs='?', help="The string to encode/decode")

    # Base64 Image Encoder/Decoder
    image64_group = parser.add_argument_group("Base64 Image Encoder/Decoder")
    image64_group.add_argument("image64", nargs='?', choices=["-e", "-d"], help="Base64 encode (-e) or decode (-d) an image")
    image64_group.add_argument("image_string", nargs='?', help="The image string to encode/decode")

    # GZip Encoder/Decoder
    gzip_group = parser.add_argument_group("GZip Encoder/Decoder")
    gzip_group.add_argument("gzip", nargs='?', choices=["-e", "-d"], help="GZip compress (-e) or decompress (-d) a string")
    gzip_group.add_argument("gzip_string", nargs='?', help="The string to compress/decompress")

    # Hash Generator
    hash_group = parser.add_argument_group("Hash Generator")
    hash_group.add_argument("hash", nargs='?', choices=["md5", "sha1", "sha256"], help="The hashing algorithm (md5, sha1, sha256)")
    hash_group.add_argument("hash_string", nargs='?', help="The string to hash")

    # UUID Generator
    parser.add_argument("uuid", nargs='?', help="Generate a UUID")

    # Lorem Ipsum Generator
    lorem_group = parser.add_argument_group("Lorem Ipsum Generator")
    lorem_group.add_argument("-w", "--words", type=int, help="Generate Lorem Ipsum with a specific number of words")
    lorem_group.add_argument("-s", "--sentences", type=int, help="Generate Lorem Ipsum with a specific number of sentences")
    lorem_group.add_argument("-p", "--paragraphs", type=int, help="Generate Lorem Ipsum with a specific number of paragraphs")

    # Checksum File
    parser.add_argument("checksum", nargs='?', metavar="file", help="Calculate the MD5 checksum of a file")

    # Cron Parser
    parser.add_argument("cron", nargs='?', help="Parse and print the next 5 scheduled occurrences of a cron expression")

    # JSON Formatter
    json_formatter_group = parser.add_argument_group("JSON Formatter")
    json_formatter_group.add_argument("json", nargs='*', metavar=("input_file", "output_file"), help="Format JSON input_file and save to output_file")

    # JSON/YAML Converter
    json_yaml_group = parser.add_argument_group("JSON <> YAML Converter")
    json_yaml_group.add_argument("jy", nargs='*', metavar=("input_file", "output_file"), help="Convert JSON to YAML (input_file to output_file) or vice versa")

    # JWT Decoder
    parser.add_argument("jwt", nargs="?", help="Decode JWT token")

    # PNG/JPEG Compressor
    imgcomp_group = parser.add_argument_group("PNG/JPEG Compressor")
    imgcomp_group.add_argument("img", nargs='*', metavar=("input_file", "output_file"), help="Compress input_file (PNG/JPEG) and save to output_file")

    # Regular Expression Tester
    regex_group = parser.add_argument_group("Regular Expression Tester")
    regex_group.add_argument("regex", nargs='*', metavar=("pattern", "text"), help="Test regex pattern against text")

    # Unix Timestamp Converter
    unix_group = parser.add_argument_group("Unix Timestamp Converter")
    unix_group.add_argument("unix", nargs='?', choices=["-e", "-d"], help="Convert Unix timestamp to datetime (-e) or vice versa (-d)")
    unix_group.add_argument("time_string", nargs='?', help="The time string to convert")

    # String Utilities
    string_group = parser.add_argument_group("String Utilities")
    string_group.add_argument("string", nargs='?', choices=["-lower", "-upper"], help="Convert string to lowercase (-lower) or uppercase (-upper)")
    string_group.add_argument("string_value", nargs='?', help="The string to convert")

    # URL Encoder/Decoder
    url_group = parser.add_argument_group("URL Encoder/Decoder")
    url_group.add_argument("url", nargs='?', choices=["-e", "-d"], help="URL encode (-e) or decode (-d) a string")
    url_group.add_argument("url_string", nargs='?', help="The string to encode/decode")

    # HTML Encoder/Decoder
    html_group = parser.add_argument_group("HTML Encoder/Decoder")
    html_group.add_argument("html", nargs='*', metavar=("input_file", "output_file"), help="HTML encode input_file and save to output_file")

    # Text Comparer
    compare_group = parser.add_argument_group("Text Comparer")
    compare_group.add_argument("-s", "--string", nargs=2, metavar=("string1", "string2"), help="Compare two strings")
    compare_group.add_argument("-f", "--file", nargs=2, metavar=("file1", "file2"), help="Compare two text files")

    # Text Escape / Unescape
    escape_group = parser.add_argument_group("Text Escape / Unescape")
    escape_group.add_argument("escape", nargs='?', choices=["-e", "-d"], help="Text escape (-e) or unescape (-d)")
    escape_group.add_argument("escape_text", nargs='?', help="The text to escape/unescape")

    # Number Base Converter
    number_group = parser.add_argument_group("Number Base Converter")
    number_group.add_argument("number", nargs='?', help="The number to convert")
    number_group.add_argument("-f", "--from_base", help="The base of the input number")
    number_group.add_argument("-t", "--to_base", help="The base to convert to")

    args = parser.parse_args()
    handle_legacy_commands(args)

if __name__ == "__main__":
    main()
