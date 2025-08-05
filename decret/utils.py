import os
from pathlib import Path
import re
import subprocess
import sys
import argparse
import jinja2
import requests
import pandas as pd
from requests.exceptions import RequestException
from decret.config import (
    CACHE_PATH,
    DEFAULT_PACKAGES,
    BEEFY_PACKAGES,
    DEFAULT_TIMEOUT,
    SUPPORTED_RELEASES,
    DEBIAN_RELEASES,
    RUNS_ON_GITHUB_ACTIONS,
    DOCKER_SHARED_DIR,
    FatalError,
)

# ====================== Requirements =========================


def check_program_is_present(
    progname: str, cmdline: list[str], fatal: bool = True
) -> bool:
    try:
        subprocess.run(cmdline, check=True, shell=False, capture_output=True)
        return True
    except subprocess.CalledProcessError as exc:
        if fatal:
            raise FatalError(
                f"{progname} does not seem to be installed. {cmdline} did not return 0."
            ) from exc
        return False


def check_requirements() -> None:
    check_program_is_present("Docker", ["docker", "-v"])


# ====================== Exploits =========================

FILE_PATH = "files_exploits.csv"
PROJECT_PATH = "exploit-database%2Fexploitdb"
URL = (
    f"https://gitlab.com/api/v4/projects/{PROJECT_PATH}"
    f"/repository/files/{FILE_PATH}/raw?ref=main"
)

HASH_PATH = CACHE_PATH / "files_exploits.hash"
CSV_PATH = CACHE_PATH / FILE_PATH


def db_is_up_to_date() -> tuple[bool, str]:
    """Returns a tuple indicating if the db is up to date and the new
    hash if so

    """

    head = requests.head(URL, timeout=DEFAULT_TIMEOUT)
    head.raise_for_status()
    blob_hash = head.headers["x-gitlab-blob-id"]

    stored_blob_hash = None

    try:
        with open(HASH_PATH, "r", encoding="utf-8") as file:
            stored_blob_hash = file.read()
    except FileNotFoundError:
        return (False, blob_hash)

    return (stored_blob_hash == blob_hash, blob_hash)


def download_db() -> None:
    # DOCS: https://docs.gitlab.com/api/repository_files/#get-file-metadata-only

    print("Cheking if the cache from exploit-db is up to date")

    try:
        up_to_date, blob_hash = db_is_up_to_date()
    except RequestException as error:
        print(f"Checking if the cache is up to date failed with {error}")
        return

    if not up_to_date:
        print("Proceeding to download files_exploits.csv from exploit-db")
    else:
        print("cache is up to date no need to download it")
        return

    try:
        response = requests.get(URL, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
    except RequestException as error:
        print(f"Failed GET request from {URL} with :\n{error}")
        return

    os.makedirs(CACHE_PATH, exist_ok=True)

    try:
        with open(CSV_PATH, "wb") as file:
            file.write(response.content)
        with open(HASH_PATH, "w", encoding="utf-8") as file:
            file.write(blob_hash)
        print("File downloaded and hash updated.")
    except IOError as error:
        print(f"Failed to write file: {error}")


def get_exploits(args):
    print("\nSearching for exploits on https://www.exploit-db.com/")
    print("The cached file is in: cached-files/files_exploits.csv")

    try:
        data = pd.read_csv(CACHE_PATH / FILE_PATH)
    except FileNotFoundError:
        download_db()
        try:
            data = pd.read_csv("cached-files/files_exploits.csv")
        except FileNotFoundError:
            print("Failed to download db")
            return

    data = data[["id", "file", "verified", "codes", "tags", "aliases"]]

    cve_id = f"CVE-{args.cve_number}"
    data = data[
        data["codes"].str.contains(cve_id, na=False)
        | data["tags"].str.contains(cve_id, na=False)
        | data["aliases"].str.contains(cve_id, na=False)
    ]
    data = list(zip(data["id"], data["file"], data["verified"]))

    output_dir = Path(args.directory)
    output_dir.mkdir(parents=True, exist_ok=True)

    if len(data) == 0:
        print("No exploits Found")
        return

    print(f"Found {len(data)} exploits:\n")

    for i, (exploit_id, path, verified) in enumerate(data):
        # Building url
        url = (
            f"https://gitlab.com/api/v4/projects/{PROJECT_PATH}"
            f"/repository/files/{path.replace('/', '%2F')}/raw?ref=main"
        )

        # Show sources
        print(f"https://www.exploit-db.com/exploits/{exploit_id}\n")

        # Building path
        file_extension = os.path.splitext(path)[1]
        exploit_filename = f"exploit_{i}_{exploit_id}"
        if verified:
            exploit_filename += "_verified"
        exploit_path = output_dir / Path(exploit_filename + file_extension)

        # Fetching exploits
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            os.makedirs(CACHE_PATH, exist_ok=True)
            with open(exploit_path, "wb") as file:
                file.write(response.content)
        else:
            print(f"Failed to download file: {response.status_code} - {response.text}")


# ====================== Version comparison =========================


def version_tuple(version_str: str):
    # Information on version convention:
    #   https://www.debian.org/doc/debian-policy/ch-controlfields.html#special-version-conventions
    # Removing epoch and revision
    # Could be a bit more robust if using epoch and revision
    if ":" in version_str:
        _, version_str = version_str.split(":", 1)

    parts = re.findall(r"\d+", version_str)
    result = tuple(int(number) for number in parts)
    return result


def version_distance(v1, v2):
    biggest_length = max(len(v1), len(v2))
    # Making tuples the same size
    v1 += (0,) * (biggest_length - len(v1))
    v2 += (0,) * (biggest_length - len(v2))

    paired_parts = enumerate(zip(v1, v2))

    # We sum the parts and add weight to different parts
    # So a bump from 1.2.0 to 1.2.15
    # is less important than a bump from
    # 1.2.0 to 1.3.0
    parts_distance = (
        abs(part1 - part2) * (100 ** (biggest_length - i - 1))
        for i, (part1, part2) in paired_parts
    )

    return sum(parts_distance)


# ====================== Arguments and Init =========================


def init_decret():  # pragma: no cover
    args = arg_parsing()
    check_requirements()
    if not args.do_not_use_sudo:
        if not check_program_is_present("Sudo", ["sudo", "-V"], fatal=False):
            print("Warning: sudo is absent. Activating --do-not-use-sudo.")
            args.do_not_use_sudo = True
    init_shared_directory(args)
    return args


def arg_parsing(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-n",
        "--number",
        dest="cve_number",
        type=str,
        help="A CVE number to search (e.g.: 2022-38392)",
        required=True,
    )
    parser.add_argument(
        "-r",
        "--release",
        dest="release",
        type=str,
        choices=DEBIAN_RELEASES,
        help="Debian Release name from 2005 to 2025",
    )
    parser.add_argument(
        "-d",
        "--directory",
        dest="dirname",
        type=str,
        help="Directory path for the CVE experiment",
        default="./default",
    )
    parser.add_argument(
        "--vulnerable-version",
        dest="vulnerable_version",
        type=str,
        help="Specify the vulnerable version number of the package",
    )
    parser.add_argument(
        "--bin_package",
        dest="bin_package",
        type=str,
        help="Name of the binary package targeted.",
    )
    parser.add_argument(
        "-c",
        "--choose",
        dest="choose",
        action="store_true",
        help="Manually choose a vulnerable configuration",
    )
    parser.add_argument(
        "--no-cache-lookup",
        dest="no_cache_lookup",
        action="store_true",
        help="Forces to search online, updates cache",
    )
    parser.add_argument(
        "--port",
        dest="port",
        type=int,
        help="Port forwarding between the Docker and the host",
    )
    parser.add_argument(
        "--host-port",
        dest="host_port",
        type=int,
        help="Set the host port in case of port forwarding (default is the --port value)",
    )
    parser.add_argument(
        "--do-not-use-sudo",
        dest="do_not_use_sudo",
        action="store_true",
        help="Do not use sudo to run docker commands",
    )
    parser.add_argument(
        "--beefy",
        dest="beefy",
        action="store_true",
        help="Installs more packages for easier analysis, see: config.py",
    )
    parser.add_argument(
        "--only-create-dockerfile",
        dest="only_create_dockerfile",
        action="store_true",
        help="Do not build nor run the created docker",
    )
    parser.add_argument(
        "--copy-exploits",
        dest="copy_exploits",
        action="store_true",
        help="Copy exploits instead of using shared dir",
    )
    parser.add_argument(
        "--dont-run",
        dest="dont_run",
        action="store_true",
        help="Do not build nor run the created docker",
    )
    parser.add_argument(
        "--run-lines",
        dest="run_lines",
        nargs="*",
        help="Add RUN lines to execute commands to finalize the environment",
    )
    parser.add_argument(
        "--cmd-line",
        dest="cmd_line",
        type=str,
        help="Change the CMD line to specify the command to run by default in the container",
    )

    namespace = parser.parse_args(args)

    if re.match(r"^CVE-2\d{3}-(0\d{3}|[1-9]\d{3,})$", namespace.cve_number):
        namespace.cve_number = namespace.cve_number[4:]
    elif not re.match(r"^2\d{3}-(0\d{3}|[1-9]\d{3,})$", namespace.cve_number):
        parser.print_usage(sys.stderr)
        raise FatalError("Wrong CVE format.")

    return namespace


# ====================== Docker =========================


def init_shared_directory(args):
    args.directory = Path(args.dirname)
    try:
        args.directory.mkdir(parents=True, exist_ok=True)
    except PermissionError as exc:
        raise FatalError(f"Error while creating {args.dirname}") from exc


def write_cmdline(args: argparse.Namespace):
    cmdline_path = args.directory / "cmdline"
    with cmdline_path.open("w", encoding="utf-8") as cmdline_file:
        args_to_write = []
        for arg in sys.argv:
            if " " in arg:
                arg = arg.replace(r"\\", r"\\")
                arg = arg.replace(r'"', r"\"")
                arg = f'"{arg}"'
            args_to_write.append(arg)
        cmdline_file.write(" ".join(args_to_write))
        cmdline_file.write("\n")


def prepare_sources(snapshot_id: str, vuln_fixed: bool):
    options = (
        "[check-valid-until=no allow-insecure=yes allow-downgrade-to-insecure=yes]"
    )
    url = f"http://snapshot.debian.org/archive/debian/{snapshot_id}/"
    if vuln_fixed:
        release = ["testing", "stable", "unstable"]
        return [f"deb {options} {url} {rel} main" for rel in release]
        # If vuln is unfixed we don't write to
        # sources.list.d/snapshot.list
        # We just take the latest relase we find
    return []


# pylint: disable=too-many-locals
def write_dockerfile(args: argparse.Namespace, cve_list, source_lines: list[str]):
    target_dockerfile = args.directory / "Dockerfile"
    decret_rootpath = Path(__file__).resolve().parent
    src_template = decret_rootpath / "Dockerfile.template"
    template_content = src_template.read_text()
    template = jinja2.Environment().from_string(template_content)

    # This should cover up to jessie
    if args.release in DEBIAN_RELEASES[:7]:
        apt_flag = "--force-yes"
    else:
        apt_flag = "--allow-unauthenticated --allow-downgrades"

    if args.beefy:
        default_packages = " ".join(DEFAULT_PACKAGES + BEEFY_PACKAGES)
    else:
        default_packages = " ".join(DEFAULT_PACKAGES)

    binary_packages = []
    for cve in cve_list:
        if cve.release == args.release:
            for bin_name in cve.vulnerable[0].bin_names:
                bin_name_and_version = [bin_name + f"={cve.vulnerable[0].version}"]
                binary_packages.extend(bin_name_and_version)

    # Old reseases should only use the snapshot sources
    content = template.render(
        clear_sources=args.release not in SUPPORTED_RELEASES,
        debian_release=args.release,
        source_lines=source_lines,
        apt_flag=apt_flag,
        default_packages=default_packages,
        package_name=" ".join(binary_packages),
        run_lines=args.run_lines,
        cmd_line=args.cmd_line,
        copy_exploits=RUNS_ON_GITHUB_ACTIONS or args.copy_exploits,
    )
    target_dockerfile.write_text(content)


def build_docker(args):
    print("Building the Docker image.")
    # This is needed as we don't know in advance which release it will choose on its own
    prepend = "" if RUNS_ON_GITHUB_ACTIONS else f"{args.release}/"
    docker_image_name = f"{prepend}cve-{args.cve_number}"

    if args.do_not_use_sudo:
        build_cmd = []
    else:
        build_cmd = ["sudo"]

    build_cmd.extend(["docker", "build"])
    build_cmd.extend(["--progress", "plain"])
    build_cmd.extend(["-t", docker_image_name])
    build_cmd.append(args.dirname)

    try:
        subprocess.run(build_cmd, check=True)
    except subprocess.CalledProcessError as exc:
        raise FatalError("Error while building the container") from exc


def run_docker(args):
    docker_image_name = f"{args.release}/cve-{args.cve_number}"
    print(f"Running the Docker. The shared directory is '{DOCKER_SHARED_DIR}'.")

    if args.do_not_use_sudo:
        run_cmd = []
    else:
        run_cmd = ["sudo"]
    run_cmd.extend(["docker", "run", "--privileged", "-it", "--rm"])
    run_cmd.extend(["-v", f"{args.directory.absolute()}:{DOCKER_SHARED_DIR}"])
    run_cmd.extend(["-h", f"cve-{args.cve_number}"])
    run_cmd.extend(["--name", f"cve-{args.cve_number}"])
    if args.port:
        if args.host_port:
            run_cmd.extend(["-p" f"{args.host_port}:{args.port}"])
        else:
            run_cmd.extend(["-p" f"{args.port}:{args.port}"])
    run_cmd.append(docker_image_name)

    try:
        subprocess.run(run_cmd, check=True)
    except subprocess.CalledProcessError as exc:
        raise FatalError("Error while running the container") from exc
