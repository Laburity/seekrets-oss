# Date: 29th August, 2024
# Authors: Laburity Research Team, Splint3r7, Hassan Khan Yusufzai
# Agenda: https://conference.hitb.org/hitbsecconf2024bkk/session/secret-scanning-in-open-source-at-scale/
# Speakers: https://conference.hitb.org/hitbsecconf2024bkk/speaker/hassan-khan-yusufzai/, https://conference.hitb.org/hitbsecconf2024bkk/speaker/danish-tariq/

#!/usr/bin/env python3

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import argparse
import shutil
import os, tarfile, zipfile, subprocess

def download_package(package_name):
    """
    Create an NPM JS downloadable Link.

    Args:
        package_name (str): NpmJS package name.

    Returns:
        str: The link to the download the package.

    """
    try:
        response = requests.get(f'https://registry.npmjs.org/{package_name}')
        if response.status_code == 200:
            latest_version = response.json()['dist-tags']['latest']
            if "@" in package_name:
                pack_name = package_name.split("/")[1]
                package_link = "https://registry.npmjs.org/{}/-/{}-{}.tgz".format(package_name,pack_name,latest_version)
            else:
                package_link = "https://registry.npmjs.org/{}/-/{}-{}.tgz".format(package_name,package_name,latest_version)
        else:
            pass
    except Exception as e:
        print(e)

    return package_link

def download_and_extract_package(url):

    """
    Download and extract the NPMJS package file.
    """
    package_name = url.split('/')[3]
    
    download_path = f"{package_name}.tgz"
    extract_path = os.path.join('extracted', package_name)
    
    os.makedirs('extracted', exist_ok=True)
    
    print(f"Downloading {package_name}")
    response = requests.get(url, stream=True)
    response.raise_for_status()

    with open(download_path, 'wb') as file:
        for chunk in response.iter_content(chunk_size=8192):
            file.write(chunk)
    print(f"Downloaded {package_name}.tgz")

    print(f"Extracting {package_name} to {extract_path}...")
    with tarfile.open(download_path, 'r:gz') as tar:
        tar.extractall(path=extract_path)
    print(f"Extracted {package_name} to {extract_path}")
    
    os.remove(download_path)
    print(f"Cleaned up: removed {download_path}")

    return extract_path

def extract_zip_file(zip_path):
    """
    Extracts the given zip file to the 'extracted' folder.

    Args:
        zip_path (str): The path to the zip file.

    Returns:
        str: The path to the extracted folder.
    """
    package_name = os.path.splitext(os.path.basename(zip_path))[0]

    extract_path = os.path.join('extracted', package_name)
    os.makedirs(extract_path, exist_ok=True)

    print(f"Extracting {zip_path} to {extract_path}...")
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
        print(f"Extracted {zip_path} to {extract_path}")
    except Exception as e:
        print(f"Error during extraction: {e}")

    return extract_path

def parse_nuclei_output(output):
    """
    Parses the Nuclei scan output and formats it for better readability.

    Args:
        output (str): The raw output from the Nuclei scan.

    Returns:
        str: The formatted and readable output.
    """
    # Split the output into individual findings based on new lines
    findings = [line.strip() for line in output.splitlines() if line.strip()]

    formatted_output = []

    for finding in findings:
        parts = finding.split('] ')
        if len(parts) >= 4:
            signature = parts[0] + ']'
            protocol = parts[1] + ']'
            severity = parts[2] + ']'
            affected_file = parts[3].split(' [')[0].strip()
            exposure = parts[3].split(' [')[1].rstrip(']').strip() if '[' in parts[3] else ""

            formatted_output.append(
                f"Signature: {signature}\n"
                f"Protocol: {protocol}\n"
                f"Severity: {severity}\n"
                f"Affected File: {affected_file}\n"
                f"Exposure: {exposure}\n"
                f"{'-'*50}\n"
            )
        else:
            formatted_output.append(f"Unrecognized format: {finding}\n")

    return "\n".join(formatted_output)

def run_secret_scan(target_path):
    
    print(f"Running Secret scan on {target_path}...")
    command = f'echo {target_path} | nuclei -t ~/nuclei-templates/file/keys/'    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        
        parsed_output = parse_nuclei_output(result.stdout)
        
        print("Secret scan completed successfully.")
        print("\nScan Results:\n" + parsed_output)
    except subprocess.CalledProcessError as e:
        print(f"Error running Secret scan: {e.stderr.strip()}")

if __name__ == "__main__":

	parser = argparse.ArgumentParser(description="Perform Secret Scanning on NPM JS Modules & Zip Files")
	parser.add_argument('-n', '--npmjs',
                    help="Choose any NPM JS package name e.g express",
                    type=str,
                    required=False)

	parser.add_argument('-z', '--zipf',
                    help="Select a ZIP file e.g file.zip",
                    type=str,
                    required=False)
	
	args = parser.parse_args()

	npmjs = args.npmjs
	zipf = args.zipf

	if npmjs:
		if os.path.isfile(npmjs):
			with open(npmjs, 'r') as file:
				packages = [line.strip() for line in file if line.strip()]
				for package in packages:
					print(f"Processing package: {package}")
					package_link = download_package(package)
					extracted_path = download_and_extract_package(package_link)
					run_secret_scan(extracted_path)
					shutil.rmtree(extracted_path)
					print(f"Completed processing for package: {package}")
		else:
			package_link = download_package(npmjs)
			extracted_path = download_and_extract_package(package_link)
			run_secret_scan(extracted_path)
			shutil.rmtree(extracted_path)

	elif zipf:
		extracted_path = extract_zip_file(zipf)
		run_secret_scan(extracted_path)
		shutil.rmtree(extracted_path)

	else:
		print("Please provide the npm package name or zip file using --npmjs or --zipf argument.")