import asyncio
from vt import Client

def clean_hash(file_hash):
    # Remove bullet character if it's at the beginning of the hash
    if file_hash.startswith("•"):
        return file_hash[1:]
    return file_hash

async def scan_file_with_virustotal(api_key, file_hash):
    result = {
        'hash': file_hash,
        'is_malicious': False,
        'malicious_percentage': 0,
        'error': None
    }

    async with Client(api_key) as client:
        try:
            file_scan = await client.get_object_async(f'/files/{file_hash}')
            analysis_stats = file_scan.last_analysis_stats
            total_votes = sum(analysis_stats.values())
            mal_count = analysis_stats['malicious']

            if mal_count > 0:
                result['is_malicious'] = True
                result['malicious_percentage'] = (mal_count / total_votes) * 100

        except Exception as e:
            result['error'] = str(e)

    return result

async def convert_md5_to_sha256(api_key, md5_hashes):
    sha256_hashes = []
    async with Client(api_key) as client:
        for md5_hash in md5_hashes:
            try:
                file_scan = await client.get_object_async(f'/files/{md5_hash}')
                sha256_hash = file_scan.sha256
                sha256_hashes.append(sha256_hash)
            except Exception as e:
                print(f"Error converting MD5 to SHA256 for hash: {md5_hash}. Error: {e}")
    return sha256_hashes

async def main(api_key, file_hashes_path, output_file_path, mal_output_file_path):
    with open(file_hashes_path, 'r') as file:
        file_hashes = [clean_hash(hash.strip()) for hash in file.read().splitlines()]

    # Detect if any of the hashes are MD5
    md5_hashes = [hash for hash in file_hashes if len(hash) == 32]

    if md5_hashes:
        print("MD5 hashes detected. Converting to SHA256...")

        # Convert MD5 hashes to SHA256
        sha256_hashes = await convert_md5_to_sha256(api_key, md5_hashes)

        # Write converted MD5 hashes to a separate file
        with open('Hahses Checker/MD5_Converted_to_SHA256.txt', 'w') as converted_file:
            for sha256_hash in sha256_hashes:
                converted_file.write(sha256_hash + '\n')

        # Remove MD5 hashes from the original list
        file_hashes = [hash for hash in file_hashes if hash not in md5_hashes]
        # Add the converted SHA256 hashes to the list
        file_hashes.extend(sha256_hashes)

    tasks = [scan_file_with_virustotal(api_key, file_hash) for file_hash in file_hashes]
    results = await asyncio.gather(*tasks)

    mal_hashes = [res['hash'] for res in results if res['is_malicious']]

    # Print malicious count for each hash
    for res in results:
        if res['is_malicious']:
            print(f"Hash: {res['hash']} has a malicious count of {res['malicious_percentage']:.2f}%")
        elif res['error'] == "Not Found":
            print(f"No results found for hash: {res['hash']}")

    # Write all results to a file
    with open(output_file_path, 'w') as output_file:
        for res in results:
            if res['error']:
                output_file.write(f"Hash: {res['hash']}, Error: {res['error']}\n")
            else:
                status = "Malicious" if res['is_malicious'] else "Not Malicious"
                output_file.write(f"Hash: {res['hash']}, Status: {status}, Malicious Percentage: {res['malicious_percentage']:.2f}%\n")
            output_file.write("\n")

    # Write only malicious hashes to a separate file
    with open(mal_output_file_path, 'w') as mal_file:
        for mal_hash in mal_hashes:
            mal_file.write(mal_hash + '\n')

# Replace 'your_api_key' with your actual VirusTotal API key
api_key = 'd63a2793c444b6a868dd06c1c506298abeef732a7992eea1975da2e58a2a0c99'
file_hashes_path = 'Hahses Checker/hashes.txt'  # Replace with the path to your file of hashes
output_file_path = 'Hahses Checker/scan_results.txt'  # Path to the output file where results will be saved
mal_output_file_path = 'Hahses Checker/malicious_hashes.txt'  # Path to the output file for malicious hashes

# Run the main function
asyncio.run(main(api_key, file_hashes_path, output_file_path, mal_output_file_path))
