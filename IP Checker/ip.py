from vt import Client
import time

def scan_file_with_virustotal(api_key, uri):
    client = Client(api_key)
    filtered_urls.append(uri)
    try:
        analysis = client.scan_url(uri)
        scan_id = analysis.id
        # Wait for the analysis to finish
        while True:
            report = client.get_object(f"/analyses/{scan_id}")
            if report.status == "completed":
                break
            time.sleep(1)  # Adjust the sleep duration as needed
        mal_count = report.stats["malicious"]
        print(f"{uri} has a malcount of {mal_count}")
        if mal_count > 0:
            mal_urls.append(uri)
    except Exception as e:
        print(f"Error scanning url {uri}: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    api_key = "d63a2793c444b6a868dd06c1c506298abeef732a7992eea1975da2e58a2a0c99"
    url_path = 'IP Checker/ips.txt'
    mal_urls = []
    filtered_urls = []
    try:
        with open(url_path, 'r') as file:
            domains = file.read().splitlines()
        for domain in domains:
            domain = domain.replace("]","").replace("[","").strip(" ")
            scan_file_with_virustotal(api_key, domain)
    except FileNotFoundError:
        print(f"Error: {url_path} not found.")
    except Exception as e:
        print(f"Error: {str(e)}")
   
    file_path_filtered = 'IP Checker/ip_filtered.txt'
    file_path = 'IP Checker/ip_output.txt'
    mal_urls = list(set(mal_urls))
    with open(file_path, 'w') as file:
        for mal_url in mal_urls:
            file.write(mal_url + '\n')

    with open(file_path_filtered, 'w') as file:
        for url in filtered_urls:
            file.write(url + '\n')

