from vt import Client
import time

def scan_file_with_virustotal(api_key, uri):
    client = Client(api_key)
    try:
        analysis = client.scan_url(uri)
        scan_id = analysis.id
        # Wait for the analysis to finish
        while True:
            report = client.get_object(f"/analyses/{scan_id}")
            if report.status == "completed":
                break
            time.sleep(2)  # Adjust the sleep duration as needed
        mal_count = report.stats["malicious"]
        if mal_count > 0:
            print(f"{uri} has a malicious count of {mal_count}")
            mal_urls.append(uri)
    except Exception as e:
        print(f"Error scanning url {uri}: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    api_key = "d63a2793c444b6a868dd06c1c506298abeef732a7992eea1975da2e58a2a0c99"
    url_path = 'URLs Checker/urls.txt'
    mal_urls = []
    try:
        with open(url_path, 'r') as file:
            urls = file.read().splitlines()
        for url in urls:
            url = url.replace("]","").replace("[","")
            protocol , url_body = url.split("://")
            protocol = protocol.replace("x","t")
            parsed_uri = protocol + "://" + url_body
            scan_file_with_virustotal(api_key, parsed_uri)
    except FileNotFoundError:
        print(f"Error: {url_path} not found.")
    except Exception as e:
        print(f"Error: {str(e)}")
    
  
    file_path = 'URLs Checker/url_output.txt'
    mal_urls = list(set(mal_urls))
    with open(file_path, 'w') as file:
        for mal_url in mal_urls:
            file.write(mal_url + '\n')
