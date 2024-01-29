import sys
import requests
from bs4 import BeautifulSoup
import pandas as pd
import argparse

def get_cve_details(cve_id):
    # Set headers
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                             '(KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36'}
    # Construct URL
    url = f'https://www.cvedetails.com/cve/{cve_id}'

    # Send GET request
    response = requests.get(url, headers=headers, verify=False)

    # Check response code
    if response.status_code != 200:
        raise Exception(f'Error: Invalid CVE ID "{cve_id}".')

    # Parse HTML response
    soup = BeautifulSoup(response.text, 'html.parser')
    # Extract the CVE ID
    cve_id = cve_id
    cve_content_div = soup.find('div', attrs={'id': 'contentdiv'})
    # the cve has no entry in cvedetails yet
    if cve_content_div.find('div', class_='alert alert-secondary my-4'):
        message = f'>> Failed to parse HTML elements cve_content_div << \n\n'
        print(f'ERROR {cve_id}{message} ')
        ## Send the result to webhook. ##
        # sys.exit(0)
        return {
            'cve_id': cve_id
        }
    description = cve_content_div.find('div', class_='cvedetailssummary-text').text.strip()
    # Extract the published date
    published_updated_elements = cve_content_div.find_all('div', class_='d-inline-block')
    published_date = published_updated_elements[0].text.strip().replace("Published", "").strip()
    updated_date = published_updated_elements[1].text.strip().replace("Updated", "").strip()
    # Extract the Vulnerability category
    vuln_cat_elements = cve_content_div.find_all('span', class_='ssc-vuln-cat')
    total_vuln_cat=[]
    for x in range(len(vuln_cat_elements )):
        total_vuln_cat+= vuln_cat_elements[x]
    # Extract the base score
    cve_content_div2 = soup.find('table',  class_='table table-borderless')
    if  not cve_content_div2:
        message = f'>> Failed to parse HTML elements cve_content_div2 << \n\n'
        print(f'ERROR {cve_id}{message} ')
        return {
            'cve_id': cve_id
        }
    base_score_elements = cve_content_div2.find_all('td', class_='ps-2')
    base_score = base_score_elements[0].find('div', class_='cvssbox').text.strip()
    base_severity = base_score_elements[1].text.strip()
    vector = base_score_elements[2].text.strip()
    exploitability = base_score_elements[3].text.strip()
    impact = base_score_elements[4].text.strip()

    # Extract the CWE ID
    cwe_id_element = soup.find('h2', string='CWE ids for ' + cve_id)
    if cwe_id_element:
        cwe_item = cwe_id_element.find_next('a')
        if cwe_item:
            cwe_id = cwe_item.text.strip()
    else:
        cwe_id = 'Not found CWE ids for ' + cve_id

    #  Extract references list
    references_heading_div = soup.find('div', style='overflow-x: scroll')
    references_heading = references_heading_div.find('ul', class_='list-group rounded-0')
    if references_heading:
        reference_links = references_heading.find_all('a', class_='ssc-ext-link')
        references = [link['href'] for link in reference_links]
    else:
        references = f'Not found references for {cve_id}'
    # formatted references list
    formatted_references=""
    if references:
        i = 0
        if isinstance(references, list):
            formatted_references = '\n'.join([f'({i + 1}) {ref}' for i, ref in enumerate(references)])
        else:
            formatted_references = f'({i + 1}) {references}'

    #  Extract CISA date of inclusion catalog
    CISA_div = soup.find('div', class_='border-top mt-2 ps-3')
    cisa_date='Not included.'
    if CISA_div:
        cisa_date = CISA_div.find_next('span', class_='text-secondary col-md-1').next_sibling.strip()

    #  Extract vendor and product
    Vendor_div = soup.find_all('div', class_='col-md-8 text-secondary')
    data = [item.text.strip() for item in Vendor_div if item]
    splited=data[0].split(":", 5)
    Vendor=splited[3]
    Product=splited[4]

    return {
        'cve_id': cve_id,
        'base_score': base_score,
        'impact': impact,
        'exploitability': exploitability,
        'base_severity': base_severity,
        'cwe_id': cwe_id,
        'Vendor': splited[3],
        'Product': splited[4],
        'description': description,
        'published_date': published_date,
        'cisa_date': cisa_date,
        'updated_date': updated_date,
        'total_vuln_cat': total_vuln_cat,
        'vector': vector,
        'references': formatted_references,

    }

def onecve(cve_id):
    try:
        cve_details = get_cve_details(cve_id)

        print(f'CVE ID: {cve_details["cve_id"]}')
        print(f'Base score: {cve_details["base_score"]}')
        print(f'Severity: {cve_details["base_severity"]}')
        print(f'Exploitability: {cve_details["exploitability"]}')
        print(f'Impact: {cve_details["impact"]}')
        print(f'Vendor: {cve_details["Vendor"]}')
        print(f'Product: {cve_details["Product"]}')
        print(f'Vector: {cve_details["vector"]}')
        print(f'Published date: {cve_details["published_date"]}')
        print(f'Updated date: {cve_details["updated_date"]}')
        print(f'CWE ID: {cve_details["cwe_id"]}')
        print(f'Vulnerability category: {cve_details["total_vuln_cat"]}')
        print(f'CISA date added to the catalog: {cve_details["cisa_date"]}')
        print(f'Description: {cve_details["description"]}')
        print(f'Ref.: {cve_details["references"]}')

    except Exception as e:
        print(f'Error: {e}')

def cvelist(cve_list):
    try:

        #df = pd.read_excel(r'cves_list.xlsx', sheet_name='CVEs')
        df = pd.read_excel(cve_list, sheet_name='CVEs')
        cve_details = [get_cve_details(x) for x in df['cve_id']]
        df = pd.DataFrame.from_dict(cve_details)
        df.to_excel("output.xlsx", index=False)
        out = df.to_json(orient='records', lines=True)
        with open('json.txt', 'w') as f:
            f.write(out)
    except Exception as e:
        print(f'Error: {e}')

if __name__ == '__main__':

    # if you type --help
    parser = argparse.ArgumentParser(description='Run Cvedetails webscrapping script.')

    # Add a command
    parser.add_argument('--list', help=' cves in a list.xlsx.  This script generates an output.xlsx and json.txt, with the cves passed as an argument list.')
    parser.add_argument('--cve', help='only one CVE.')
    # Get our arguments from the user
    args = parser.parse_args()

    if (args.list or args.cve) is None:
        parser.print_help()

    if args.list:
        cve_list = sys.argv[2]
        cvelist(cve_list)

    if args.cve:
        cve_id = sys.argv[2]
        onecve(cve_id)



