import hashlib
import requests
import json
from fleep import get
import re 

def acceptable_files(file, extensions, mimes, types):
    # Virus Test
    hashed_file = hashlib.sha256()
    data = file.read()
    hashed_file.update(data)
    test_hash = hashed_file.hexdigest()
    # test_hash = "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d"
    data = {
        'query': 'get_info',
        'hash': ''+test_hash+'',
        'field': 'sha256_hash'
    }
    try:
        response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, timeout=15)
    except:
        print('Virus testing site is down. Please try again later.')
        raise Exception('Malware Bazaar is experiencing issues. Try again later.')
    else:
        json_response = response.content.decode("utf-8", "ignore")
        parsed_response = json.loads(json_response)
        query_status = parsed_response["query_status"]
        if query_status == "hash_not_found":
            print("Not found in virus db")
        elif query_status == "ok":
            # Want to send IP address, user, company, group to IT
            raise Exception("Attempted known virus upload.")
        else:
            raise Exception("Unknown error. Try again later.")
    
    # Regex Extension and Name Test
    def remove_period(i):
        k = i.split('.')
        return k[1]
    plain_extensions = list(map(remove_period, extensions))
    regex_extensions = "|".join(plain_extensions)
    file_path = file.temporary_file_path()
    file_name = file.name
    regex = "^(?:[a-zA-Z0-9])[a-zA-Z0-9\-\_\ ]{0,50}(?:[a-zA-Z0-9])\.(?:"+regex_extensions+")$"
    file_name_validation = re.search(regex, file_name)
    if not file_name_validation:
        raise Exception('Uploaded file has a prohibited name.')
    
    uploded_mime = file.content_type
    uploded_extension = file.file.name.split('.')[-1]

    # File Typing Test
    with open(file_path , "rb") as file_2:
        info = get(file_2.read(128))
        info_type = info[0].type
        info_extension = info[0].extension
        info_mime = info[0].mime
        info_all = info[1]
        # NOTE: the indexing on info on the above 4 lines only works on a modified version of fleep

    # if in acceptable items
    for t in types:
        if t in info_type:
            type = t
            break
    for m in mimes:
        if m in info_mime:
            mime = m
            break
    for e in plain_extensions:
        if e in info_extension:
            extension = e
            break
    if file.size <= 50000000:
        size = file.size

    if not type:
        raise Exception('File type not supported.')
    if not mime:
        raise Exception('File mime not supported.')
    if not extension:
        raise Exception('File extension not supported.')
    if not size:
        raise Exception('File size not supported.')

    # if acceptable file has all the matching features (type, extention, mime)
    check = False
    for item in info_all:
        if uploded_mime in item["mime"]:
            if uploded_extension in item["extension"]:
                print(item)
                check = True
    
    if not check:
        raise Exception('File signature did not match mime, type, or extension.')

    

