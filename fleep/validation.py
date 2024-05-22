import hashlib
import requests
import json
from fleep.__init__ import get
import re 

def acceptable_file(uploaded_file, allowed_extensions, allowed_mimes, allowed_types, allowed_size):
    def remove_period(i):
        k = i.split('.')
        return k[1]

    allowed_extensions = list(map(remove_period, allowed_extensions))
    
    # VIRUS TEST
    hashed_file = hashlib.sha256()
    data = uploaded_file.read()
    hashed_file.update(data)
    uploaded_file_hash = hashed_file.hexdigest()
    # test hash (known virus hash)
    # uploaded_file_hash = "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d"
    data = {
        'query': 'get_info',
        'hash': ''+uploaded_file_hash+'',
        'field': 'sha256_hash'
    }
    try:
        response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, timeout=15)
    except:
        raise Exception('Malware Bazaar is experiencing issues. Try again later.')
    else:
        json_response = response.content.decode("utf-8", "ignore")
        parsed_response = json.loads(json_response)
        query_status = parsed_response["query_status"]
        if query_status == "hash_not_found":
            pass
        elif query_status == "ok":
            # Want to send info to IT about who this was.
            raise Exception("Attempted known virus upload.")
        else:
            raise Exception("Unknown error. Try again later.")
    
    # REGEX EXTENSION AND NAME TEST
    def remove_period(i):
        k = i.split('.')
        return k[1]

    regex_extensions = "|".join(allowed_extensions)
    uploaded_file_path = uploaded_file.temporary_file_path()
    uploded_file_name = uploaded_file.name
    regex = "^(?:[a-zA-Z0-9])[a-zA-Z0-9\-\_\ ]{0,50}(?:[a-zA-Z0-9])\.(?:"+regex_extensions+")$"
    file_name_validation = re.search(regex, uploded_file_name)
    if not file_name_validation:
        raise Exception('Uploaded file has a prohibited name.')
    
    uploded_mime = uploaded_file.content_type
    uploded_extension = uploaded_file.file.name.split('.')[-1]

    # FILE TYPING TEST
    with open(uploaded_file_path , "rb") as file:
        info = get(file.read(128))
        info_type = info[0].type
        info_extension = info[0].extension
        info_mime = info[0].mime
        info_all = info[1]
        # NOTE: the indexing on info on the above 4 lines only works on a modified version of fleep

    # if in acceptable items
    for t in allowed_types:
        if t in info_type:
            type = t
            break
    for m in allowed_mimes:
        if m in info_mime:
            mime = m
            break
    for e in allowed_extensions:
        if e in info_extension:
            extension = e
            break
    if file.size <= allowed_size:
        size = file.size

    if not type:
        raise Exception('File type not supported.')
    if not mime:
        raise Exception('File mime not supported.')
    if not extension:
        raise Exception('File extension not supported.')
    if not size:
        raise Exception('File size not supported.')

    # if acceptable file has all the matching features (type, extension, mime)
    check = False
    for item in info_all:
        if uploded_mime in item["mime"]:
            if uploded_extension in item["extension"]:
                check = True
    
    if not check:
        raise Exception('File signature did not match mime, type, or extension.')