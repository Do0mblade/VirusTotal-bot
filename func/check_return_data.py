
from pprint import pprint
from .decorators import benchmark

@benchmark
async def check_answer(data):
    undetected = data['attributes']['last_analysis_stats']['undetected']
    malicious = data['attributes']['last_analysis_stats']['malicious']
    prog = int(undetected) + int(malicious)
    last_analys = data['attributes']['last_analysis_date']
    first_analys = data['attributes']['first_submission_date']
    type = data['type']
    hash = data['id']
    magic = data['attributes']['magic']
    bites = data['attributes']['size']
    kbites = 0
    mbites = 0
    gbites = 0
    if bites >= 1024:
        bites = bites/1024
        kbites = bites
        if kbites >= 1024:
                mbites = kbites / 1024
                if mbites >= 1024:
                        gbites = mbites / 1024
                        if gbites >= 1024:
                            size = 'Много'
                        else:
                            size = f'{gbites} гб'
                else:
                    size = f'{mbites} мб'
        else:
            size = f'{kbites} кб'
    else:
        size = f'{bites} б'

    id = data['id']
    try:
        tag = data['attributes']['type_extension']
    except:
        tag = 'unknown'


    return last_analys, first_analys, prog, malicious, type, hash, magic, size, id, tag


