
import asyncio

from pprint import pprint
from virustotal_python.virustotal import VirustotalError

from .decorators import benchmark

@benchmark
async def get_info_about_file(hash, vtotal):
    try:

        await asyncio.sleep(2)

        FILE_ID = hash

        while True:

            if not vtotal.request(f"files/{FILE_ID}"):
                await asyncio.sleep(5)
            else:
                resp = vtotal.request(f"files/{FILE_ID}")
                database = resp.data
                if not database['attributes']['last_analysis_stats']:
                    await asyncio.sleep(5)
                else:
                    if not database['attributes']['last_analysis_results']:
                        await asyncio.sleep(5)
                    else:
                        error = ''
                        return database, error


    except VirustotalError as err:
        database = 'Error API'
        error = str(err)
        return database, error