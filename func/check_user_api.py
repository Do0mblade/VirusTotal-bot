
import virustotal_python
from virustotal_python.virustotal import VirustotalError

from .decorators import benchmark

@benchmark
async def check_user_api(api):
    var = api.split()
    if len(var) == 1:
        try:
            vtotal = virustotal_python.Virustotal(API_KEY=var[0])
            FILE_ID = '881771ba20ff67a9ab584c0a6f79701a4fbec7593ff57056a8449212daf98efb'
            if vtotal.request(f"files/{FILE_ID}"):
                return True, var[0]
        except VirustotalError:
            return 'err api', None
    else:
        return 'More 1', None

