

import hashlib
import os
import os.path

from virustotal_python.virustotal import VirustotalError

import virustotal_python

from .decorators import benchmark

@benchmark
async def send_to_analys(file_name, VIRUSTOTAL_API):

        try:

            FILE_PATH = file_name

            vtotal = virustotal_python.Virustotal(API_KEY=VIRUSTOTAL_API)
            # Create dictionary containing the large file to send for multipart encoding upload
            large_file = {
                "file": (
                    os.path.basename(f"{FILE_PATH}"),
                    open(os.path.abspath(f"{FILE_PATH}"), "rb"),
                )
            }
            # Get URL to send a large file
            upload_url = vtotal.request("files/upload_url").data
            # Submit large file to VirusTotal for analysis
            vtotal.request(upload_url, files=large_file, method="POST", large_file=True)

            file = f"{file_name}"  # Location of the file (can be set a different way)
            BLOCK_SIZE = 65536  # The size of each read from the file

            file_hash = hashlib.sha256()  # Create the hash object, can use something other than `.sha256()` if you wish
            with open(file, 'rb') as f:  # Open the file to read it's bytes
                fb = f.read(BLOCK_SIZE)  # Read from the file. Take in the amount declared above
                while len(fb) > 0:  # While there is still data being read from the file
                    file_hash.update(fb)  # Update the hash
                    fb = f.read(BLOCK_SIZE)  # Read the next block from the file

            hash = file_hash.hexdigest()

            return hash, vtotal

        except VirustotalError as err:
            err_type = 'Error'
            error = str(err)
            return err_type, error

