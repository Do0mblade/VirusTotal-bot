
from .decorators import benchmark

@benchmark
async def download_file(message, file_name):
    if message.document:
        destination_file = await message.document.download(destination_file=file_name)
    if message.video:
        destination_file = await message.video.download(destination_file=file_name)
    return destination_file

