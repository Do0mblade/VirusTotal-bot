
import os

from .decorators import benchmark
from datetime import datetime

@benchmark
async def del_file(file_name):
    if os.path.isfile(file_name):
        os.remove(file_name)
    else:
        print(f'\n[&] {datetime.now()} Don`t del file: {file_name}\n')