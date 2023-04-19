
from .decorators import benchmark

import datetime

@benchmark
async def start_text():
    text = """
Привет, я бот анализирующий файлы на вирусы.
Какие файлы я анализирую?
Такие: <i>фото</i>, <i>видео</i>, <i>документы</i>.

<b>⚠️ Ограничение по загрузке файлов в 20 мб. ⚠</b>️ 

/start - это сообщение
/site - официальный сайт антивирусной системы VirysTotal
/info - информация о твоём профиле Telegram

Если файл был когда-либо просканирован другим пользователем и с тех пор не изменялся, то я моментально 
выдам результат, в ином случае придётся ждать полного сканирования от VirusTotal, данный процесс может в лучшем случае занять 10-20 секунд, 
в худшем пару минут. Всё зависит от антивирусной системы VirusTotal и размера файла!


<b>⚠️ На данный момент в боте используется бесплатный API от VirusTotal, поэтому анализ файла может производиться с задержкой! ⚠</b>️


    """
    return text


@benchmark
async def profile_text(id, name, premium, lan, is_bot):
    if is_bot is True:
        user_bot = 'Бот'
    else:
        user_bot = 'Не бот!'
    text = f"""
<b>ID:</b> <i>{id}</i>
<b>Имя:</b> <i>{name}</i>
<b>Telegram premium:</b> <i>{premium}</i>
<b>Язык:</b> <i>{lan}</i>
<b>{user_bot}</b>

        """
    return text

@benchmark
async def return_data_analys_text(last_analys, first_analys, prog, malicious, type, hash, magic, size, id, tag, file_name, time, api_key):
    text = f"""
🧬 Обнаружения: <b>{malicious}</b> / {prog}
            
🗂 Имя файла: <b>{file_name}</b>
📄 Формат файла: <b>{type}</b>
📚 Размер файла: <b>{size}</b>
🔰 Тег файла: <b>{tag}</b>

🕗 Анализ занял: <b>{time}</b> s

🔬 Первый анализ:
▫️ <b>{datetime.datetime.fromtimestamp(first_analys).strftime("%A, %B %d, %Y %I:%M:%S")}</b>

🔭 Последний анализ: 
▫️ <b>{datetime.datetime.fromtimestamp(last_analys).strftime("%A, %B %d, %Y %I:%M:%S")}</b>

💫 Magic:
▫️ <b>{magic}</b>

🃏 HASH:
▫️ {hash}
{api_key}
<b><a href="https://www.virustotal.com/gui/file/{id}">Ссылка на анализ</a></b>

"""
    return text