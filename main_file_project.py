
import asyncio


from pprint import pprint

from aiogram import Bot, types
from aiogram.dispatcher import Dispatcher
from aiogram.utils import executor

import virustotal_python

from func.check_user_api import check_user_api
from func.check_return_data import check_answer
from func.decorators import benchmark
from func.delete_file import del_file
from func.get_info_about_file import get_info_about_file
from func.send_to_analys import send_to_analys
from func.texts import *
from func.download import download_file

from sett.config import TOKEN
from sett.config import VIRUSTOTAL_API

import datetime


bot = Bot(token=TOKEN)
dp = Dispatcher(bot)

@dp.message_handler(commands=['start', 'help'])
async def start_command(message: types.Message):
    text = await start_text()
    await message.answer(text, parse_mode='HTML')



@dp.message_handler(commands=['site', 'website'])
async def website_command(message: types.Message):
    text = '<a href="https://www.virustotal.com">Оффициальный сайт Virustotal</a>'
    await message.reply(text, parse_mode='HTML')


@dp.message_handler(commands=['info', 'user'])
async def profile_command(message: types.Message):
    id = message.from_user.id
    name = message.from_user.full_name
    premium = message.from_user.is_premium
    lan = message.from_user.language_code
    is_bot = message.from_user.is_bot
    text = await profile_text(id, name, premium, lan, is_bot)
    await message.reply(text, parse_mode='HTML')

@dp.message_handler(content_types=['audio', 'video', 'document', 'text', 'photo'])
async def analys_files(message: types.Message):

    msg = await message.reply('<b><i>🌐 Инициализация файла</i></b>', parse_mode='HTML')

    if message.text:
        await msg.edit_text('<b><i>💁🏼 Простите, но я не обрабатываю текст!</i></b>', parse_mode='HTML')
        await asyncio.sleep(4)
        await msg.delete()
    elif message.photo:
        await msg.edit_text('<b><i>💁🏼 Простите, но я не обрабатываю фото. \nОтправьте мне фото в виде файла, для его обработки.</i></b>', parse_mode='HTML')
        await asyncio.sleep(10)
        await msg.delete()
    elif message.audio:
        await msg.edit_text('<b><i>💁🏼 Простите, но я не обрабатываю аудио файлы!</i></b>', parse_mode='HTML')
        await asyncio.sleep(4)
        await msg.delete()
    elif message.video:
        status_code = 0

        if message.caption:
            answer, api = await check_user_api(message.caption)
            if answer == 'More 1':
                await msg.edit_text('<b><i>⚠ Вы ввели лишние аргументы! ⚠</i></b>', parse_mode='HTML')
            if answer == 'err api':
                await msg.edit_text('<b><i>⚠ С вашим <u>api</u> что-то не так! ⚠</i></b>', parse_mode='HTML')
            if answer is True:
                status_code = 1
                API = api
        else:
            status_code = 1
            API = VIRUSTOTAL_API

        if status_code == 1:

            await msg.edit_text('<b>📄 Проверка размера видео</b>', parse_mode='HTML')

            if message.video.file_size <= 20971520:

                file_name = f'files/{message.video.file_name}'

                await msg.edit_text('<b>📥 Загрузка видео на сервер</b>', parse_mode='HTML')

                if await download_file(message, file_name):

                    first_time = datetime.datetime.now()

                    await msg.edit_text('<b>📤 Выгрузка видео на анализ</b>', parse_mode='HTML')

                    hash_file, vtotal = await send_to_analys(file_name, API)

                    if hash_file != 'Error':

                        await msg.edit_text('<b>💤 Ожидание ответа с сервера</b>', parse_mode='HTML')

                        await del_file(file_name)

                        database, error = await get_info_about_file(hash_file, vtotal)

                        if database != 'Error API':

                            await msg.edit_text('<b>🗂 Структурирование ответа</b>', parse_mode='HTML')

                            last_analys, first_analys, prog, malicious, type, hash, magic, size, id, tag = await check_answer(
                                database)

                            if API == VIRUSTOTAL_API:
                                api_key = ''
                            else:
                                api_key = f"\n🔑 Ваш api:\n▫{API}\n"

                            second_time = datetime.datetime.now()

                            time = second_time - first_time

                            text = await return_data_analys_text(last_analys, first_analys, prog, malicious, type, hash,
                                                                 magic, size, id, tag, message.video.file_name, time.seconds, api_key)

                            await msg.edit_text(text, parse_mode='HTML')

                        else:
                            await del_file(file_name)
                            await msg.edit_text(
                                f'<b><i>⚠ Критическая ошибка! ⚠\nОшибка:</i></b>\n{error}\n\nЕсли ошибка повториться, просьба обратиться к администрации бота.',
                                parse_mode='HTML')

                    else:
                        await del_file(file_name)
                        await msg.edit_text(
                            f'<b><i>⚠ Критическая ошибка! ⚠\nОшибка:</i></b>\n{vtotal}\n\nЕсли ошибка повториться, просьба обратиться к администрации бота.',
                            parse_mode='HTML')


                else:
                    await del_file(file_name)
                    await msg.edit_text('<b><i>⚠ Ошибка при скачивании файла! ⚠</i></b>',
                                        parse_mode='HTML')

            else:
                await msg.edit_text('<b><i>⚠ Превышено ограничение размера файла в 20 Мб! ⚠</i></b>', parse_mode='HTML')

    elif message.document:

        status_code = 0

        if message.caption:
            answer, api = await check_user_api(message.caption)
            if answer == 'More 1':
                await msg.edit_text('<b><i>⚠ Вы ввели лишние аргументы! ⚠</i></b>', parse_mode='HTML')
            if answer == 'err api':
                await msg.edit_text('<b><i>⚠ С вашим <u>api</u> что-то не так! ⚠</i></b>', parse_mode='HTML')
            if answer is True:
                status_code = 1
                API = api
        else:
            status_code = 1
            API = VIRUSTOTAL_API

        if status_code == 1:

            await msg.edit_text('<b>📄 Проверка размера файла</b>', parse_mode='HTML')

            if message.document.file_size <= 20971520:

                file_name = f'files/{message.document.file_name}'

                await msg.edit_text('<b>📥 Загрузка файла на сервер</b>', parse_mode='HTML')

                if await download_file(message, file_name):

                    first_time = datetime.datetime.now()

                    await msg.edit_text('<b>📤 Выгрузка файла на анализ</b>', parse_mode='HTML')

                    hash_file, vtotal = await send_to_analys(file_name, API)

                    if hash_file != 'Error':

                        await msg.edit_text('<b>💤 Ожидание ответа с сервера</b>', parse_mode='HTML')

                        await del_file(file_name)

                        database, error = await get_info_about_file(hash_file, vtotal)

                        if database != 'Error API':

                            await msg.edit_text('<b>🗂 Структурирование ответа</b>', parse_mode='HTML')

                            last_analys, first_analys, prog, malicious, type, hash, magic, size, id, tag = await check_answer(database)

                            if API == VIRUSTOTAL_API:
                                api_key = ''
                            else:
                                api_key = f"\n🔑 Ваш api:\n▫{API}\n"

                            second_time = datetime.datetime.now()

                            time = second_time - first_time

                            text = await return_data_analys_text(last_analys, first_analys, prog, malicious, type, hash, magic, size, id, tag, message.document.file_name, time.seconds, api_key)

                            await msg.edit_text(text, parse_mode='HTML')

                        else:
                            await del_file(file_name)
                            await msg.edit_text(
                                f'<b><i>⚠ Критическая ошибка! ⚠\nОшибка:</i></b>\n{error}\n\nЕсли ошибка повториться, просьба обратиться к администрации бота.',
                                parse_mode='HTML')

                    else:
                        await del_file(file_name)
                        await msg.edit_text(f'<b><i>⚠ Критическая ошибка! ⚠\nОшибка:</i></b>\n{vtotal}\n\nЕсли ошибка повториться, просьба обратиться к администрации бота.',
                                                parse_mode='HTML')


                else:
                    await del_file(file_name)
                    await msg.edit_text('<b><i>⚠ Ошибка при скачивании файла! ⚠</i></b>',
                                        parse_mode='HTML')

            else:
                await msg.edit_text('<b><i>⚠ Превышено ограничение размера файла в 20 Мб! ⚠</i></b>', parse_mode='HTML')


    else:
        await msg.edit_text('<b><i>⚠ Не удалось определить тип файла ⚠</i></b>', parse_mode='html')





if __name__ == '__main__':
    executor.start_polling(dp, skip_updates=True)


