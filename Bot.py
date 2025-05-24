from flask import Flask, request, Response
import telebot
import io
import numpy as np
from PIL import Image
import logging
import sqlite3
import secrets
import hashlib
import requests
import json

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Инициализация Flask и Telegram бота
app = Flask(__name__)
bot = telebot.TeleBot(" ")
WEBHOOK_URL = "https://romanio.pythonanywhere.com/webhook"  

# Инициализация базы данных SQLite
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        password_hash TEXT,
        salt TEXT,
        is_admin INTEGER DEFAULT 0,
        logged_in INTEGER DEFAULT 0,
        prediction_count INTEGER DEFAULT 0
    )''')
    conn.commit()
    conn.close()
    logging.info("База данных инициализирована")

init_db()

# Установка меню команд
commands = [
    telebot.types.BotCommand(command="/start", description="Запустить бота"),
    telebot.types.BotCommand(command="/register", description="Зарегистрироваться"),
    telebot.types.BotCommand(command="/login", description="Войти в аккаунт"),
    telebot.types.BotCommand(command="/logout", description="Выйти из аккаунта"),
    telebot.types.BotCommand(command="/predict", description="Классифицировать изображение"),
    telebot.types.BotCommand(command="/admin_users", description="Список пользователей (админ)"),
    telebot.types.BotCommand(command="/admin_delete", description="Удалить пользователя (админ)"),
    telebot.types.BotCommand(command="/admin_promote", description="Назначить администратора (админ)")
]
bot.set_my_commands(commands)
logging.info("Меню команд установлено")

# Функции для работы с базой данных
def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

def save_user(user_id, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    salt = secrets.token_hex(16)
    password_hash = hash_password(password, salt)
    is_admin = 1 if password == "admin123" and not check_any_admin() else 0
    c.execute("INSERT INTO users (user_id, password_hash, salt, is_admin, logged_in, prediction_count) VALUES (?, ?, ?, ?, 0, 0)",
              (user_id, password_hash, salt, is_admin))
    conn.commit()
    conn.close()
    logging.info(f"Пользователь {user_id} зарегистрирован")

def check_user(user_id, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT password_hash, salt FROM users WHERE user_id = ?", (user_id,))
    result = c.fetchone()
    conn.close()
    if result:
        stored_hash, salt = result
        return hash_password(password, salt) == stored_hash
    return False

def check_user_exists(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE user_id = ?", (user_id,))
    exists = c.fetchone() is not None
    conn.close()
    return exists

def check_is_admin(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT is_admin FROM users WHERE user_id = ?", (user_id,))
    result = c.fetchone()
    conn.close()
    return result and result[0] == 1

def check_any_admin():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE is_admin = 1 LIMIT 1")
    exists = c.fetchone() is not None
    conn.close()
    return exists

def get_user_list():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT user_id, prediction_count FROM users")
    users = c.fetchall()
    conn.close()
    return users

def delete_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    logging.info(f"Пользователь {user_id} удален")

def promote_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("UPDATE users SET is_admin = 1 WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    logging.info(f"Пользователь {user_id} повышен до администратора")

def increment_prediction_count(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("UPDATE users SET prediction_count = prediction_count + 1 WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

def is_logged_in(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT logged_in FROM users WHERE user_id = ?", (user_id,))  # Исправлено: c.execute
    result = c.fetchone()
    conn.close()
    return result and result[0] == 1

def set_logged_in(user_id, status):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("UPDATE users SET logged_in = ? WHERE user_id = ?", (status, user_id))
    conn.commit()
    conn.close()

# Хранилище для отслеживания следующего шага
next_step_handlers = {}

# Функции обработки сообщений
def handle_start(chat_id, user_id):
    if check_user_exists(user_id):
        bot.send_message(chat_id, 'Вы уже зарегистрированы. Пожалуйста, войдите с помощью команды /login.')
    else:
        bot.send_message(chat_id, 'Вы не зарегистрированы. Пожалуйста, зарегистрируйтесь с помощью команды /register.')

def handle_register(chat_id, user_id):
    bot.send_message(chat_id, 'Придумайте пароль для регистрации:')
    next_step_handlers[user_id] = 'get_pincode'

def handle_login(chat_id, user_id):
    if check_user_exists(user_id):
        bot.send_message(chat_id, 'Введите ваш пароль для входа:')
        next_step_handlers[user_id] = 'check_pincode'
    else:
        bot.send_message(chat_id, 'Вы не зарегистрированы. Пожалуйста, зарегистрируйтесь с помощью команды /register.')

def handle_logout(chat_id, user_id):
    if check_user_exists(user_id):
        if is_logged_in(user_id):
            set_logged_in(user_id, 0)
            bot.send_message(chat_id, 'Вы успешно вышли из аккаунта.')
        else:
            bot.send_message(chat_id, 'Вы не были авторизованы.')
    else:
        bot.send_message(chat_id, 'Вы не зарегистрированы. Пожалуйста, зарегистрируйтесь с помощью команды /register.')

def handle_admin_users(chat_id, user_id):
    if check_user_exists(user_id) and is_logged_in(user_id) and check_is_admin(user_id):
        users = get_user_list()
        if users:
            response = "\n".join([f"UserID: {user[0]}, Predictions: {user[1]}" for user in users])
            bot.send_message(chat_id, f"Список пользователей:\n{response}")
        else:
            bot.send_message(chat_id, "Пользователи не найдены.")
    else:
        bot.send_message(chat_id, 'Эта команда доступна только администраторам после входа.')

def handle_admin_delete(chat_id, user_id):
    if check_user_exists(user_id) and is_logged_in(user_id) and check_is_admin(user_id):
        bot.send_message(chat_id, 'Введите UserID пользователя для удаления:')
        next_step_handlers[user_id] = 'process_delete_user'
    else:
        bot.send_message(chat_id, 'Эта команда доступна только администраторам после входа.')

def handle_admin_promote(chat_id, user_id):
    if check_user_exists(user_id) and is_logged_in(user_id) and check_is_admin(user_id):
        bot.send_message(chat_id, 'Введите UserID пользователя для назначения администратором:')
        next_step_handlers[user_id] = 'process_promote_user'
    else:
        bot.send_message(chat_id, 'Эта команда доступна только администраторам после входа.')

def handle_get_pincode(chat_id, user_id, text):
    try:
        if check_user_exists(user_id):
            bot.send_message(chat_id, 'Вы уже зарегистрированы. Используйте /login для входа.')
        else:
            save_user(user_id, text)
            bot.send_message(chat_id, 'Регистрация прошла успешно! Теперь выполните вход через команду /login.')
        next_step_handlers.pop(user_id, None) # Использование None как значения по умолчанию предотвращает ошибку KeyError, если user_id отсутствует в словаре
        # Предотвращает накопление ненужных записей в словаре.
    except Exception as e:
        logging.error(f"Ошибка регистрации: {str(e)}")
        bot.send_message(chat_id, "Ошибка сервера. Попробуйте позже.")

def handle_check_pincode(chat_id, user_id, text):
    try:
        if check_user(user_id, text):
            set_logged_in(user_id, 1)
            bot.send_message(chat_id, '✅ Вход выполнен успешно! Теперь можете использовать команду /predict.')
        else:
            set_logged_in(user_id, 0)
            bot.send_message(chat_id, '❌ Неверный пароль. Попробуйте снова через /login.')
        next_step_handlers.pop(user_id, None)
    except Exception as e:
        logging.error(f"Ошибка входа: {str(e)}")
        bot.send_message(chat_id, "Ошибка сервера. Попробуйте позже.")

def handle_process_delete_user(chat_id, user_id, text):
    if check_is_admin(user_id):
        target_user_id = text.strip()
        if check_user_exists(target_user_id):
            delete_user(target_user_id)
            bot.send_message(chat_id, f"Пользователь {target_user_id} удален.")
        else:
            bot.send_message(chat_id, f"Пользователь {target_user_id} не найден.")
        next_step_handlers.pop(user_id, None)
    else:
        bot.send_message(chat_id, 'Эта команда доступна только администраторам.')

def handle_process_promote_user(chat_id, user_id, text):
    if check_is_admin(user_id):
        target_user_id = text.strip()
        if check_user_exists(target_user_id):
            promote_user(target_user_id)
            bot.send_message(chat_id, f"Пользователь {target_user_id} повышен до администратора.")
        else:
            bot.send_message(chat_id, f"Пользователь {target_user_id} не найден.")
        next_step_handlers.pop(user_id, None)
    else:
        bot.send_message(chat_id, 'Эта команда доступна только администраторам.')

def handle_predict(chat_id, user_id):
    if check_user_exists(user_id):
        if is_logged_in(user_id):
            bot.send_message(chat_id, 'Отправьте изображение без сжатия для анализа.')
            next_step_handlers[user_id] = 'classificator'
        else:
            bot.send_message(chat_id, 'Сначала выполните вход через /login')
    else:
        bot.send_message(chat_id, 'Вы не зарегистрированы. Пожалуйста, зарегистрируйтесь с помощью команды /register.')

def handle_classificator(chat_id, user_id, photo):
    try:
        # Проверка, отправлена ли фотография
        if not photo:
            # Если фото не отправлено, отправляем сообщение пользователю и завершаем функцию
            bot.send_message(chat_id, "Пожалуйста, отправьте фотографию.")
            return
        
        # Извлечение идентификатора файла последней (самой качественной) фотографии из списка
        image_id = photo[-1].file_id
        
        # Получение информации о файле фотографии с серверов Telegram
        image_path = bot.get_file(image_id)
        
        # Загрузка байтов изображения с серверов Telegram
        image = bot.download_file(image_path.file_path)
        
        # Преобразование байтов изображения в файловый объект в памяти
        image_bytes = io.BytesIO(image)
        
        # Открытие изображения с помощью библиотеки PIL (Pillow)
        image = Image.open(image_bytes)
        
        # Проверка, является ли изображение RGB (3 канала: красный, зеленый, синий)
        if image.mode != 'RGB':
            # Если режим не RGB, конвертируем в RGB
            image = image.convert('RGB')
        
        # Изменение размера изображения до 200x200 пикселей для унификации
        resized_image = image.resize((200, 200))
        
        # Преобразование изображения в массив NumPy размером (200, 200, 3)
        img_array = np.array(resized_image)
        
        # Преобразование цветного изображения в оттенки серого
        # Берется среднее значение по каналам RGB для каждого пикселя
        gray = np.mean(img_array, axis=2).astype(np.uint8)
        
        # Нормализация значений интенсивности пикселей в диапазон [0, 255]
        # Вычитается минимум, делится на разницу между максимумом и минимумом, умножается на 255
        # 1e-8 добавлено для предотвращения деления на ноль
        gray = (gray - np.min(gray)) / (np.max(gray) - np.min(gray) + 1e-8) * 255
        
        # Приведение нормализованного массива к типу uint8 (целые числа от 0 до 255)
        gray = gray.astype(np.uint8)
        
        # Вычисление доли темных пикселей (интенсивность < 100)
        # np.sum(gray < 100) подсчитывает количество темных пикселей
        # Делится на общее количество пикселей (200 * 200 = 40,000)
        black_pixel_ratio = np.sum(gray < 100) / (200 * 200)
        
        # Классификация на основе доли темных пикселей
        if black_pixel_ratio > 0.25:
            # Если темных пикселей больше 25%, считаем, что это горилла
            mess = "🦍 Это горилла!"
        else:
            # Иначе считаем, что это человек
            mess = "🧑‍🦲 Это человек!"
        
        # Отправка результата классификации пользователю в чат
        bot.send_message(chat_id, mess)
        
        # Увеличение счетчика предсказаний для пользователя 
        increment_prediction_count(user_id)
        
        # Удаление user_id из словаря обработчиков следующего шага
        # Завершает текущий этап взаимодействия с пользователем
        next_step_handlers.pop(user_id, None)
    
    # Обработка любых ошибок, возникших во время выполнения
    except Exception as e:
        # Запись ошибки в лог для отладки
        logging.error(f"Ошибка обработки изображения: {str(e)}")
        # Отправка сообщения об ошибке пользователю
        bot.send_message(chat_id, f"Ошибка обработки изображения: {str(e)}")

# Обработчик для корневого маршрута
@app.route('/', methods=['GET']) # базовый адрес веб-приложения
def index():
    logging.info(f"Root endpoint accessed from {request.remote_addr}")
    return "This is a Telegram bot webhook server. Use the /webhook endpoint for bot interactions.", 200

# Webhook обработчик
@app.route('/webhook', methods=['POST'])
def webhook():
    logging.info(f"Webhook received: {request.get_json()}")
    update = telebot.types.Update.de_json(request.get_json())
    if update.message:
        chat_id = update.message.chat.id
        user_id = str(update.message.from_user.id)
        text = update.message.text
        photo = update.message.photo

        # Обработка следующего шага
        if user_id in next_step_handlers:
            handler = next_step_handlers[user_id]
            if handler == 'get_pincode':
                handle_get_pincode(chat_id, user_id, text)
            elif handler == 'check_pincode':
                handle_check_pincode(chat_id, user_id, text)
            elif handler == 'process_delete_user':
                handle_process_delete_user(chat_id, user_id, text)
            elif handler == 'process_promote_user':
                handle_process_promote_user(chat_id, user_id, text)
            elif handler == 'classificator' and photo:
                handle_classificator(chat_id, user_id, photo)
            return Response(status=200)

        # Обработка команд
        if text:
            if text == '/start':
                handle_start(chat_id, user_id)
            elif text == '/register':
                handle_register(chat_id, user_id)
            elif text == '/login':
                handle_login(chat_id, user_id)
            elif text == '/logout':
                handle_logout(chat_id, user_id)
            elif text == '/admin_users':
                handle_admin_users(chat_id, user_id)
            elif text == '/admin_delete':
                handle_admin_delete(chat_id, user_id)
            elif text == '/admin_promote':
                handle_admin_promote(chat_id, user_id)
            elif text == '/predict':
                handle_predict(chat_id, user_id)
            else:
                bot.send_message(chat_id, "❓ Я не понимаю эту команду. Используйте /start, /register, /login, /logout, /predict, /admin_users, /admin_delete или /admin_promote.")
        elif photo:
            if check_user_exists(user_id):
                if is_logged_in(user_id):
                    handle_classificator(chat_id, user_id, photo)
                else:
                    bot.send_message(chat_id, 'Сначала выполните вход через /login')
            else:
                bot.send_message(chat_id, 'Вы не зарегистрированы. Пожалуйста, зарегистрируйтесь с помощью команды /register.')
    return Response(status=200)

# Регистрация webhook
def set_webhook():
    bot.remove_webhook()
    response = bot.set_webhook(url=WEBHOOK_URL)
    if response:
        logging.info(f"Webhook установлен: {WEBHOOK_URL}")
    else:
        logging.error("Ошибка при установке webhook")

if __name__ == '__main__':
    set_webhook()
    app.run(host='0.0.0.0', port=5000)