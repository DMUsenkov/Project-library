# Система управления библиотекой

Этот проект представляет собой систему управления библиотекой, реализованную с использованием Flask, Flask-Login, Flask-SQLAlchemy и JWT для аутентификации. Система включает регистрацию и вход пользователей, управление ролями (администратор и читатель), управление книгами и отслеживание аренды. Backend контейнеризован с помощью Docker, с отдельными микросервисами для базы данных PostgreSQL и приложения Flask.

## Особенности

- Регистрация и вход пользователей с аутентификацией JWT.
- Управление ролями доступа (администратор и читатель).
- Управление книгами (добавление, просмотр доступных книг).
- Отслеживание аренды книг.
- Эндпоинт для обновления токена.
- Документация API с использованием Swagger

## Эндпоинты

### Эндпоинты пользователя

- **Регистрация**: `POST /register/`
  - Регистрация нового пользователя.
  - Тело запроса:
    ```json
    {
      "username": "User",
      "password": "password123",
      "email": "user@mail.ru",
      "role": "admin"
    }
    ```
  - Ответы:
    - `201 Created`: Регистрация успешна.
    - `400 Bad Request`: Пользователь уже существует.

- **Вход**: `POST /login/`
  - Вход пользователя.
  - Тело запроса:
    ```json
    {
      "username": "User",
      "password": "password123"
    }
    ```
  - Ответы:
    - `200 OK`: Вход успешен.
    - `401 Unauthorized`: Неверное имя пользователя или пароль.

- **Выход**: `POST /logout/`
  - Выход текущего пользователя.
  - Ответы:
    - `200 OK`: Выход успешен.

### Эндпоинты книг

- **Панель управления**: `GET /dashboard/`
  - Просмотр списка книг.
  - Ответы:
    - `200 OK`: Список книг.

- **Добавить книгу**: `POST /add_book/`
  - Добавление новой книги (только для администратора).
  - Тело запроса:
    ```json
    {
      "title": "Book Title",
      "author": "Author Name",
      "genre": "Genre",
      "total_copies": 1
    }
    ```
  - Ответы:
    - `201 Created`: Книга успешно добавлена.
    - `403 Forbidden`: Доступ запрещен.

### Эндпоинты аренды

- **Аренда книги**: `POST /rent_book/<int:book_id>/`
  - Аренда книги (только для читателей).
  - Ответы:
    - `200 OK`: Книга успешно арендована.
    - `400 Bad Request`: Нет доступных копий.
    - `403 Forbidden`: Администраторы не могут арендовать книги.

### Эндпоинты токенов

- **Обновить токен**: `POST /refresh/`
  - Обновление токена доступа.
  - Тело запроса:
    ```json
    {
      "refresh_token": "refresh_token"
    }
    ```
  - Ответы:
    - `200 OK`: Токен доступа успешно обновлен.
    - `401 Unauthorized`: Неверный или истекший токен обновления.

## Swagger

Для документирования API используется Swagger. Swagger предоставляет интерактивную документацию, которая позволяет разработчикам легко понять и протестировать эндпоинты API. Swagger UI автоматически генерирует документацию на основе аннотаций в коде.

## Настройка Docker

Проект использует Docker для контейнеризации базы данных PostgreSQL и приложения Flask. Настройка Docker включает два микросервиса:

1. **База данных PostgreSQL**: Работает на порту 5432.
2. **Приложение Flask**: Работает на порту 5005.

### Команды Docker

- Собрать Docker-образы:
  ```sh
  docker compose build 
  ```

- Запустить Docker-контейнеры:
  ```sh
  docker compose up
  ```

- Остановить Docker-контейнеры:
  ```sh
  docker compose down
  ```

## Структура проекта

```
library-management-system/
│
├── app/
│   ├── __init__.py
│   ├── models.py
│   ├── routes.py
│   │── auth.py
│   ├── utils.py
│   └── config.py
│
├── run.py
│   
│
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```
