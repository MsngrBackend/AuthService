# Auth Service

Микросервис авторизации. Отвечает за регистрацию пользователей, вход, выдачу токенов и управление сессиями.

---

## Что делает этот сервис

Когда пользователь открывает приложение и хочет войти — всё проходит через этот сервис:

```
Клиент (браузер/приложение)
        │
        ▼
  Auth Service :8081
        │
        ├── PostgreSQL  — хранит пользователей и сессии (постоянно)
        └── Redis       — хранит временные коды (письмо с подтверждением)
```

### Что хранится в базах данных

**PostgreSQL** — основная БД, данные хранятся навсегда:
- `users` — таблица пользователей: email, хэш пароля, подтверждён ли email
- `sessions` — активные сессии: у кого, с какого IP, до какого времени

**Redis** — быстрое хранилище с таймером, данные сами удаляются через N минут:
- Коды подтверждения email (`123456`)
- Коды сброса пароля

---

## Как работает авторизация (JWT)

Сервис выдаёт **два токена** при входе:

| Токен | Что это | Живёт |
|---|---|---|
| `access_token` | JWT — короткий, подтверждает кто ты | 15 минут |
| `refresh_token` | Длинный случайный ключ, хранится в БД | 30 дней |

**Сценарий:**
1. Пользователь входит → получает оба токена
2. На каждый запрос к API передаёт `access_token` в заголовке
3. Через 15 минут `access_token` истекает → клиент отправляет `refresh_token`, получает новую пару
4. Если пользователь не заходил 30 дней → нужно войти заново

Пароли хранятся в виде **bcrypt-хэша** — даже если БД утечёт, пароли не восстановить.

---

## Эндпоинты

| Метод | URL | Зачем |
|---|---|---|
| POST | `/api/v1/auth/register` | Зарегистрировать пользователя |
| POST | `/api/v1/auth/register/confirm` | Подтвердить email по коду |
| POST | `/api/v1/auth/login` | Войти, получить токены |
| POST | `/api/v1/auth/refresh` | Обновить access token |
| POST | `/api/v1/auth/logout` | Выйти (удалить сессию) |
| GET  | `/api/v1/auth/sessions` | Список моих активных сессий |
| DELETE | `/api/v1/auth/sessions/:id` | Завершить конкретную сессию |
| GET  | `/healthz` | Проверить что сервис жив |

🔒 — последние 3 требуют `Authorization: Bearer <access_token>` в заголовке.

---

## Структура кода (для понимания)

```
AuthService/
├── cmd/
│   └── main.go              ← точка входа, запуск сервера
│
├── internal/
│   ├── config/
│   │   └── config.go        ← читает настройки из переменных окружения (.env)
│   │
│   ├── model/
│   │   ├── user.go          ← структура User (как строка в таблице users)
│   │   └── session.go       ← структура Session
│   │
│   ├── repository/          ← работа с БД (SQL-запросы)
│   │   ├── user_repo.go     ← create, findByEmail, markVerified...
│   │   └── session_repo.go  ← create, list, delete, rotate...
│   │
│   ├── cache/
│   │   └── redis.go         ← сохранить/получить/удалить код в Redis
│   │
│   ├── service/
│   │   └── auth.go          ← бизнес-логика: Register, Login, Refresh...
│   │                           здесь пароли хэшируются, токены генерируются
│   └── handler/
│       ├── auth.go          ← HTTP-хендлеры: читают запрос, вызывают service,
│       │                       пишут JSON-ответ
│       └── middleware.go    ← проверяет JWT перед защищёнными эндпоинтами
│
├── migrations/
│   └── 001_init.sql         ← SQL-скрипт создания таблиц (запускается 1 раз)
│
├── Dockerfile               ← как собрать сервис в Docker-контейнер
├── docker-compose.yml       ← запустить сервис + postgres + redis одной командой
└── .env.example             ← пример конфига (скопировать в .env)
```

**Поток запроса** (пример: login):
```
HTTP POST /api/v1/auth/login
    │
    ▼
handler/auth.go → Login()        читает JSON из запроса
    │
    ▼
service/auth.go → Login()        проверяет пароль, создаёт сессию
    │
    ├── repository/user_repo.go  → FindByEmail() — SELECT из PostgreSQL
    ├── bcrypt.CompareHashAndPassword()          — проверяет пароль
    └── repository/session_repo.go → Create()   — INSERT в PostgreSQL
    │
    ▼
handler/auth.go                  возвращает { access_token, refresh_token }
```

---

## Как запустить

### Требования

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) — нужен для запуска PostgreSQL и Redis
- [Go 1.23+](https://go.dev/dl/) — нужен если запускать без Docker

Проверить что установлено:
```bash
docker --version   # Docker version 27.x.x
go version         # go version go1.23.x
```

---

### Вариант 1 — Docker (рекомендуется, ничего не нужно настраивать)

```bash
# 1. Перейти в папку сервиса
cd AuthService

# 2. Скопировать файл с настройками
cp .env.example .env

# 3. Запустить всё (PostgreSQL + Redis + сервис)
docker compose up --build
```

Первый запуск скачает образы и соберёт сервис (~1-2 мин).

Успешный запуск выглядит так:
```
auth-1      | postgres: connected
auth-1      | redis: connected
auth-1      | auth service listening on :8081
```

Остановить: `Ctrl+C`, или `docker compose down`

---

### Вариант 2 — Запуск напрямую через Go

Если PostgreSQL и Redis уже запущены локально:

```bash
# 1. Перейти в папку сервиса
cd AuthService

# 2. Скачать зависимости
go mod tidy

# 3. Запустить
go run ./cmd/main.go
```

---

### Вариант 3 — Только базы данных в Docker, сервис локально

Удобно для разработки — перезапуск мгновенный:

```bash
# Запустить только postgres и redis
docker compose up postgres redis -d

# Запустить сервис
go run ./cmd/main.go
```

---

## Как тестировать

### Через Test UI (самый простой способ)

1. Запустить сервис (любым вариантом выше)
2. Открыть файл `../test-ui/index.html` в браузере
3. Сценарий:
   - **register** → в логе появится `confirm_code` и автоматически заполнит форму confirm
   - **confirm** → подтвердить email
   - **login** → токены сохранятся в панели «Хранилище токенов»
   - **sessions** → увидеть активные сессии
   - **logout** → завершить сессию

### Через curl (из терминала)

```bash
# Регистрация
curl -X POST http://localhost:8081/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"12345678"}'

# Ответ: {"confirm_code":"123456","message":"..."}

# Подтверждение email (вставить код из ответа выше)
curl -X POST http://localhost:8081/api/v1/auth/register/confirm \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","code":"123456"}'

# Вход
curl -X POST http://localhost:8081/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"12345678"}'

# Ответ: {"access_token":"eyJ...","refresh_token":"a1b2c3...","expires_in":900}

# Список сессий (вставить access_token из ответа выше)
curl http://localhost:8081/api/v1/auth/sessions \
  -H "Authorization: Bearer eyJ..."
```

### Проверить что сервис запущен

```bash
curl http://localhost:8081/healthz
# {"status":"ok"}
```

---

## Частые ошибки

**`connection refused`** — сервис не запущен или запускается на другом порту.

**`postgres ping: ...`** — PostgreSQL не запущен. Проверь `docker compose up postgres`.

**`email not verified`** при логине — нужно сначала подтвердить email через `/register/confirm`.

**`invalid or expired token`** — access token истёк (15 мин), используй `/refresh`.

---

## Переменные окружения (.env)

| Переменная | По умолчанию | Описание |
|---|---|---|
| `HTTP_PORT` | `8081` | Порт сервиса |
| `POSTGRES_HOST` | `postgres` | Хост БД |
| `POSTGRES_PASSWORD` | `postgres` | Пароль БД |
| `JWT_ACCESS_SECRET` | `change-me-...` | Секрет для подписи JWT — **поменяй в production** |
| `JWT_ACCESS_TTL` | `15m` | Время жизни access token |
| `JWT_REFRESH_TTL` | `720h` | Время жизни refresh token (30 дней) |
| `EMAIL_CODE_TTL` | `15m` | Время жизни кода подтверждения email |
