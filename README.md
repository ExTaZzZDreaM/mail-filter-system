# Mail Filter System

Учебный почтовый сервер с фильтрацией входящих писем. Принимает почту по SMTP, проверяет каждое письмо (SPF, DKIM, DMARC, репутация IP отправителя, антивирусная проверка вложений) и раскладывает письма в ящики пользователей или в карантин. Есть веб-интерфейс для пользователей и администратора.

> ⚠️ Проект находится в стадии прототипа и **не предназначен для продакшена**. Список известных проблем приведён в разделе [Известные ограничения](#известные-ограничения).

## Возможности

- **SMTP-сервер** (порт `587`) на базе [`mhale/smtpd`]: принимает письма только для зарегистрированных адресов домена.
- **Разбор MIME**: `text/plain`, `text/html`, `multipart/mixed|alternative|related`, вложения и встроенные файлы (base64 / 7bit / 8bit).
- **Цепочка проверок** (`backend/internal/service/mailService/validator`):
  | Проверка | Что делает |
  |---|---|
  | SPF | Проверяет, может ли IP отправителя слать почту от имени домена (`ip4`, `ip6`, `a`, `mx`, `include`, `all`) |
  | DKIM | Проверяет подпись `DKIM-Signature` (только `rsa-sha256`) |
  | DMARC | Блокирует письмо, если у домена политика `p=reject`, а SPF или DKIM не прошли |
  | AbuseIPDB | Блокирует IP с abuse-score > 50 |
  | VirusTotal | Загружает вложения на проверку и блокирует письмо при срабатывании хотя бы одного движка |
- **Карантин**: письма, не прошедшие проверку, группируются по причине блокировки и доступны администратору.
- **HTTP API** (порт `8080`) и **React-клиент**: регистрация, вход, просмотр почты; для администратора — карантин и активация новых пользователей.

## Архитектура

```
             SMTP :587                       HTTP :8080
 Отправитель ─────────► mailHandler      React UI ─────────► backendHandler
                            │                                    │
                            ▼                                    ▼
                       mailService ── validator ──►      backendService
                            │      (SPF/DKIM/DMARC,             │
                            │       AbuseIPDB, VirusTotal)      │
                            ▼                                    ▼
                  mailStorage (в памяти)            userStorage (PostgreSQL)
```

```
mail-filter-system/
├── backend/                 Go-сервер (module mail_server)
│   ├── cmd/main.go          точка входа: запуск SMTP и HTTP серверов
│   ├── check/main.go        утилита для отправки тестового письма с вложением
│   ├── config.json          адреса SMTP/HTTP серверов
│   ├── init.sql             схема БД и тестовые пользователи
│   ├── Dockerfile           образ PostgreSQL с init.sql
│   ├── internal/
│   │   ├── handler/         SMTP- и HTTP-обработчики
│   │   ├── service/         бизнес-логика и валидаторы
│   │   └── repo/            хранилища писем (память) и пользователей (Postgres)
│   ├── models/              структуры Mail и User
│   └── utils/parser.go      MIME-парсер
└── frontend/                React (Create React App) + Bootstrap
```

## Быстрый старт

### Требования

- Go 1.24+
- Node.js 18+ и npm
- Docker (для PostgreSQL)

### 1. База данных

```bash
cd backend
docker build -t mail-db .
docker run -d --name mail-db -p 5432:5432 mail-db
```

Будет создана БД `mail` с таблицей `staff` и тестовыми пользователями из `init.sql` (`jdoe` — администратор, `jsmith` — пользователь, `mjohnson` — неактивный). Пароли хранятся как bcrypt-хеши (через `pgcrypto`). Если контейнер был создан со старой версией `init.sql` (пароли открытым текстом), пересоздайте его: `docker rm -f mail-db` и запустите заново.

### 2. Переменные окружения

Шаблон — `backend/.env.example`. Сам `.env` в git не попадает.

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `DATABASE_URL` | `host=localhost user=postgres password=postgres dbname=mail sslmode=disable` | Подключение к PostgreSQL |
| `CORS_ORIGIN` | `http://localhost:3000` | Origin фронтенда, которому разрешён доступ к API |
| `ABUSEIPDB_API_KEY` | — | Ключ [AbuseIPDB](https://www.abuseipdb.com/); без него проверка IP пропускается |
| `VIRUSTOTAL_API_KEY` | — | Ключ [VirusTotal](https://www.virustotal.com/); без него проверка вложений пропускается |

### 3. Backend

```bash
cd backend
go run ./cmd
```

Тесты:

```bash
cd backend
go test ./...
```

`config.json` читается из текущей директории:

```json
{
  "smtp_addr": ":587",
  "http_addr": ":8080"
}
```

Почтовый домен (`test.com`) пока захардкожен в `cmd/main.go` и `backendService`.

### 4. Frontend

```bash
cd frontend
npm install
npm start
```

Интерфейс откроется на http://localhost:3000, API ожидается на `http://localhost:8080`.

### 5. Отправка тестового письма

`backend/check/main.go` отправляет письмо на `john.doe@test.com` с вложением `./kk.exe` (файл нужно положить рядом):

```bash
cd backend/check
go run .
```

## HTTP API

Все защищённые методы требуют заголовок `Authorization: Bearer <token>`.

| Метод | Путь | Доступ | Описание |
|---|---|---|---|
| POST | `/register` | все | `{first_name, last_name, password}` → `201 {message, username}`; создаёт неактивного пользователя, логин = `FirstName+LastName`, адрес = `<логин>@test.com`. `409`, если такой логин уже есть |
| POST | `/auth` | все | `{username, password}` → `{token}` (токен живёт 24 часа); `403`, если аккаунт ещё не активирован |
| GET | `/mails` | пользователь | Письма текущего пользователя |
| GET | `/is_admin` | пользователь | `200`, если пользователь администратор |
| GET | `/blocked-mails` | админ | Заблокированные письма, сгруппированные по причине |
| GET | `/inactive` | админ | Список неактивных пользователей |
| POST | `/update-status` | админ | `{username}` → активирует пользователя |

## Известные ограничения

Проект — прототип; перед любым реальным использованием нужно исправить как минимум следующее.

**Безопасность**
- HTTP и SMTP работают без TLS.
- Сессии хранятся в памяти процесса и теряются при перезапуске.
- Ключи API и ACME-ключ убраны из кода и из индекса git, но **остаются в истории коммитов** — их нужно перевыпустить.

**Корректность**
- SPF проверяется для фиксированного адреса `asd@yandex.kz`, а не для реального отправителя; механизм `all` перехватывается веткой `a`.
- Реализация DKIM неполная (не проверяется `bh=`, неверно разбирается `c=relaxed/relaxed`), поэтому корректно подписанные письма могут блокироваться.
- Письмо доставляется по заголовку `To`, а не по SMTP-конверту: получатели из `Cc`/`Bcc` письмо не получают, а при нескольких получателях всё попадает в ящик первого.
- Письма хранятся только в памяти и пропадают при перезапуске.

## Лицензия

Не указана.

[`mhale/smtpd`]: https://github.com/mhale/smtpd
