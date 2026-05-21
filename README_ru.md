# ZenithSSO

ZenithSSO — это легко настраиваемый провайдер аутентификации (Identity Provider, IdP), написанный на Go с использованием принципов чистой архитектуры. Он реализует стандарты OAuth2/OIDC и предоставляет интерфейсы REST API и gRPC для удобной интеграции.

## Справочник по конфигурации (`config.yaml`)

| Параметр | Описание | По умолчанию / Пример |
| :--- | :--- | :--- |
| `grpc.port` | Порт для gRPC сервера | `50051` |
| `grpc.tls.enabled` | Включить TLS для gRPC | `true` |
| `grpc.tls.cert_path` | Путь к TLS сертификату | `./certs/server.crt` |
| `grpc.tls.key_path` | Путь к закрытому ключу TLS | `./certs/server.key` |
| `sso.issuer` | Базовый URL провайдера (Identity Provider) | `http://localhost:8080` |
| `server.secured` | Использовать безопасные cookies (требует HTTPS) | `true` |
| `server.port` | Порт для HTTP сервера | `8080` |
| `datasource.url` | URL подключения к базе данных PostgreSQL | `195.208.118.156:5432` |
| `datasource.db` | Имя базы данных PostgreSQL | `auth` |
| `superuser.username` | Имя начального администратора | `admin` |
| `superuser.email` | Email начального администратора | `admin@admin.com` |
| `superuser.password` | Пароль начального администратора | `password` |
| `jwt.ttl.access` | Время жизни access токенов (TTL) | `1` |
| `jwt.ttl.refresh` | Время жизни refresh токенов | `15` |
| `jwt.ttl.unit` | Единица измерения времени для TTL (`s`, `m`, `h`) | `m` |
| `jwt.cleanup.interval` | Интервал очистки истекших токенов | `5` |
| `jwt.cleanup.unit` | Единица измерения времени для интервала | `m` |
| `jwt.private_key_path` | Путь к закрытому ключу RSA для подписи JWT | `certs/private.pem` |
| `jwt.public_key_path` | Путь к открытому ключу RSA для проверки JWT | `certs/public.pem` |
| `ui.custom_dir` | (Опционально) Путь к пользовательской директории UI для переопределения встроенного фронтенда. | `/path/to/custom/web` |

## Список эндпоинтов

### REST API Эндпоинты
* `GET /.well-known/openid-configuration` - Эндпоинт OIDC Discovery.
* `GET /api/v1/jwks` - Возвращает открытые ключи для проверки токенов.
* `POST /api/v1/register` - Регистрация нового аккаунта пользователя.
* `GET /api/v1/userinfo` - Получение информации об аутентифицированном пользователе.
* `POST /api/v1/token` - Обмен токенов (authorization code, refresh token, password grants).
* `GET /api/v1/authorize` - Запуск процесса авторизации OAuth2.
* `POST /api/v1/authorize` - Обработка входа пользователя во время авторизации.
* `GET /api/v1/consent` - Запрос согласия у пользователя.
* `POST /api/v1/consent` - Обработка согласия пользователя.

### UI Маршруты
* `GET /login`, `POST /login` - Отдельная страница входа пользователя.
* `POST /logout` - Выход пользователя.
* `GET /settings`, `POST /settings` - Управление профилем и сессиями пользователя.
* `POST /settings/revoke-session` - Отзыв определенной сессии.
* `GET /admin` - Админ-панель для управления пользователями и ролями.
* `POST /admin/scopes` - Создать новую роль (scope).
* `POST /admin/users/scopes` - Назначить роль пользователю.

### gRPC Сервис (`AuthService`)
Определен в `api/proto/auth.proto`.
* `rpc Token` - Операции обмена токенов.
* `rpc Authorize` - Headless авторизация для доверенных клиентов.
* `rpc UserInfo` - Получение информации о пользователе.
* `rpc Revoke` - Отзыв access или refresh токена.
* `rpc Sessions` - Список активных сессий пользователя.
* `rpc RevokeSession` - Отзыв определенной сессии или всех, кроме текущей.

## Кастомизация UI (Пользовательский интерфейс)

ZenithSSO поставляется со встроенным пользовательским интерфейсом. Тем не менее, вы можете легко переопределить HTML-шаблоны и статические файлы (CSS/JS) без перекомпиляции приложения.

1. **Создайте структуру директорий:**
   Создайте папку в любом месте на сервере, например, `/opt/zenithsso/custom_ui`. Внутри создайте две поддиректории: `templates` и `static`.
   ```bash
   mkdir -p custom_ui/templates
   mkdir -p custom_ui/static/css
   ```

2. **Добавьте ваши файлы:**
   Поместите измененные HTML-файлы в папку `templates/` (например, `login.html`, `admin.html`). Поместите CSS-файлы в `static/css/` (например, `style.css`). Убедитесь, что вы сохраняете имена файлов, ожидаемые сервером.

3. **Обновите `config.yaml`:**
   Укажите серверу путь к вашей новой директории с помощью параметра `ui.custom_dir`:
   ```yaml
   ui:
     custom_dir: "/opt/zenithsso/custom_ui"
   ```

После перезапуска ZenithSSO будет использовать ваши файлы вместо встроенных!