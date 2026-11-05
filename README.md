# Yandex Search Guard 0.2.0

Самостоятельный проект: OWUI (engine=yandex) -> guard -> Yandex Search API.
Внешний endpoint: POST /v2/web/search. Это НЕ external engine /search из 0.1.0.
Работа через официальный API Яндекса, не через scraping yandex.ru.
Модель, Yandex account и API-ключ в архив не включены.

## 1. Запуск

Распакуйте в отдельный каталог, не поверх 0.1.0. Если старая версия запущена,
сначала остановите её сервис (занимает 8091), но не удаляйте volume.
Миграции БД 0.1.0 нет. Для новой версии используйте отдельный Compose project:

    python3 init.py
    docker compose -p yandex-search-guard up -d --build
    docker compose -p yandex-search-guard ps
    docker compose -p yandex-search-guard logs --tail=50

init.py создаёт .env (0600), никогда не перезаписывает его. Читать локально:

    cat .env

Не передавайте секреты в чат и Git. ADMIN_PASSWORD для панели,
SEARCH_TOKEN только для подключения OWUI. Они разные.
Панель слушает только http://127.0.0.1:8091. Для удалённого сервера:

    ssh -N -L 8091:127.0.0.1:8091 user@docker-host

Открыть на рабочем компьютере http://127.0.0.1:8091. HTTP Basic Auth:
ADMIN_USER/ADMIN_PASSWORD из .env. Для постоянного сетевого доступа нужны
HTTPS reverse proxy, ограничение администраторов и rate limit.
Встроенной защиты от перебора паролей нет. Не публикуйте HTTP Basic наружу.

## 2. Панель

Настройте модель:
- OpenAI-compatible API base: например http://host.docker.internal:11434/v1.
- Реальный ID уже загруженной non-thinking instruction-модели.
- Ключ, если требуется. Для LiteLLM нужен локальный маршрут без внешних fallback.
- API base вводится БЕЗ /chat/completions: этот суффикс добавляет шлюз.
- JSON mode можно отключить, если сервер его не поддерживает; строгая проверка
  ответа остаётся. Допустим ровно {"decision":"ALLOW"} или {"decision":"BLOCK"}.
  Модель обязана закончить ответ с finish_reason=stop. Лимит вывода 64 токена.
- Пока модель не задана или неисправна, поиск блокируется, rules-only fallback нет.

Настройте Яндекс:
- Настоящий API-ключ с разрешением yc.search-api.execute.
- folderId рабочего каталога.
- searchType и регион (по умолчанию SEARCH_TYPE_RU, 225).
Ключ/каталог нужны сервисному аккаунту с ролью search-api.webSearch.user.
URL Яндекса зафиксирован в коде: https://searchapi.api.cloud.yandex.net/v2/web/search
В версии 0.2 используется API-ключ (не IAM-токен с автоматическим обновлением).
Сохранённые ключи не возвращаются панелью; пустое поле сохраняет прежний ключ.
Отдельной кнопки удаления ключей пока нет. Volume и backup содержат секреты
в незашифрованном виде. Защитите доступ к Docker-хосту и резервным копиям.

Правила: секреты/credentials обязательны; email/телефоны/IP переключаемые.
Внутренние домены и запрещённые подстроки задаются строками, без regex.
Телефонное правило консервативное — может блокировать обычные длинные номера.
Сохраните настройки перед проверкой. Кнопка проверки НЕ вызывает Яндекс,
но передаёт текст настроенному API классификатора — проверьте его маршрут.

## 3. Общая сеть с OWUI

    docker network create ai-egress
    docker compose -p yandex-search-guard -f compose.yaml -f compose.network.yaml up -d --build

compose.network.yaml подключает шлюз к внешней сети ai-egress. Далее во ВСЕХ
командах Compose используйте те же -p и -f, чтобы не потерять конфигурацию сети.
Либо объедините этот override с основным compose.yaml.

Добавьте сеть ai-egress в существующий Compose OWUI. Сохраните все прежние
сети! Файл owui.compose.example.yaml — пример фрагмента, а не полный OWUI stack.
Не запускайте пример как отдельный OWUI проект.
Если классификатор в другом контейнере, подключите и его к доступной общей сети
или используйте адрес Docker-хоста. Дополнительная сеть сама по себе не
запрещает выход в интернет.

Для быстрого временного теста вместо правки Compose OWUI:

    docker network connect ai-egress ИМЯ_КОНТЕЙНЕРА_OWUI

Это подключение исчезает после пересоздания контейнера, поэтому затем
закрепите сеть в Compose OWUI.

## 4. Настройки OWUI

В существующий environment сервиса OWUI:

    ENABLE_WEB_SEARCH: "True"
    WEB_SEARCH_ENGINE: "yandex"
    YANDEX_WEB_SEARCH_URL: "http://search-guard:8000/v2/web/search"
    YANDEX_WEB_SEARCH_API_KEY: "ЗНАЧЕНИЕ_SEARCH_TOKEN_ИЗ_ENV_ШЛЮЗА"
    YANDEX_WEB_SEARCH_CONFIG: '{"query":{"searchType":"SEARCH_TYPE_RU"}}'

Это НЕ настоящий API-ключ Яндекса: его хранит только шлюз.
Входной Authorization поддерживает Api-Key и Bearer с SEARCH_TOKEN.
Шлюз всегда заменяет исходящую авторизацию на настоящий Api-Key Яндекса.
Входные X-OpenWebUI-* и другие заголовки провайдеру не пересылаются.

Если в OWUI уже сохранены PersistentConfig-настройки, переменные окружения
могут не переопределить их. Проверьте/измените текущие параметры в Admin Settings
или через поддерживаемый вашей версией OWUI способ управления конфигурацией.
Не сбрасывайте всю БД и не отключайте PersistentConfig вслепую.
После изменения environment обычно требуется пересоздание сервиса OWUI.

Важная особенность: прокси сохраняет JSON ответ Яндекса с rawData, а не
возвращает массив link/title/snippet. Декодированием выдачи занимается OWUI.
При BLOCK HTTP 403 — OWUI может показать общую ошибку поиска; точную причину
смотрите в панели шлюза. Не генерируется фиктивная поисковая выдача.

## 5. Проверка

В панели (синтетические данные):
- PostgreSQL replication slot disk usage -> ALLOW при рабочей модели;
- private@example.com -> BLOCK / EMAIL, модель и Яндекс не вызываются;
- password=test-only-not-real -> BLOCK / CREDENTIAL;
- остановить модель, проверить обычный текст -> BLOCK / MODEL_ERROR.

End-to-end через Яндекс, может тарифицироваться:

    set -a; . ./.env; set +a
    curl -i http://127.0.0.1:8091/v2/web/search \
      -H "Authorization: Api-Key $SEARCH_TOKEN" \
      -H 'Content-Type: application/json' \
      --data '{"query":{"queryText":"PostgreSQL replication slot disk usage","searchType":"SEARCH_TYPE_RU"},"responseFormat":"FORMAT_XML"}'

При успехе: HTTP 200, JSON с rawData. При BLOCK: HTTP 403, фиксированный code,
request_id, X-Guard-Decision. Недоступный Яндекс: 502 / YANDEX_ERROR.
Нет ключа/folderId: 503 / YANDEX_NOT_CONFIGURED. Невалидный payload: 422.
Для проверки отсутствия вызовов провайдера используйте тесты с mocks ниже,
затем сетевой мониторинг/метрики Яндекса при приёмке в реальном окружении.

## 6. Тесты

    docker compose -p yandex-search-guard -f compose.yaml -f compose.network.yaml \
      run --rm --no-deps -v "$PWD/tests:/app/tests:ro" search-guard \
      python -m unittest discover -s tests -v

12 интеграционных тестов используют временную БД и mocks, внешние вызовы
не выполняют. Отчёт VALIDATION.json отражает проверки, выполненные при
подготовке архива. Docker build, FastAPI интеграция, реальная LLM и Яндекс
в среде подготовки не запускались. Не считайте их подтверждёнными.

## 7. Ограничения и границы защиты

Шлюз не прозрачен ко ВСЕМ параметрам API: он пересобирает payload по allowlist.
Клиентский folderId, searchType и region заменяются серверными настройками.
queryText нормализуется перед проверкой; именно проверенный текст уходит
Яндексу. page, familyMode, fixTypoMode, responseFormat и groupSpec проходят
строгую проверку. sortSpec, maxPassages, l10N, userAgent допускаются во входном
контракте для совместимости, но не пересылаются. Неизвестные поля отвергаются.
Поэтому нельзя спрятать исходящий текст в userAgent или ином метаполе.
Лимиты: query 4096 символов, POST body 64 KiB, 4 параллельных задачи,
до 2 секунд ожидания слота, один worker. Переполнение даёт 503 / BUSY.

HTTP redirects, trust_env proxies отключены. Нет fallback, обезличивания,
SSO/RBAC, полноценного аудита изменений конфигурации и сертификации DLP.
Малая LLM может ошибаться; кодировки, обфускация и prompt injection не
гарантированно выявляются. Regex не покрывают все паспорта/СНИЛС/ИНН/секреты.
Нужен собственный тестовый набор русскоязычных кейсов и настройка словарей.

Журнал: последние 10000 решений (панель показывает 200), без текста запросов,
ответов модели/Яндекса, user IDs и query hash. Лог доступа uvicorn выключен.
Проверьте, что прокси, LLM backend, LiteLLM и APM не записывают содержимое.
Ключи в SQLite не шифруются. Администратор панели может менять URL модели
и политику и считается доверенным. Нужны сеть/права/backup policy.

Защищается только маршрут Yandex search через этот URL. Основная LLM,
fetch_url, чтение найденных страниц, MCP/Tools и прямые HTTP вызовы не защищены.
Пользователь или администратор с альтернативным инструментом может обойти
маршрут. Для обязательного контроля нужен egress firewall, а не только сеть
Docker: OWUI не должен иметь бесконтрольный выход к поисковым API.
Для постоянной эксплуатации используйте HTTPS, rate limit и мониторинг.
Зависимости зафиксированы для прототипа; перед production обновите/проверьте
уязвимости. Backup SQLite делать штатным backup API или при остановленном
контейнере. Не удаляйте volume командой down -v без резервной копии.

## Официальные контракты

OWUI Yandex:
https://docs.openwebui.com/features/chat-conversations/web-search/providers/yandex
Yandex Search API:
https://yandex.cloud/ru/docs/search-api/operations/web-search-sync
