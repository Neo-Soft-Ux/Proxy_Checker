#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Proxy Checker v4.1 — проверка списков прокси (Tkinter, только stdlib).

Аудит-фиксы (v4.1):
  • убрано двойное TCP-соединение при проверке SOCKS (_alive_check открывает
    ровно одно соединение на эндпоинт)
  • кнопка «Сервисы…» блокируется на время проверки (устранена гонка с
    глобальными ALIVE_URLS / ECHO_URLS / GEO_BASE)
  • DNS-кэш с TTL 300 с вместо вечного

Из v4:
  • IPv6-прокси [2001:db8::1]:8080
  • резервные alive-эндпоинты (gstatic → google → cloudflare)
  • умный ретрай (повторяются только таймаут/нет ответа)
  • настраиваемые сервисы (диалог «Сервисы…», сохраняются в settings.json)
  • стабильная сортировка при живой проверке
  • запоминание настроек (%APPDATA%/ProxyChecker/settings.json)
  • ротация User-Agent, скоринг 0–100
  • всё из v3: RU/EN, автодополнение фильтра, анонимность, целевые URL,
    честный HTTPS, автосохранение, пауза, drag&drop, статистика
"""

import base64
import csv
import json
import locale
import os
import queue
import random
import re
import socket
import ssl
import threading
import time
import tkinter as tk
from collections import Counter, defaultdict
from dataclasses import dataclass
from tkinter import filedialog, messagebox, ttk
from urllib.request import Request, urlopen

try:                                   # drag&drop опционален
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except Exception:
    HAS_DND = False

# --------------------------------------------------------------------------
# Сервисы (редактируются в диалоге «Сервисы…», сохраняются в settings.json)
# --------------------------------------------------------------------------
DEFAULT_ALIVE = [
    "http://www.gstatic.com/generate_204",
    "http://www.google.com/generate_204",
    "http://cp.cloudflare.com/generate_204",
]
DEFAULT_ECHO = ["http://httpbin.org/get", "http://postman-echo.com/get"]
DEFAULT_GEO = "http://ip-api.com/json/"
ALIVE_URLS = list(DEFAULT_ALIVE)
ECHO_URLS = list(DEFAULT_ECHO)
GEO_BASE = DEFAULT_GEO

GEO_FIELDS = "status,message,country,countryCode,city,query"
GEO_RPM = 45
ECHO_DIRECT = [("http://httpbin.org/ip", "origin"),
               ("http://postman-echo.com/get", "origin")]

SETTINGS_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"),
                            "ProxyChecker")
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "settings.json")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]
USER_AGENT = USER_AGENTS[0]          # fallback, если UA не назначен

STATUS_ORDER = ("ok", "unreachable", "auth_required",
                "auth_failed", "target_fail", "error", "stopped")
RETRYABLE = {"timeout", "no_reply"}          # умный ретрай: что стоит повторять

C_BG, C_PANEL, C_CARD = "#16181f", "#1e222c", "#232837"
C_TEXT, C_DIM         = "#e8eaf0", "#8b93a7"
C_ACCENT, C_GREEN     = "#4f8cff", "#3ddc84"
C_RED, C_AMBER        = "#ff5c69", "#ffb454"
C_ROW                 = "#1b1f29"
FONT = ("Segoe UI", 9)

# --------------------------------------------------------------------------
# Локализация
# --------------------------------------------------------------------------
def _detect_lang():
    try:
        loc = (locale.getdefaultlocale()[0] or "").lower()
        return "ru" if loc.startswith("ru") else "en"
    except Exception:
        return "ru"

LANG = _detect_lang()

TR = {
"ru": {
    "ready": "Готов • загрузите список и нажмите «Старт»",
    "ready_dnd": "Готов • можно перетащить файл списка прямо в окно",
    "btn_load": "📂  Загрузить", "m_file": "Из файла…",
    "m_url": "По URL…", "m_clip": "Из буфера обмена…",
    "btn_start": "▶  Старт", "btn_pause": "⏸  Пауза",
    "btn_resume": "▶  Продолжить", "btn_stop": "■  Стоп",
    "btn_recheck": "↻  Перепроверить", "btn_export": "💾  Экспорт",
    "btn_stats": "📊  Статистика", "btn_services": "Сервисы…",
    "opt_timeout": "Таймаут, с", "opt_geo_timeout": "Гео-таймаут, с",
    "opt_retries": "Повторов", "opt_threads": "Потоки (0 — авто)",
    "opt_proxy_geo": "Гео через прокси", "opt_direct_geo": "Прямое гео (45/мин)",
    "opt_target": "Целевой сайт:", "btn_targets": "URL… ({n})",
    "opt_autosave": "Автосохранение рабочих", "btn_autosave": "Файл…",
    "opt_anon": "Определять анонимность", "opt_flags": "Флаги (эмодзи)",
    "filter_label": "Фильтр:", "filter_only_ok": "Только рабочие",
    "filter_status": "Статус:", "status_all": "Все статусы",
    "st_queued": "в очереди", "st_checking": "проверяется", "st_ok": "Рабочий",
    "st_unreachable": "Недоступен", "st_auth_required": "Нужна авторизация",
    "st_auth_failed": "Неверные данные", "st_target_fail": "Не проходит цель",
    "st_error": "Ошибка", "st_stopped": "Остановлено",
    "col_num": "№", "col_proxy": "Прокси", "col_type": "Тип",
    "col_status": "Статус", "col_ping": "Пинг", "col_score": "Оценка",
    "col_country": "Страна", "col_city": "Город", "col_exit": "Exit IP",
    "col_anon": "Анонимн.", "col_target": "Цель", "col_note": "Примечание",
    "ctx_copy": "Копировать адрес", "ctx_copy_all": "Копировать все выделенные",
    "ctx_recheck": "Перепроверить выделенные",
    "ctx_export": "Экспортировать выделенные…",
    "copied_one": "Скопировано: {a}",
    "copied_many": "Скопировано {n} прокси в буфер",
    "drop_hint": "Перетащите текстовый файл со списком прокси",
    "loaded": "Загружено {n} прокси",
    "loaded_bad": ", пропущено некорректных строк: {n}",
    "press_start": ". Нажмите «Старт».",
    "started": "Проверка запущена: {n} прокси • {t} потоков • таймаут {to} с • повторов {r}{tg}",
    "started_targets": " • цель: {n} URL",
    "autosave_nofile": "Автосохранение: не указан файл — отключено.",
    "resumed": "Продолжено.",
    "paused": "Пауза: новые проверки не начинаются, текущие завершатся.",
    "paused_label": "⏸ пауза",
    "stopped": "Остановлено: проверено {d}/{n} (рабочих {ok}).",
    "rechecking": "Перепроверка: {n} прокси…",
    "ok_found": "✔ {a} — {proto}, {ping}, {geo}{anon}",
    "done": "Готово: {ok} рабочих из {n} за {t}.",
    "err_none": "Ошибки: нет", "err_dash": "Ошибки: —", "err_prefix": "Ошибки: ",
    "err_more": " • ещё {n} видов",
    "prog": "{d}/{n} • рабочих {ok} • нерабочих {fail}",
    "live": "в работе: {a} • {s} прокси/мин • осталось ≈ {t}",
    "ms": "мс", "time_s": "{s} с", "time_ms": "{m} мин {s} с",
    "time_hm": "{h} ч {m} мин",
    "n_timeout": "таймаут", "n_no_conn": "нет соединения",
    "n_closed": "соединение закрыто", "n_not_socks": "это не SOCKS",
    "n_bad_creds_s5": "неверный логин/пароль (SOCKS5)",
    "n_s5_auth": "SOCKS5 требует авторизацию",
    "n_s5_method": "SOCKS5: метод отклонён",
    "n_s5_err": "SOCKS5: код {c}", "n_s4_err": "SOCKS4: код {c}",
    "n_s4_no_v6": "SOCKS4 не поддерживает IPv6",
    "n_connect_denied": "CONNECT отклонён",
    "n_no_connect_reply": "нет ответа на CONNECT",
    "n_tls_fail": "TLS handshake не удался", "n_no_reply": "нет ответа",
    "n_spoofed": "подмена ответа (это не прокси?)",
    "n_auth_http": "требуется авторизация",
    "n_creds_rejected": "прокси отклонил логин/пароль",
    "n_http": "HTTP {c}", "n_geo_unavail": "гео недоступно",
    "n_bad_url": "неверный URL: {u}", "n_target": "цель: {m}",
    "t_unreachable": "недоступен",
    "an_elite": "Элитный", "an_anon": "Анонимный", "an_transp": "Прозрачный",
    "url_title": "Загрузить список по URL",
    "url_label": "URL текстового файла со списком прокси\n(можно без схемы — https:// добавится автоматически):",
    "btn_ok": "Загрузить", "btn_cancel": "Отмена",
    "url_bad_scheme": "Поддерживаются только http:// и https://",
    "buf_title": "Список из буфера обмена",
    "buf_label": "Вставьте список (Ctrl+V), по одному прокси на строку:",
    "tgt_title": "Целевые URL",
    "tgt_help": "Формат: один URL на строку.\n    https://example.com/login\n    http://site.org/page\n    example.com/path        — без схемы, префикс добавится сам\nПрокси считается прошедшим, если ВСЕ URL ответили успешно (2xx/3xx).\nВключите галочку «Целевой сайт», чтобы проверка применялась.",
    "tgt_scheme": "Схема для строк без неё:", "btn_save": "Сохранить",
    "tgt_bad": "Поддерживаются только схемы http/https, строки пропущены:\n",
    "svc_title": "Настройки сервисов",
    "svc_help": "Если стандартные точки проверки недоступны в вашей сети — замените их здесь. Изменения сохраняются в settings.json.",
    "svc_alive": "Alive-проверка (URL, по одному на строку; «204» в URL — строгая проверка кода 204, иначе успех = 2xx/3xx):",
    "svc_echo": "Эхо-сервисы для определения анонимности (JSON с headers):",
    "svc_geo": "База гео-API (шаблон ip-api):",
    "svc_bad": "Некорректные строки пропущены:\n",
    "svc_need_alive": "Нужен хотя бы один корректный alive-URL.",
    "svc_saved": "Настройки сервисов сохранены.",
    "exp_title": "Экспорт результатов",
    "exp_selected": "Экспорт выделенных строк: {n} шт.",
    "exp_format": "Формат:", "fmt_proto": "протокол://ip:port",
    "fmt_full": "протокол://логин:пароль@ip:port", "fmt_csv": "CSV (все колонки)",
    "exp_only": "Только рабочие", "btn_saveas": "Сохранить…",
    "exp_none": "Нет данных для экспорта.",
    "exp_saved": "Сохранено {n} строк:\n{p}",
    "exp_error": "Не удалось сохранить файл:\n{e}",
    "stats_title": "Статистика проверки", "btn_close": "Закрыть",
    "stats_nodata": "Нет данных — сначала выполните проверку.",
    "st_total": "Всего в списке :", "st_checked": "Проверено      :",
    "st_working": "Рабочих        :", "st_ping": "Пинг           :",
    "st_score": "Средний балл   :", "st_types": "Типы           :",
    "st_anon": "Анонимность    :",
    "st_countries": "Страны (топ-10): ", "st_fast": "Лучшие по пингу (топ-10):",
    "st_reasons": "Причины отказов:", "st_nodata": "Нет данных",
    "st_min": "мин", "st_med": "медиана", "st_max": "макс",
    "fd_open_title": "Выберите файл со списком прокси",
    "fd_autosave_title": "Файл автосохранения рабочих прокси",
    "ft_text": "Текстовые файлы", "ft_all": "Все файлы",
    "mb_title": "Proxy Checker",
    "mb_read_err": "Не удалось прочитать файл:\n{e}",
    "mb_running": "Идёт проверка — сначала остановите её.",
    "mb_noproxies": "Не найдено ни одного корректного прокси.",
    "mb_wait": "Дождитесь завершения текущих проверок.",
    "ti_recheck": "Перепроверка", "mb_sel_rows": "Выделите строки в таблице.",
    "mb_recheck_nodata": "Нет прокси для перепроверки.",
    "mb_recheck_first": "Сначала выполните проверку.",
    "mb_load_first": "Сначала загрузите список.",
    "ti_export": "Экспорт", "ti_stats": "Статистика",
    "ti_autosave": "Автосохранение", "ti_services": "Сервисы",
    "mb_autosave_err": "Не удалось открыть файл:\n{e}",
    "ti_url": "URL", "ti_load": "Загрузка списка",
    "mb_download_err": "Не удалось скачать:\n{e}",
    "ti_targets": "Целевые URL",
},
"en": {
    "ready": "Ready • load a list and press “Start”",
    "ready_dnd": "Ready • you can drag & drop a list file into the window",
    "btn_load": "📂  Load", "m_file": "From file…",
    "m_url": "From URL…", "m_clip": "From clipboard…",
    "btn_start": "▶  Start", "btn_pause": "⏸  Pause",
    "btn_resume": "▶  Resume", "btn_stop": "■  Stop",
    "btn_recheck": "↻  Recheck", "btn_export": "💾  Export",
    "btn_stats": "📊  Statistics", "btn_services": "Services…",
    "opt_timeout": "Timeout, s", "opt_geo_timeout": "Geo timeout, s",
    "opt_retries": "Retries", "opt_threads": "Threads (0 = auto)",
    "opt_proxy_geo": "Geo via proxy", "opt_direct_geo": "Direct geo (45/min)",
    "opt_target": "Target site:", "btn_targets": "URL… ({n})",
    "opt_autosave": "Auto-save working", "btn_autosave": "File…",
    "opt_anon": "Detect anonymity", "opt_flags": "Flags (emoji)",
    "filter_label": "Filter:", "filter_only_ok": "Working only",
    "filter_status": "Status:", "status_all": "All statuses",
    "st_queued": "queued", "st_checking": "checking", "st_ok": "Working",
    "st_unreachable": "Unreachable", "st_auth_required": "Auth required",
    "st_auth_failed": "Bad credentials", "st_target_fail": "Target failed",
    "st_error": "Error", "st_stopped": "Stopped",
    "col_num": "#", "col_proxy": "Proxy", "col_type": "Type",
    "col_status": "Status", "col_ping": "Ping", "col_score": "Score",
    "col_country": "Country", "col_city": "City", "col_exit": "Exit IP",
    "col_anon": "Anonymity", "col_target": "Target", "col_note": "Note",
    "ctx_copy": "Copy address", "ctx_copy_all": "Copy all selected",
    "ctx_recheck": "Recheck selected",
    "ctx_export": "Export selected…",
    "copied_one": "Copied: {a}",
    "copied_many": "Copied {n} proxies to clipboard",
    "drop_hint": "Drop a text file with the proxy list",
    "loaded": "Loaded {n} proxies",
    "loaded_bad": ", skipped invalid lines: {n}",
    "press_start": ". Press “Start”.",
    "started": "Check started: {n} proxies • {t} threads • timeout {to} s • retries {r}{tg}",
    "started_targets": " • targets: {n} URL",
    "autosave_nofile": "Auto-save: no file chosen — disabled.",
    "resumed": "Resumed.",
    "paused": "Paused: no new checks will start; current ones will finish.",
    "paused_label": "⏸ paused",
    "stopped": "Stopped: checked {d}/{n} (working {ok}).",
    "rechecking": "Rechecking: {n} proxies…",
    "ok_found": "✔ {a} — {proto}, {ping}, {geo}{anon}",
    "done": "Done: {ok} working of {n} in {t}.",
    "err_none": "Errors: none", "err_dash": "Errors: —", "err_prefix": "Errors: ",
    "err_more": " • {n} more kinds",
    "prog": "{d}/{n} • working {ok} • failed {fail}",
    "live": "active: {a} • {s} proxies/min • ≈ {t} left",
    "ms": "ms", "time_s": "{s}s", "time_ms": "{m}m {s}s",
    "time_hm": "{h}h {m}m",
    "n_timeout": "timeout", "n_no_conn": "no connection",
    "n_closed": "connection closed", "n_not_socks": "not a SOCKS proxy",
    "n_bad_creds_s5": "wrong login/password (SOCKS5)",
    "n_s5_auth": "SOCKS5 requires auth",
    "n_s5_method": "SOCKS5: method rejected",
    "n_s5_err": "SOCKS5: code {c}", "n_s4_err": "SOCKS4: code {c}",
    "n_s4_no_v6": "SOCKS4 does not support IPv6",
    "n_connect_denied": "CONNECT denied",
    "n_no_connect_reply": "no reply to CONNECT",
    "n_tls_fail": "TLS handshake failed", "n_no_reply": "no reply",
    "n_spoofed": "spoofed reply (is it a proxy?)",
    "n_auth_http": "authorization required",
    "n_creds_rejected": "proxy rejected login/password",
    "n_http": "HTTP {c}", "n_geo_unavail": "geo unavailable",
    "n_bad_url": "invalid URL: {u}", "n_target": "target: {m}",
    "t_unreachable": "unreachable",
    "an_elite": "Elite", "an_anon": "Anonymous", "an_transp": "Transparent",
    "url_title": "Load list from URL",
    "url_label": "URL of a text file with the proxy list\n(scheme optional — https:// is added automatically):",
    "btn_ok": "Load", "btn_cancel": "Cancel",
    "url_bad_scheme": "Only http:// and https:// are supported",
    "buf_title": "Proxy list from clipboard",
    "buf_label": "Paste the list (Ctrl+V), one proxy per line:",
    "tgt_title": "Target URLs",
    "tgt_help": "Format: one URL per line.\n    https://example.com/login\n    http://site.org/page\n    example.com/path        — no scheme, the prefix is added automatically\nA proxy passes only if ALL URLs answer successfully (2xx/3xx).\nEnable the “Target site” checkbox to apply this check.",
    "tgt_scheme": "Scheme for lines without one:", "btn_save": "Save",
    "tgt_bad": "Only http/https schemes are supported, lines skipped:\n",
    "svc_title": "Service settings",
    "svc_help": "If the standard check endpoints are blocked in your network, replace them here. Changes are stored in settings.json.",
    "svc_alive": "Alive check (URLs, one per line; “204” in URL = strict 204 expected, otherwise 2xx/3xx counts as success):",
    "svc_echo": "Echo services for anonymity detection (JSON with headers):",
    "svc_geo": "Geo API base (ip-api template):",
    "svc_bad": "Invalid lines skipped:\n",
    "svc_need_alive": "At least one valid alive URL is required.",
    "svc_saved": "Service settings saved.",
    "exp_title": "Export results",
    "exp_selected": "Exporting selected rows: {n}",
    "exp_format": "Format:", "fmt_proto": "protocol://ip:port",
    "fmt_full": "protocol://login:password@ip:port", "fmt_csv": "CSV (all columns)",
    "exp_only": "Working only", "btn_saveas": "Save…",
    "exp_none": "No data to export.",
    "exp_saved": "Saved {n} rows:\n{p}",
    "exp_error": "Could not save file:\n{e}",
    "stats_title": "Check statistics", "btn_close": "Close",
    "stats_nodata": "No data — run a check first.",
    "st_total": "Total in list  :", "st_checked": "Checked        :",
    "st_working": "Working        :", "st_ping": "Ping           :",
    "st_score": "Average score  :", "st_types": "Types          :",
    "st_anon": "Anonymity      :",
    "st_countries": "Countries (top 10): ", "st_fast": "Best by ping (top 10):",
    "st_reasons": "Failure reasons:", "st_nodata": "No data",
    "st_min": "min", "st_med": "median", "st_max": "max",
    "fd_open_title": "Choose a proxy list file",
    "fd_autosave_title": "Auto-save file for working proxies",
    "ft_text": "Text files", "ft_all": "All files",
    "mb_title": "Proxy Checker",
    "mb_read_err": "Could not read file:\n{e}",
    "mb_running": "A check is running — stop it first.",
    "mb_noproxies": "No valid proxies found.",
    "mb_wait": "Wait for current checks to finish.",
    "ti_recheck": "Recheck", "mb_sel_rows": "Select rows in the table.",
    "mb_recheck_nodata": "No proxies to recheck.",
    "mb_recheck_first": "Run a check first.",
    "mb_load_first": "Load a list first.",
    "ti_export": "Export", "ti_stats": "Statistics",
    "ti_autosave": "Auto-save", "ti_services": "Services",
    "mb_autosave_err": "Could not open file:\n{e}",
    "ti_url": "URL", "ti_load": "List download",
    "mb_download_err": "Could not download:\n{e}",
    "ti_targets": "Target URLs",
},
}


def T(key, **kw):
    s = TR.get(LANG, {}).get(key) or TR["en"].get(key) or key
    return s.format(**kw) if kw else s


S5_MSGS = {
    "ru": {1: "ошибка SOCKS5", 2: "запрещено правилами", 3: "сеть недоступна",
           4: "хост недоступен", 5: "отказ в соединении", 6: "истёк TTL",
           7: "команда не поддерживается", 8: "тип адреса не поддерживается"},
    "en": {1: "SOCKS5 general failure", 2: "not allowed by ruleset",
           3: "network unreachable", 4: "host unreachable",
           5: "connection refused", 6: "TTL expired",
           7: "command not supported", 8: "address type not supported"},
}
S4_MSGS = {
    "ru": {91: "SOCKS4: запрос отклонён", 92: "SOCKS4: нет identd",
           93: "SOCKS4: ident не совпадает"},
    "en": {91: "SOCKS4: request rejected", 92: "SOCKS4: identd required",
           93: "SOCKS4: ident mismatch"},
}


def status_disp(key):
    return T("st_" + key) if key else "—"


def note_disp(note):
    if not note:
        return "—"
    if note.startswith("@"):
        return status_disp(note[1:])
    if note.startswith("http:"):
        return T("n_http", c=note[5:])
    if note.startswith("s5err:"):
        v = note[6:]
        return S5_MSGS[LANG].get(int(v) if v.isdigit() else -1, T("n_s5_err", c=v))
    if note.startswith("s4err:"):
        v = note[6:]
        return S4_MSGS[LANG].get(int(v) if v.isdigit() else -1, T("n_s4_err", c=v))
    if note.startswith("bad_url:"):
        return T("n_bad_url", u=note[8:])
    if note.startswith("target:"):
        return T("n_target", m=note[7:])
    k = "n_" + note
    if k in TR.get(LANG, {}) or k in TR["en"]:
        return T(k)
    return note


def flag_emoji(cc):
    cc = (cc or "").strip().upper()
    if len(cc) == 2 and cc.isascii() and cc.isalpha():
        return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc)
    return ""


class ProxyError(Exception): pass
class BadProto(ProxyError): pass
class AuthRequired(ProxyError): pass
class AuthFailed(ProxyError): pass

# --------------------------------------------------------------------------
# Лимитер прямых запросов к ip-api (45/мин с нашего IP — жёстко)
# --------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, rpm):
        self._interval = 60.0 / rpm
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self):
        with self._lock:
            now = time.monotonic()
            if now < self._next:
                time.sleep(self._next - now)
                now = time.monotonic()
            self._next = max(now, self._next) + self._interval

# --------------------------------------------------------------------------
# Модели
# --------------------------------------------------------------------------
@dataclass
class Proxy:
    host: str
    port: int
    user: str = None
    pwd: str = None
    hint: str = None
    idx: int = 0
    ua: str = None                       # персональный User-Agent
    stable_ok: int = 0                   # история для скоринга
    stable_total: int = 0
    status: str = "queued"
    proto: str = ""
    ping: float = None
    country: str = ""
    cc: str = ""
    city: str = ""
    exit_ip: str = ""
    anon: str = ""                       # elite / anon / transp
    target: str = ""
    note: str = ""
    checked: bool = False

    @property
    def addr(self):
        return f"{self.host}:{self.port}"

    @property
    def alive(self):
        return self.status == "ok"


@dataclass
class Cfg:
    timeout: float = 5.0
    geo_timeout: float = 4.0
    retries: int = 1
    use_proxy_geo: bool = True
    direct_geo: bool = True
    anon: bool = True
    targets: list = None


def parse_line(line):
    """ip:port | ip:port:user:pass | proto://[user:pass@]host:port.
    IPv6 — только в скобках: [2001:db8::1]:8080."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    hint = None
    if "://" in s:
        scheme, s = s.split("://", 1)
        scheme = scheme.lower()
        if scheme in ("http", "https", "socks4", "socks5"):
            hint = "http" if scheme == "https" else scheme
    user = pwd = None
    if "@" in s:
        cred, s = s.rsplit("@", 1)
        user, pwd = (cred.split(":", 1) + [""])[:2] if ":" in cred else (cred, "")
        if not user:
            raise ValueError
    if s.startswith("["):                                   # IPv6
        m = re.match(r"^\[([0-9A-Fa-f:.]+)\]:(\d+)(?::(.+))?$", s)
        if not m:
            raise ValueError
        host, port, rest = m.group(1), int(m.group(2)), m.group(3)
        try:
            socket.inet_pton(socket.AF_INET6, host)
        except OSError:
            raise ValueError
        if not (1 <= port <= 65535):
            raise ValueError
        if rest and user is None:
            u, _, w = rest.partition(":")
            user, pwd = u, w
        return Proxy(host=host, port=port, user=user, pwd=pwd, hint=hint)
    parts = s.split(":")
    if len(parts) < 2:
        raise ValueError
    host, port = parts[0], int(parts[1])
    if not host or not (1 <= port <= 65535):
        raise ValueError
    if len(parts) >= 4 and user is None:
        user, pwd = parts[2], ":".join(parts[3:])
    return Proxy(host=host, port=port, user=user, pwd=pwd, hint=hint)

# --------------------------------------------------------------------------
# Сокеты
# --------------------------------------------------------------------------
_dns_cache = {}                       # host -> (ip, expires_at) — фикс аудита: TTL
_dns_lock = threading.Lock()
DNS_TTL = 300.0                       # сек


def resolved_ip(host):
    now = time.monotonic()
    with _dns_lock:
        ent = _dns_cache.get(host)
        if ent and ent[1] > now:
            return ent[0]
    ip = socket.gethostbyname(host)
    with _dns_lock:
        _dns_cache[host] = (ip, time.monotonic() + DNS_TTL)
    return ip


def _connect(p, timeout):
    return socket.create_connection((p.host, p.port), timeout=timeout)


def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise BadProto("closed")
        buf += chunk
    return buf


def _read_response(sock, timeout):
    sock.settimeout(timeout)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                return None, b""
            buf += chunk
    except (socket.timeout, OSError):
        return None, b""
    head, body = buf.split(b"\r\n\r\n", 1)
    try:
        status = int(head.split(b"\r\n", 1)[0].split()[1])
    except (IndexError, ValueError):
        return None, b""
    if status in (204, 304):
        return status, b""
    deadline = time.monotonic() + timeout
    try:
        while len(body) < 262144:
            sock.settimeout(max(0.2, deadline - time.monotonic()))
            chunk = sock.recv(4096)
            if not chunk:
                break
            body += chunk
    except (socket.timeout, OSError):
        pass
    return status, body


def _proxy_auth_header(p):
    if p.user is None:
        return ""
    token = base64.b64encode(f"{p.user}:{p.pwd or ''}".encode()).decode()
    return f"Proxy-Authorization: Basic {token}\r\n"


def _open_socks5(p, target_host, target_port, timeout):
    sock = _connect(p, timeout)
    try:
        sock.settimeout(timeout)
        if p.user is not None:
            sock.sendall(b"\x05\x02\x00\x02")
            ver, method = _recvn(sock, 2)
            if ver != 5:
                raise BadProto("not_socks")
            if method == 2:
                u, w = p.user.encode(), (p.pwd or "").encode()
                sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(w)]) + w)
                ver, code = _recvn(sock, 2)
                if code != 0:
                    raise AuthFailed("bad_creds_s5")
            elif method != 0:
                raise AuthRequired("s5_auth")
        else:
            sock.sendall(b"\x05\x01\x00")
            ver, method = _recvn(sock, 2)
            if ver != 5:
                raise BadProto("not_socks")
            if method == 2:
                raise AuthRequired("s5_auth")
            if method != 0:
                raise BadProto("s5_method")
        # ATYP: 1=IPv4, 3=домен, 4=IPv6
        try:
            addr, atyp = socket.inet_pton(socket.AF_INET6, target_host), b"\x04"
        except OSError:
            try:
                addr, atyp = socket.inet_aton(target_host), b"\x01"
            except OSError:
                atyp = b"\x03"
                addr = bytes([len(target_host)]) + target_host.encode()
        sock.sendall(b"\x05\x01\x00" + atyp + addr + target_port.to_bytes(2, "big"))
        resp = _recvn(sock, 4)
        if resp[1] != 0:
            raise BadProto(f"s5err:{resp[1]}")
        atyp = resp[3]
        if atyp == 1:
            _recvn(sock, 6)
        elif atyp == 3:
            _recvn(sock, _recvn(sock, 1)[0] + 2)
        elif atyp == 4:
            _recvn(sock, 18)
        return sock
    except Exception:
        try: sock.close()
        except OSError: pass
        raise


def _open_socks4(p, target_ip, target_port, timeout):
    sock = _connect(p, timeout)
    try:
        sock.settimeout(timeout)
        try:
            ipb = socket.inet_aton(target_ip)
        except OSError:
            raise BadProto("s4_no_v6")                 # SOCKS4 = только IPv4
        sock.sendall(b"\x04\x01" + target_port.to_bytes(2, "big") + ipb + b"\x00")
        resp = _recvn(sock, 8)
        if resp[1] != 90:
            raise BadProto(f"s4err:{resp[1]}")
        return sock
    except Exception:
        try: sock.close()
        except OSError: pass
        raise


def _open_by_proto(p, proto, host, port, timeout):
    if proto == "http":
        return _connect(p, timeout)
    if proto == "socks5":
        return _open_socks5(p, host, port, timeout)
    return _open_socks4(p, resolved_ip(host), port, timeout)


def _http_get(sock, proto, url, p, timeout):
    _, rest = url.split("://", 1)
    host, _, path = rest.partition("/")
    path = "/" + path
    if proto == "http":
        req = f"GET {url} HTTP/1.1\r\nHost: {host}\r\n" + _proxy_auth_header(p)
    else:
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
    req += (f"User-Agent: {p.ua or USER_AGENT}\r\n"
            f"Accept: */*\r\nConnection: close\r\n\r\n")
    sock.settimeout(timeout)
    sock.sendall(req.encode())
    return _read_response(sock, timeout)


def _tls_request(p, proto, host, port, path, timeout):
    """GET https://host/path через прокси → (status, body). Реальный TLS."""
    if proto == "http":
        sock = _connect(p, timeout)
        try:
            sock.settimeout(timeout)
            sock.sendall((f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                          + _proxy_auth_header(p) + "\r\n").encode())
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    raise BadProto("no_connect_reply")
                buf += chunk
            line = buf.split(b"\r\n", 1)[0].split()
            if len(line) < 2 or line[1] != b"200":
                raise BadProto("connect_denied")
        except Exception:
            try: sock.close()
            except OSError: pass
            raise
    else:
        sock = _open_by_proto(p, proto, host, port, timeout)
    try:
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(sock, server_hostname=host)
    except Exception:
        try: sock.close()
        except OSError: pass
        raise BadProto("tls_fail")
    try:
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               f"User-Agent: {p.ua or USER_AGENT}\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n")
        tls.sendall(req.encode())
        return _read_response(tls, timeout)
    finally:
        try: tls.close()
        except OSError: pass

# --------------------------------------------------------------------------
# Alive-проверка с резервными эндпоинтами
# --------------------------------------------------------------------------
def _split_target(url):
    """url → (scheme, host, port, path_с_query, netloc) или None."""
    m = re.match(r"^(https?)://([^/]+?)(/.*)?$", url, re.I)
    if not m:
        return None
    scheme = m.group(1).lower()
    netloc, path = m.group(2), m.group(3) or "/"
    default_port = 443 if scheme == "https" else 80
    bm = re.match(r"^\[(.+)\](?::(\d+))?$", netloc)
    if bm:
        host = bm.group(1)
        port = int(bm.group(2)) if bm.group(2) else default_port
    elif ":" in netloc:
        h, _, pt = netloc.rpartition(":")
        port = int(pt) if pt.isdigit() else 0
        if h and 1 <= port <= 65535:
            host = h
        else:
            host, port = netloc, default_port
    else:
        host, port = netloc, default_port
    return scheme, host, port, path, netloc


def _alive_check(p, proto, timeout, stop_event):
    """Перебирает ALIVE_URLS. Возвращает (ok, ping_ms, note_code).
    Ошибки соединения с самим прокси — пробрасываются (смена эндпоинта не поможет).
    Фикс аудита: ровно ОДНО соединение на эндпоинт — socks открывает его сам,
    без предварительного _connect (раньше было двойное подключение)."""
    best, saw = "timeout", False
    for url in ALIVE_URLS:
        if stop_event.is_set():
            break
        parts = _split_target(url)
        if not parts:
            continue
        scheme, host, port, path, _ = parts
        t0 = time.monotonic()
        try:
            if proto == "http":
                sock = _connect(p, timeout)
            elif proto == "socks5":
                sock = _open_socks5(p, host, port, timeout)
            else:
                sock = _open_socks4(p, resolved_ip(host), port, timeout)
        except (AuthFailed, AuthRequired, socket.timeout, OSError):
            raise
        except BadProto as e:
            best = str(e)
            continue
        try:
            try:
                status, _ = _http_get(sock, proto, url, p, timeout)
            except (socket.timeout, OSError):
                status = None
        finally:
            try: sock.close()
            except OSError: pass
        ms = (time.monotonic() - t0) * 1000.0
        if status is None:
            best = "no_reply"
            continue
        strict = "204" in path
        if (status == 204) if strict else (200 <= status < 400):
            return True, ms, ""
        saw = True
        best = "spoofed"                                   # каптив-портал/подмена
    return False, None, best if not saw else "spoofed"


def _https_check(p, timeout):
    """Тип HTTPS: CONNECT + реальный TLS + успешный ответ на первый alive-URL."""
    parts = _split_target(ALIVE_URLS[0]) if ALIVE_URLS else None
    if not parts:
        return False
    _, host, port, path, _ = parts
    try:
        status, _ = _tls_request(p, "http", host, port, path, timeout)
        return status == 204 if "204" in path else (200 <= status < 400)
    except Exception:
        return False

# --------------------------------------------------------------------------
# Геолокация и анонимность
# --------------------------------------------------------------------------
def geo_url(ip=None):
    lang = "ru" if LANG == "ru" else "en"
    if ip:
        return f"{GEO_BASE}{ip}?fields={GEO_FIELDS}&lang={lang}"
    return f"{GEO_BASE}?fields={GEO_FIELDS}&lang={lang}"


def _geo_through(p, proto, timeout):
    """Гео через сам прокси: лимит ip-api расходует exit-IP прокси, не наш."""
    url = geo_url()
    parts = _split_target(url)
    if not parts:
        return None
    scheme, host, port, path, _ = parts
    try:
        if scheme == "https":
            status, body = _tls_request(p, proto, host, port, path, timeout)
        else:
            sock = _open_by_proto(p, proto, host, port, timeout)
            try:
                status, body = _http_get(sock, proto, url, p, timeout)
            finally:
                try: sock.close()
                except OSError: pass
    except Exception:
        return None
    try:
        if status != 200:
            return None
        data = json.loads(body.decode("utf-8", "replace"))
        if data.get("status") != "success":
            return None
        return (data.get("country", ""), data.get("countryCode", ""),
                data.get("city", ""), data.get("query", ""))
    except Exception:
        return None


def _geo_direct(ip_or_host):
    """Прямое гео — расходует общий лимит, вызывать только через RateLimiter."""
    try:
        ip = resolved_ip(ip_or_host)
        with urlopen(Request(geo_url(ip), headers={"User-Agent": USER_AGENT}),
                     timeout=6) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        if data.get("status") == "success":
            return (data.get("country", ""), data.get("countryCode", ""),
                    data.get("city", ""), data.get("query", ip))
    except Exception:
        pass
    return None


def _direct_echo_ip(timeout=6):
    for url, key in ECHO_DIRECT:
        try:
            with urlopen(Request(url, headers={"User-Agent": USER_AGENT}),
                         timeout=timeout) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            ip = str(data.get(key, "")).split(",")[0].strip()
            if ip:
                return ip
        except Exception:
            continue
    return None


def _echo_headers(p, proto, timeout):
    for url in ECHO_URLS:
        parts = _split_target(url)
        if not parts:
            continue
        scheme, host, port, path, _ = parts
        try:
            if scheme == "https":
                status, body = _tls_request(p, proto, host, port, path, timeout)
            else:
                sock = _open_by_proto(p, proto, host, port, timeout)
                try:
                    status, body = _http_get(sock, proto, url, p, timeout)
                finally:
                    try: sock.close()
                    except OSError: pass
        except Exception:
            continue
        if status == 200:
            try:
                data = json.loads(body.decode("utf-8", "replace"))
                h = data.get("headers")
                if isinstance(h, dict) and h:
                    return h
            except Exception:
                continue
    return None


_ANON_KEYS = ("via", "x-forwarded-for", "forwarded", "proxy-connection",
              "x-real-ip", "client-ip", "true-client-ip", "x-proxy-id")

def classify_anon(headers, real_ip):
    if not isinstance(headers, dict):
        return ""
    low = {str(k).lower(): str(v) for k, v in headers.items()}
    if real_ip and any(real_ip in v for v in low.values()):
        return "transp"
    if any(k in low for k in _ANON_KEYS):
        return "anon"
    return "elite"

# --------------------------------------------------------------------------
# Целевые URL
# --------------------------------------------------------------------------
def _check_targets(p, proto, cfg):
    for url in cfg.targets:
        parts = _split_target(url)
        if parts is None:
            return False, T("n_bad_url", u=url[:60])
        scheme, host, port, path, disp = parts
        try:
            if scheme == "https":
                status, _ = _tls_request(p, proto, host, port, path, cfg.timeout)
            else:
                sock = _open_by_proto(p, proto, host, port, cfg.timeout)
                try:
                    status, _ = _http_get(sock, proto, url, p, cfg.timeout)
                finally:
                    try: sock.close()
                    except OSError: pass
        except Exception as e:
            return False, f"{disp}: {str(e)[:60] or T('t_unreachable')}"
        if status and 200 <= status < 400:
            continue
        return False, (f"{disp}: HTTP {status}" if status
                       else f"{disp}: {T('n_no_reply')}")
    return True, "OK"

# --------------------------------------------------------------------------
# Проверка одного прокси (умный ретрай)
# --------------------------------------------------------------------------
def check_proxy(p, cfg, limiter, stop_event, real_ip_fn):
    for _ in range(max(1, cfg.retries + 1)):
        if stop_event.is_set():
            p.status = "stopped"
            return p
        _attempt(p, cfg, limiter, stop_event, real_ip_fn)
        if p.alive or p.status in ("auth_required", "auth_failed"):
            break                        # авторизация детерминирована
        if p.note not in RETRYABLE:
            break                        # «порт закрыт» и пр. — повтор бессмыслен
    return p


def _attempt(p, cfg, limiter, stop_event, real_ip_fn):
    if not p.ua:
        p.ua = random.choice(USER_AGENTS)               # ротация UA
    order = ([p.hint] if p.hint else []) + [x for x in ("http", "socks5", "socks4")
                                            if x != p.hint]
    note, need_auth, bad_creds = "", False, False
    for proto in order:
        if stop_event.is_set():
            p.status = "stopped"
            return
        try:
            ok, ping_ms, note2 = _alive_check(p, proto, cfg.timeout, stop_event)
        except AuthFailed:
            bad_creds, note = True, "bad_creds_s5"; continue
        except AuthRequired:
            need_auth, note = True, "s5_auth"; continue
        except socket.timeout:
            note = "timeout"; continue
        except OSError:
            note = "no_conn"; continue
        if not ok:
            note = note2
            continue

        p.ping = round(ping_ms)
        p.note = ""
        if proto == "http":
            p.proto = "HTTPS" if _https_check(p, cfg.timeout) else "HTTP"
        else:
            p.proto = proto.upper()

        geo = None
        if cfg.use_proxy_geo and not stop_event.is_set():
            geo = _geo_through(p, proto, cfg.geo_timeout)
        if geo is None and cfg.direct_geo and not stop_event.is_set():
            limiter.wait()
            geo = _geo_direct(p.host)
        if geo:
            p.country, p.cc, p.city, p.exit_ip = geo
        else:
            p.note = "geo_unavail"

        if cfg.anon and not stop_event.is_set():
            try:
                h = _echo_headers(p, proto, cfg.geo_timeout)
                p.anon = classify_anon(h, real_ip_fn()) if h else ""
            except Exception:
                p.anon = ""

        if cfg.targets and not stop_event.is_set():
            try:
                ok, msg = _check_targets(p, proto, cfg)
            except Exception as e:
                ok, msg = False, repr(e)[:60]
            p.target = msg
            if not ok:
                p.status = "target_fail"
                p.note = "target:" + msg
                return
        else:
            p.target = ""
        p.status = "ok"
        return

    p.note = note
    p.status = "auth_failed" if bad_creds else \
               "auth_required" if need_auth else "unreachable"

# --------------------------------------------------------------------------
# Пул потоков
# --------------------------------------------------------------------------
def calc_threads(total, timeout):
    if total <= 0:
        return 16
    return max(16, min(400, int(total * timeout / 600) or 16))


class WorkerPool:
    def __init__(self, size, fn, stop_event, pause_event):
        self.q = queue.Queue()
        self.stop_event = stop_event
        self.pause_event = pause_event
        self.threads = [threading.Thread(target=self._loop, args=(fn,), daemon=True)
                        for _ in range(size)]
        for t in self.threads:
            t.start()

    def submit_many(self, items):
        for it in items:
            self.q.put(it)

    def drain(self):
        try:
            while True:
                self.q.get_nowait()
        except queue.Empty:
            pass

    def close(self):
        for _ in self.threads:
            self.q.put(None)

    def _loop(self, fn):
        while True:
            item = self.q.get()
            if item is None:
                return
            if self.stop_event.is_set():
                continue
            while self.pause_event.is_set() and not self.stop_event.is_set():
                time.sleep(0.08)
            if self.stop_event.is_set():
                continue
            try:
                fn(item)
            except Exception:
                pass

# --------------------------------------------------------------------------
# Утилиты
# --------------------------------------------------------------------------
def fmt_time(sec):
    sec = int(max(0, sec))
    if sec < 60:
        return T("time_s", s=sec)
    m, s = divmod(sec, 60)
    if m < 60:
        return T("time_ms", m=m, s=s)
    h, m = divmod(m, 60)
    return T("time_hm", h=h, m=m)


def _reset_proxy(p):
    p.status = "checking"
    p.proto = ""
    p.ping = None
    p.country = p.cc = p.city = p.exit_ip = p.anon = p.target = p.note = ""
    # stable_ok / stable_total НЕ сбрасываются — это история для скоринга


def _export_line(p, fmt):
    if fmt == "plain":
        return f"{p.host}:{p.port}"
    scheme = (p.proto or "http").lower()
    if fmt == "proto":
        return f"{scheme}://{p.host}:{p.port}"
    auth = f"{p.user}:{p.pwd or ''}@" if p.user is not None else ""
    return f"{scheme}://{auth}{p.host}:{p.port}"


def _auto_line(p):
    scheme = (p.proto or "http").lower()
    if p.user is not None:
        return f"{scheme}://{p.user}:{p.pwd or ''}@{p.host}:{p.port}"
    return f"{scheme}://{p.host}:{p.port}"

# --------------------------------------------------------------------------
# Приложение
# --------------------------------------------------------------------------
class App:
    def __init__(self, root, dnd=False):
        self.root = root
        root.configure(bg=C_BG)
        global LANG
        st = self._load_settings()
        if st.get("lang") in ("ru", "en"):
            LANG = st["lang"]

        self.proxies = []
        self.done = self.ok = self.fail = self.active = 0
        self.running = False
        self.run_id = 0
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.limiter = RateLimiter(GEO_RPM)
        self.q = queue.Queue()
        self.timeout = 5
        self.geo_timeout = 4
        self.cfg = None
        self.targets = st.get("targets") or []
        self.list_path = None
        self.autosave_path = st.get("autosave_path") or None
        self.autosave_fh = None
        self.pool = None
        self.t_start = 0.0
        self._st = st
        self._sort_dir = {}
        self._sort_state = None          # (col, rev) — активная сортировка
        self._order = []
        self._order_keys = []
        self._filter_after = None
        self.err_counter = Counter()
        self.exit_counts = defaultdict(int)
        self.exit_map = defaultdict(set)
        self._real_ip = None
        self._real_ip_fetched = False
        self._real_ip_lock = threading.Lock()
        self._fstatus_key = "all"
        self._lang_map = {"Русский": "ru", "English": "en"}
        self._lang_rev = {v: k for k, v in self._lang_map.items()}
        self._ac_win = None
        self._ac_lb = None
        self._ac_after = None
        self._ac_cache = (None, None, 0.0)

        self._setup_style()
        self._build_ui()
        if st.get("geometry"):
            try:
                root.geometry(st["geometry"])
            except Exception:
                pass
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        if dnd:
            try:
                root.drop_target_register(DND_FILES)
                root.dnd_bind("<<Drop>>", self._on_drop)
                self.set_event(T("ready_dnd"))
            except Exception:
                self.set_event(T("ready"))
        else:
            self.set_event(T("ready"))
        self.root.after(100, self._poll)

    # ------------------------------ настройки -----------------------------
    def _load_settings(self):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except Exception:
            return {}

    def _collect_settings(self):
        return {
            "timeout": self.var_timeout.get(),
            "geo_timeout": self.var_geo_timeout.get(),
            "retries": self.var_retries.get(),
            "threads": self.var_threads.get(),
            "proxy_geo": bool(self.var_proxygeo.get()),
            "direct_geo": bool(self.var_directgeo.get()),
            "anon": bool(self.var_anon.get()),
            "flags": bool(self.var_flags.get()),
            "lang": LANG,
            "autosave_path": self.autosave_path,
            "targets": self.targets,
            "services": {"alive": list(ALIVE_URLS), "echo": list(ECHO_URLS),
                         "geo": GEO_BASE},
            "geometry": self.root.geometry(),
        }

    def _save_settings(self):
        try:
            os.makedirs(SETTINGS_DIR, exist_ok=True)
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(self._collect_settings(), f, ensure_ascii=False, indent=1)
        except Exception:
            pass

    def _on_close(self):
        if self.running:
            self.stop_event.set()
        self._save_settings()
        self._close_autosave()
        self.root.destroy()

    def _apply_services(self, alive, echo, geo):
        global GEO_BASE
        ALIVE_URLS[:] = alive
        ECHO_URLS[:] = echo
        GEO_BASE = geo

    # ------------------------------ стиль ---------------------------------
    def _setup_style(self):
        st = ttk.Style(self.root)
        st.theme_use("clam")
        st.configure(".", background=C_BG, foreground=C_TEXT,
                     fieldbackground=C_CARD, font=FONT)
        st.configure("TButton", background=C_CARD, foreground=C_TEXT,
                     borderwidth=0, focusthickness=0)
        st.map("TButton", background=[("active", "#2c3345"), ("disabled", C_PANEL)],
               foreground=[("disabled", C_DIM)])
        st.configure("Accent.TButton", background=C_ACCENT, foreground="#ffffff")
        st.map("Accent.TButton", background=[("active", "#3d78e8"), ("disabled", C_PANEL)],
               foreground=[("disabled", C_DIM)])
        st.configure("Danger.TButton", background=C_RED, foreground="#ffffff")
        st.map("Danger.TButton", background=[("active", "#e04855"), ("disabled", C_PANEL)],
               foreground=[("disabled", C_DIM)])
        st.configure("TMenubutton", background=C_CARD, foreground=C_TEXT, borderwidth=0)
        st.map("TMenubutton", background=[("active", "#2c3345"), ("disabled", C_PANEL)],
               foreground=[("disabled", C_DIM)])
        st.configure("TSpinbox", background=C_CARD, foreground=C_TEXT,
                     fieldbackground=C_CARD, buttonbackground=C_CARD,
                     arrowcolor=C_TEXT, borderwidth=0)
        st.configure("TCombobox", fieldbackground=C_CARD, background=C_CARD,
                     foreground=C_TEXT, arrowcolor=C_TEXT, borderwidth=0)
        st.configure("TCheckbutton", background=C_BG, foreground=C_TEXT)
        st.map("TCheckbutton", background=[("active", C_BG)])
        st.configure("TRadiobutton", background=C_BG, foreground=C_TEXT)
        st.map("TRadiobutton", background=[("active", C_BG)])
        st.configure("Horizontal.TProgressbar", background=C_ACCENT,
                     troughcolor=C_CARD, borderwidth=0,
                     lightcolor=C_ACCENT, darkcolor=C_ACCENT)
        st.configure("Treeview", background=C_ROW, foreground=C_TEXT,
                     fieldbackground=C_ROW, rowheight=24, borderwidth=0)
        st.map("Treeview", background=[("selected", "#31415f")],
               foreground=[("selected", "#ffffff")])
        st.configure("Treeview.Heading", background=C_CARD, foreground=C_DIM,
                     relief="flat", font=("Segoe UI", 9, "bold"))
        st.map("Treeview.Heading", background=[("active", "#2c3345")])

    # ------------------------------ интерфейс -----------------------------
    def _build_ui(self):
        top = tk.Frame(self.root, bg=C_BG)
        top.pack(fill="x", padx=12, pady=(12, 6))
        self.mb_load = ttk.Menubutton(top, text=T("btn_load"))
        self._build_load_menu()
        self.mb_load.pack(side="left")
        self.btn_start = ttk.Button(top, text=T("btn_start"), style="Accent.TButton",
                                    command=self.start, state="disabled")
        self.btn_start.pack(side="left", padx=(8, 0))
        self.btn_pause = ttk.Button(top, text=T("btn_pause"), command=self.toggle_pause,
                                    state="disabled")
        self.btn_pause.pack(side="left", padx=(8, 0))
        self.btn_stop = ttk.Button(top, text=T("btn_stop"), style="Danger.TButton",
                                   command=self.stop, state="disabled")
        self.btn_stop.pack(side="left", padx=(8, 0))
        self.btn_recheck = ttk.Button(top, text=T("btn_recheck"),
                                      command=self.recheck, state="disabled")
        self.btn_recheck.pack(side="left", padx=(8, 0))
        self.btn_export = ttk.Button(top, text=T("btn_export"),
                                     command=self.export_dialog, state="disabled")
        self.btn_export.pack(side="left", padx=(8, 0))
        self.btn_stats = ttk.Button(top, text=T("btn_stats"),
                                    command=self._stats_dialog, state="disabled")
        self.btn_stats.pack(side="left", padx=(8, 0))

        opts = tk.Frame(self.root, bg=C_BG)
        opts.pack(fill="x", padx=12, pady=(0, 2))
        s = self._st
        self.var_timeout = tk.StringVar(value=str(s.get("timeout", "5")))
        self.var_geo_timeout = tk.StringVar(value=str(s.get("geo_timeout", "4")))
        self.var_retries = tk.StringVar(value=str(s.get("retries", "1")))
        self.var_threads = tk.StringVar(value=str(s.get("threads", "0")))
        self.var_proxygeo = tk.BooleanVar(value=bool(s.get("proxy_geo", True)))
        self.var_directgeo = tk.BooleanVar(value=bool(s.get("direct_geo", True)))
        self.var_anon = tk.BooleanVar(value=bool(s.get("anon", True)))
        self.var_target = tk.BooleanVar(value=False)
        self.var_autosave = tk.BooleanVar(value=False)
        self.var_flags = tk.BooleanVar(value=bool(s.get("flags", False)))

        self.lbl_timeout = tk.Label(opts, text=T("opt_timeout"), bg=C_BG, fg=C_DIM, font=FONT)
        self.lbl_timeout.grid(row=0, column=0, padx=(0, 4))
        ttk.Spinbox(opts, from_=2, to=30, width=4, textvariable=self.var_timeout
                    ).grid(row=0, column=1)
        self.lbl_geo = tk.Label(opts, text=T("opt_geo_timeout"), bg=C_BG, fg=C_DIM, font=FONT)
        self.lbl_geo.grid(row=0, column=2, padx=(14, 4))
        ttk.Spinbox(opts, from_=2, to=15, width=4, textvariable=self.var_geo_timeout
                    ).grid(row=0, column=3)
        self.lbl_retries = tk.Label(opts, text=T("opt_retries"), bg=C_BG, fg=C_DIM, font=FONT)
        self.lbl_retries.grid(row=0, column=4, padx=(14, 4))
        ttk.Spinbox(opts, from_=0, to=5, width=3, textvariable=self.var_retries
                    ).grid(row=0, column=5)
        self.lbl_threads = tk.Label(opts, text=T("opt_threads"), bg=C_BG, fg=C_DIM, font=FONT)
        self.lbl_threads.grid(row=0, column=6, padx=(14, 4))
        ttk.Spinbox(opts, from_=0, to=500, width=5, textvariable=self.var_threads
                    ).grid(row=0, column=7)
        self.chk_pgeo = ttk.Checkbutton(opts, text=T("opt_proxy_geo"),
                                        variable=self.var_proxygeo)
        self.chk_pgeo.grid(row=0, column=8, padx=(16, 0))
        self.chk_dgeo = ttk.Checkbutton(opts, text=T("opt_direct_geo"),
                                        variable=self.var_directgeo)
        self.chk_dgeo.grid(row=0, column=9, padx=(10, 0))

        opts2 = tk.Frame(self.root, bg=C_BG)
        opts2.pack(fill="x", padx=12, pady=(0, 6))
        self.chk_target = ttk.Checkbutton(opts2, text=T("opt_target"),
                                          variable=self.var_target)
        self.chk_target.grid(row=0, column=0)
        self.btn_targets = ttk.Button(opts2, text=T("btn_targets", n=len(self.targets)),
                                      command=self._edit_targets)
        self.btn_targets.grid(row=0, column=1, padx=(4, 0))
        self.chk_autosave = ttk.Checkbutton(opts2, text=T("opt_autosave"),
                                            variable=self.var_autosave)
        self.chk_autosave.grid(row=0, column=2, padx=(18, 0))
        self.btn_autosave = ttk.Button(opts2, text=T("btn_autosave"),
                                       command=self.choose_autosave)
        self.btn_autosave.grid(row=0, column=3, padx=(4, 0))
        self.chk_anon = ttk.Checkbutton(opts2, text=T("opt_anon"), variable=self.var_anon)
        self.chk_anon.grid(row=0, column=4, padx=(18, 0))
        self.chk_flags = ttk.Checkbutton(opts2, text=T("opt_flags"),
                                         variable=self.var_flags,
                                         command=self._apply_filter)
        self.chk_flags.grid(row=0, column=5, padx=(18, 0))
        self.btn_services = ttk.Button(opts2, text=T("btn_services"),
                                       command=lambda: ServicesDialog(self))
        self.btn_services.grid(row=0, column=6, padx=(18, 0))
        tk.Label(opts2, text="🌐", bg=C_BG, fg=C_TEXT, font=FONT
                 ).grid(row=0, column=7, padx=(20, 2))
        self.var_lang = tk.StringVar(value=self._lang_rev.get(LANG, "Русский"))
        cb_lang = ttk.Combobox(opts2, textvariable=self.var_lang, state="readonly",
                               values=("Русский", "English"), width=9)
        cb_lang.grid(row=0, column=8)
        cb_lang.bind("<<ComboboxSelected>>", self._on_lang)

        frow = tk.Frame(self.root, bg=C_BG)
        frow.pack(fill="x", padx=12, pady=(0, 6))
        self.lbl_filter = tk.Label(frow, text=T("filter_label"), bg=C_BG, fg=C_DIM, font=FONT)
        self.lbl_filter.pack(side="left")
        self.var_filter = tk.StringVar()
        self._filter_entry = ttk.Entry(frow, textvariable=self.var_filter, width=30)
        self._filter_entry.pack(side="left", padx=(6, 0))
        self.var_filter.trace_add("write", self._on_filter_changed)
        self._filter_entry.bind("<KeyRelease>", self._ac_key)
        self._filter_entry.bind("<Down>", lambda e: self._ac_move(1))
        self._filter_entry.bind("<Up>", lambda e: self._ac_move(-1))
        self._filter_entry.bind("<Return>", self._ac_enter)
        self._filter_entry.bind("<Tab>", self._ac_enter)
        self._filter_entry.bind("<Escape>", lambda e: self._ac_hide())
        self._filter_entry.bind("<FocusOut>",
                                lambda e: self.root.after(150, self._ac_hide))
        self.var_only_ok = tk.BooleanVar(value=False)
        self.chk_onlyok = ttk.Checkbutton(frow, text=T("filter_only_ok"),
                                          variable=self.var_only_ok,
                                          command=self._apply_filter)
        self.chk_onlyok.pack(side="left", padx=(14, 0))
        self.lbl_fstatus = tk.Label(frow, text=T("filter_status"),
                                    bg=C_BG, fg=C_DIM, font=FONT)
        self.lbl_fstatus.pack(side="left", padx=(14, 4))
        self.var_fstatus = tk.StringVar(value=T("status_all"))
        self.cb_fstatus = ttk.Combobox(frow, textvariable=self.var_fstatus,
                                       values=self._status_values(),
                                       state="readonly", width=18)
        self.cb_fstatus.pack(side="left")
        self.cb_fstatus.bind("<<ComboboxSelected>>", self._on_fstatus)

        prow = tk.Frame(self.root, bg=C_BG)
        prow.pack(fill="x", padx=12, pady=(0, 2))
        self.progress = ttk.Progressbar(prow, mode="determinate")
        self.progress.pack(side="left", fill="x", expand=True)
        self.lbl_prog = tk.Label(prow, text="—", bg=C_BG, fg=C_DIM,
                                 font=FONT, width=40, anchor="e")
        self.lbl_prog.pack(side="left", padx=(10, 0))
        self.lbl_err = tk.Label(self.root, text=T("err_dash"), bg=C_BG, fg=C_DIM,
                                font=FONT, anchor="w")
        self.lbl_err.pack(fill="x", padx=12, pady=(0, 4))

        tw = tk.Frame(self.root, bg=C_BG)
        tw.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        self.cols = ("num", "proxy", "type", "status", "ping", "score",
                     "country", "city", "exit", "anon", "target", "note")
        self.col_keys = ("col_num", "col_proxy", "col_type", "col_status",
                         "col_ping", "col_score", "col_country", "col_city",
                         "col_exit", "col_anon", "col_target", "col_note")
        widths = (44, 150, 66, 140, 62, 58, 120, 95, 125, 88, 105, 160)
        self.tree = ttk.Treeview(tw, columns=self.cols, show="headings",
                                 selectmode="extended")
        for c, w in zip(self.cols, widths):
            self.tree.column(c, width=w, minwidth=40, anchor="w",
                             stretch=(c in ("proxy", "note")))
        self._set_headings()
        vs = ttk.Scrollbar(tw, orient="vertical", command=self.tree.yview)
        hs = ttk.Scrollbar(tw, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        tw.grid_rowconfigure(0, weight=1)
        tw.grid_columnconfigure(0, weight=1)
        self.tree.tag_configure("ok", foreground=C_GREEN)
        self.tree.tag_configure("warn", foreground=C_AMBER)
        self.tree.tag_configure("bad", foreground="#8d95a8")
        self.tree.bind("<Double-1>", lambda e: self._copy_row_cmd())
        self.tree.bind("<Control-c>", lambda e: self._copy_selected_all())
        self.tree.bind("<Button-3>", self._show_ctx)

        self.ctx = tk.Menu(self.root, tearoff=0, bg=C_CARD, fg=C_TEXT,
                           activebackground="#2c3345", activeforeground=C_TEXT)
        self.ctx.add_command(label=T("ctx_copy"), command=self._copy_row_cmd)
        self.ctx.add_command(label=T("ctx_copy_all"), command=self._copy_selected_all)
        self.ctx.add_separator()
        self.ctx.add_command(label=T("ctx_recheck"), command=self._recheck_selected)
        self.ctx.add_separator()
        self.ctx.add_command(label=T("ctx_export"), command=self._export_selected)

        sb = tk.Frame(self.root, bg=C_PANEL)
        sb.pack(fill="x", side="bottom")
        self.lbl_event = tk.Label(sb, bg=C_PANEL, fg=C_DIM, font=FONT, anchor="w",
                                  text=T("ready"))
        self.lbl_event.pack(side="left", fill="x", expand=True, padx=10, pady=5)
        self.lbl_live = tk.Label(sb, bg=C_PANEL, fg=C_TEXT, font=FONT, anchor="e")
        self.lbl_live.pack(side="right", padx=10, pady=5)

    def _build_load_menu(self):
        menu = tk.Menu(self.mb_load, tearoff=0, bg=C_CARD, fg=C_TEXT,
                       activebackground="#2c3345", activeforeground=C_TEXT)
        menu.add_command(label=T("m_file"), command=self.load_file)
        menu.add_command(label=T("m_url"), command=self.load_url)
        menu.add_command(label=T("m_clip"), command=self.load_buffer)
        self.mb_load["menu"] = menu

    def _set_headings(self):
        for c, key in zip(self.cols, self.col_keys):
            self.tree.heading(c, text=T(key), command=lambda cc=c: self._sort(cc))

    def _status_values(self):
        return [T("status_all")] + [T("st_" + k) for k in STATUS_ORDER]

    # ------------------------------ язык ----------------------------------
    def _on_lang(self, _e=None):
        global LANG
        LANG = self._lang_map.get(self.var_lang.get(), "ru")
        self._ac_cache = (None, None, 0.0)
        self._apply_lang()
        self._save_settings()

    def _apply_lang(self):
        self._build_load_menu()
        self.mb_load.configure(text=T("btn_load"))
        self.btn_start.configure(text=T("btn_start"))
        self.btn_pause.configure(text=T("btn_resume" if self.pause_event.is_set()
                                         else "btn_pause"))
        self.btn_stop.configure(text=T("btn_stop"))
        self.btn_recheck.configure(text=T("btn_recheck"))
        self.btn_export.configure(text=T("btn_export"))
        self.btn_stats.configure(text=T("btn_stats"))
        self.btn_services.configure(text=T("btn_services"))
        self.lbl_timeout.configure(text=T("opt_timeout"))
        self.lbl_geo.configure(text=T("opt_geo_timeout"))
        self.lbl_retries.configure(text=T("opt_retries"))
        self.lbl_threads.configure(text=T("opt_threads"))
        self.chk_pgeo.configure(text=T("opt_proxy_geo"))
        self.chk_dgeo.configure(text=T("opt_direct_geo"))
        self.chk_target.configure(text=T("opt_target"))
        self.btn_targets.configure(text=T("btn_targets", n=len(self.targets)))
        self.chk_autosave.configure(text=T("opt_autosave"))
        self.btn_autosave.configure(
            text=os.path.basename(self.autosave_path) if self.autosave_path
            else T("btn_autosave"))
        self.chk_anon.configure(text=T("opt_anon"))
        self.chk_flags.configure(text=T("opt_flags"))
        self.lbl_filter.configure(text=T("filter_label"))
        self.chk_onlyok.configure(text=T("filter_only_ok"))
        self.lbl_fstatus.configure(text=T("filter_status"))
        self.cb_fstatus.configure(values=self._status_values())
        self.var_fstatus.set(T("status_all") if self._fstatus_key == "all"
                             else T("st_" + self._fstatus_key))
        self._set_headings()
        for i, key in ((0, "ctx_copy"), (1, "ctx_copy_all"),
                       (3, "ctx_recheck"), (5, "ctx_export")):
            self.ctx.entryconfig(i, label=T(key))
        if not self.proxies and not self.running:
            self.set_event(T("ready_dnd") if HAS_DND else T("ready"))
        self.tree.delete(*self.tree.get_children(""))
        for p in self.proxies:
            if p.checked and self._matches(p):
                self._upsert_row(p)
        self._update_progress()

    # ------------------------------ автодополнение ------------------------
    def _ac_pool(self):
        sig = (len(self.proxies), LANG)
        now = time.monotonic()
        sig_ok, pool, ts = self._ac_cache
        if pool is not None and sig == sig_ok and now - ts < 3.0:
            return pool
        s = set(T("st_" + k) for k in STATUS_ORDER)
        s.update(("HTTP", "HTTPS", "SOCKS5", "SOCKS4"))
        s.update(T("an_" + k) for k in ("elite", "anon", "transp"))
        for p in self.proxies:
            s.add(p.addr)
            s.add(p.host)
            if p.cc:
                s.add(p.cc)
            if p.country:
                s.add(p.country)
            if p.city:
                s.add(p.city)
            if p.exit_ip:
                s.add(p.exit_ip)
            if p.anon:
                s.add(T("an_" + p.anon))
        pool = sorted(s)
        self._ac_cache = (sig, pool, now)
        return pool

    def _ac_hide(self):
        if self._ac_after:
            try:
                self.root.after_cancel(self._ac_after)
            except Exception:
                pass
            self._ac_after = None
        if self._ac_win:
            try:
                self._ac_win.destroy()
            except Exception:
                pass
            self._ac_win = None
            self._ac_lb = None

    def _ac_update(self):
        self._ac_after = None
        q = self.var_filter.get().strip()
        if not q:
            self._ac_hide()
            return
        ql = q.lower()
        matches = [s for s in self._ac_pool()
                   if ql in s.lower() and s.lower() != ql][:10]
        if not matches:
            self._ac_hide()
            return
        if self._ac_win is None:
            win = tk.Toplevel(self.root)
            win.overrideredirect(True)
            win.attributes("-topmost", True)
            lb = tk.Listbox(win, bg=C_CARD, fg=C_TEXT, relief="flat",
                            highlightthickness=1, highlightbackground=C_ACCENT,
                            font=FONT, exportselection=False, takefocus=0)
            lb.pack(fill="both", expand=True)
            lb.bind("<Button-1>", self._ac_pick)
            self._ac_win, self._ac_lb = win, lb
        lb = self._ac_lb
        lb.delete(0, "end")
        for s in matches:
            lb.insert("end", s)
        lb.selection_set(0)
        lb.see(0)
        ent = self._filter_entry
        x = ent.winfo_rootx()
        y = ent.winfo_rooty() + ent.winfo_height() + 2
        w = max(ent.winfo_width(), 220)
        self._ac_win.geometry(f"{w}x{22 * len(matches) + 6}+{x}+{y}")

    def _ac_pick(self, e):
        if self._ac_lb:
            i = self._ac_lb.nearest(e.y)
            if i >= 0:
                self._ac_accept(self._ac_lb.get(i))

    def _ac_accept(self, s):
        self._ac_hide()
        self.var_filter.set(s)

    def _ac_move(self, delta):
        if not self._ac_lb:
            return "break"
        lb = self._ac_lb
        cur = lb.curselection()
        i = cur[0] if cur else 0
        i = max(0, min(lb.size() - 1, i + delta))
        lb.selection_clear(0, "end")
        lb.selection_set(i)
        lb.see(i)
        return "break"

    def _ac_enter(self, _e):
        if self._ac_lb:
            cur = self._ac_lb.curselection()
            if cur:
                self._ac_accept(self._ac_lb.get(cur[0]))
                return "break"
        self._ac_hide()
        return None

    def _ac_key(self, e):
        if e.keysym in ("Up", "Down", "Return", "KP_Enter", "Tab", "Escape"):
            return
        if self._ac_after:
            self.root.after_cancel(self._ac_after)
        self._ac_after = self.root.after(150, self._ac_update)

    # ------------------------------ события UI ----------------------------
    def set_event(self, text):
        self.lbl_event.configure(text=text)

    def _copy_row_cmd(self):
        sel = self.tree.selection()
        if sel:
            addr = self.tree.item(sel[0], "values")[1]
            self.root.clipboard_clear()
            self.root.clipboard_append(addr)
            self.set_event(T("copied_one", a=addr))

    def _copy_selected_all(self):
        sel = self.tree.selection()
        if not sel:
            return
        addrs = "\n".join(self.tree.item(i, "values")[1] for i in sel)
        self.root.clipboard_clear()
        self.root.clipboard_append(addrs)
        self.set_event(T("copied_many", n=len(sel)))

    def _show_ctx(self, e):
        iid = self.tree.identify_row(e.y)
        if iid and iid not in self.tree.selection():
            self.tree.selection_set(iid)
        try:
            self.ctx.tk_popup(e.x_root, e.y_root)
        finally:
            self.ctx.grab_release()

    def _recheck_selected(self):
        if not self.tree.selection():
            messagebox.showinfo(T("ti_recheck"), T("mb_sel_rows"), parent=self.root)
            return
        self.recheck()

    def _export_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo(T("ti_export"), T("mb_sel_rows"), parent=self.root)
            return
        idxs = {int(i) for i in sel if str(i).isdigit()}
        rows = [p for p in self.proxies if p.idx in idxs]
        if rows:
            ExportDialog(self, rows=rows)

    def _on_fstatus(self, _e=None):
        rev = {T("status_all"): "all"}
        rev.update({T("st_" + k): k for k in STATUS_ORDER})
        self._fstatus_key = rev.get(self.var_fstatus.get(), "all")
        self._apply_filter()

    # ------------------------------ сортировка ----------------------------
    def _sort_key_from_vals(self, col, vals):
        v = vals[self.cols.index(col)]
        tie = float(vals[0]) if str(vals[0]).strip().isdigit() else 0.0
        if col in ("num", "ping", "score"):
            v = v.replace(T("ms"), "").strip()
            try:
                return (0, float(v), tie)
            except ValueError:
                return (1, 0.0, tie)
        return (0, str(v).lower(), tie)

    def _sort(self, col):
        rev = not self._sort_dir.get(col, False)
        self._sort_dir[col] = rev
        self._sort_state = (col, rev)
        items = sorted(((self._sort_key_from_vals(col, self.tree.item(iid, "values")),
                         iid) for iid in self.tree.get_children("")),
                       key=lambda t: t[0], reverse=rev)
        self._order = [iid for _, iid in items]
        self._order_keys = [k for k, _ in items]
        for pos, iid in enumerate(self._order):
            self.tree.move(iid, "", pos)

    def _order_remove(self, iid):
        try:
            i = self._order.index(iid)
        except ValueError:
            return
        del self._order[i]
        del self._order_keys[i]

    def _order_insert(self, iid, vals):
        key = self._sort_key_from_vals(self._sort_state[0], vals)
        keys, lo, hi = self._order_keys, 0, len(self._order_keys)
        rev = self._sort_state[1]
        while lo < hi:
            mid = (lo + hi) // 2
            if rev:
                if keys[mid] >= key:
                    lo = mid + 1
                else:
                    hi = mid
            else:
                if keys[mid] <= key:
                    lo = mid + 1
                else:
                    hi = mid
        keys.insert(lo, key)
        self._order.insert(lo, iid)

    def _on_filter_changed(self, *_):
        if self._filter_after:
            self.root.after_cancel(self._filter_after)
        self._filter_after = self.root.after(250, self._apply_filter)

    # ------------------------------ загрузка ------------------------------
    def load_file(self):
        path = filedialog.askopenfilename(
            title=T("fd_open_title"),
            filetypes=[(T("ft_text"), "*.txt"), (T("ft_all"), "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError as e:
            messagebox.showerror(T("mb_title"), T("mb_read_err", e=e),
                                 parent=self.root)
            return
        self.list_path = path
        self._load_text(content)

    def load_url(self, url=None):
        if url is None:
            URLDialog(self)
            return
        try:
            with urlopen(Request(url, headers={"User-Agent": USER_AGENT}),
                         timeout=20) as r:
                text = r.read().decode("utf-8", "replace")
        except Exception as e:
            messagebox.showerror(T("ti_load"), T("mb_download_err", e=e),
                                 parent=self.root)
            return
        self._load_text(text)

    def load_buffer(self):
        BufferDialog(self)

    def _on_drop(self, e):
        for raw in re.findall(r"\{[^}]*\}|\S+", e.data):
            path = raw.strip("{}").strip()
            if os.path.isfile(path):
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except OSError as ex:
                    messagebox.showerror(T("mb_title"), T("mb_read_err", e=ex),
                                         parent=self.root)
                    return
                self.list_path = path
                self._load_text(content)
                return
        self.set_event(T("drop_hint"))

    def _load_text(self, text):
        if self.running:
            messagebox.showinfo(T("mb_title"), T("mb_running"), parent=self.root)
            return
        proxies, bad_lines, seen = [], 0, set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                p = parse_line(line)
            except ValueError:
                bad_lines += 1
                continue
            key = (p.host, p.port, p.user, p.pwd)
            if key in seen:
                continue
            seen.add(key)
            p.idx = len(proxies)
            proxies.append(p)
        if not proxies:
            messagebox.showwarning(T("mb_title"), T("mb_noproxies"),
                                   parent=self.root)
            return
        self.proxies = proxies
        self.done = self.ok = self.fail = 0
        self.err_counter = Counter()
        self.exit_counts = defaultdict(int)
        self.exit_map = defaultdict(set)
        self._sort_state = None
        self._ac_cache = (None, None, 0.0)
        self.tree.delete(*self.tree.get_children(""))
        self.progress.configure(maximum=len(proxies), value=0)
        self.btn_start["state"] = "normal"
        self.btn_export["state"] = "disabled"
        self.btn_recheck["state"] = "disabled"
        self.btn_stats["state"] = "disabled"
        msg = T("loaded", n=len(proxies))
        if bad_lines:
            msg += T("loaded_bad", n=bad_lines)
        self.set_event(msg + T("press_start"))
        self.lbl_prog.configure(text=f"0/{len(proxies)}")
        self.lbl_live.configure(text="")

    # ------------------------------ настройки -----------------------------
    def _edit_targets(self):
        TargetDialog(self)

    def choose_autosave(self):
        path = filedialog.asksaveasfilename(
            title=T("fd_autosave_title"),
            defaultextension=".txt", initialfile="working_proxies.txt",
            filetypes=[(T("ft_text"), "*.txt"), (T("ft_all"), "*.*")])
        if path:
            self.autosave_path = path
            self.var_autosave.set(True)
            self.btn_autosave.configure(text=os.path.basename(path))

    # ------------------------------ запуск/стоп ---------------------------
    def _read_spin(self, var, default, lo, hi):
        try:
            return max(lo, min(hi, int(var.get())))
        except ValueError:
            var.set(str(default))
            return default

    def start(self):
        if not self.proxies:
            return
        if self.active:
            messagebox.showinfo(T("mb_title"), T("mb_wait"), parent=self.root)
            return
        self.timeout = self._read_spin(self.var_timeout, 5, 1, 60)
        self.geo_timeout = self._read_spin(self.var_geo_timeout, 4, 1, 30)
        retries = self._read_spin(self.var_retries, 1, 0, 5)
        threads = self._read_spin(self.var_threads, 0, 0, 500)
        targets = list(self.targets) \
            if self.var_target.get() and self.targets else None
        self.cfg = Cfg(timeout=float(self.timeout),
                       geo_timeout=float(self.geo_timeout),
                       retries=retries,
                       use_proxy_geo=bool(self.var_proxygeo.get()),
                       direct_geo=bool(self.var_directgeo.get()),
                       anon=bool(self.var_anon.get()),
                       targets=targets)
        if threads <= 0:
            threads = calc_threads(len(self.proxies), self.timeout)
            self.var_threads.set(str(threads))
        threads = max(1, min(threads, len(self.proxies)))

        for p in self.proxies:
            self._retract(p)
            _reset_proxy(p)

        self.stop_event.clear()
        self.pause_event.clear()
        self.btn_pause["text"] = T("btn_pause")
        self.run_id += 1
        self.done = self.ok = self.fail = 0
        self.err_counter = Counter()
        self.exit_counts = defaultdict(int)
        self.exit_map = defaultdict(set)
        self._real_ip, self._real_ip_fetched = None, False
        self.running = True
        self.t_start = time.monotonic()

        self._sort_state = None
        self._order, self._order_keys = [], []
        self.tree.delete(*self.tree.get_children(""))
        self.progress.configure(maximum=len(self.proxies), value=0)
        self.btn_start["state"] = "disabled"
        self.btn_recheck["state"] = "disabled"
        self.btn_export["state"] = "disabled"
        self.btn_stats["state"] = "disabled"
        self.btn_stop["state"] = "normal"
        self.btn_pause["state"] = "normal"
        self.mb_load["state"] = "disabled"
        self.btn_services["state"] = "disabled"        # фикс аудита: гонка сервисов

        self._open_autosave()
        self._save_settings()
        if self.pool:
            self.pool.close()
        self.pool = WorkerPool(threads, self._task, self.stop_event, self.pause_event)
        self.pool.submit_many(self.proxies)
        tg = T("started_targets", n=len(targets)) if targets else ""
        self.set_event(T("started", n=len(self.proxies), t=threads,
                         to=self.timeout, r=retries, tg=tg))

    def _open_autosave(self):
        self.autosave_fh = None
        if not self.var_autosave.get():
            return
        path = self.autosave_path
        if not path and self.list_path:
            path = os.path.splitext(self.list_path)[0] + "_working.txt"
        if not path:
            self.set_event(T("autosave_nofile"))
            return
        try:
            self.autosave_fh = open(path, "w", encoding="utf-8", buffering=1)
        except OSError as e:
            messagebox.showerror(T("ti_autosave"), T("mb_autosave_err", e=e),
                                 parent=self.root)

    def _close_autosave(self):
        if self.autosave_fh:
            try:
                self.autosave_fh.close()
            except OSError:
                pass
            self.autosave_fh = None

    def toggle_pause(self):
        if not self.running:
            return
        if self.pause_event.is_set():
            self.pause_event.clear()
            self.btn_pause["text"] = T("btn_pause")
            self.set_event(T("resumed"))
        else:
            self.pause_event.set()
            self.btn_pause["text"] = T("btn_resume")
            self.set_event(T("paused"))

    def stop(self):
        self.stop_event.set()
        if self.pool:
            self.pool.drain()
        self.running = False
        self._close_autosave()
        self._save_settings()
        self.btn_stop["state"] = "disabled"
        self.btn_pause["state"] = "disabled"
        self.btn_start["state"] = "normal"
        self.mb_load["state"] = "normal"
        self.btn_services["state"] = "normal"          # фикс аудита
        if self.done:
            self.btn_recheck["state"] = "normal"
            self.btn_export["state"] = "normal"
            self.btn_stats["state"] = "normal"
        self.set_event(T("stopped", d=self.done, n=len(self.proxies), ok=self.ok))
        self.lbl_live.configure(text="")

    def recheck(self):
        if self.running:
            messagebox.showinfo(T("ti_recheck"), T("mb_running"), parent=self.root)
            return
        if not self.proxies:
            messagebox.showinfo(T("ti_recheck"), T("mb_load_first"), parent=self.root)
            return
        if self.pool is None:
            messagebox.showinfo(T("ti_recheck"), T("mb_recheck_first"),
                                parent=self.root)
            return
        sel = self.tree.selection()
        if sel:
            idxs = {int(i) for i in sel if str(i).isdigit()}
            chosen = [p for p in self.proxies if p.idx in idxs]
        else:
            chosen = [p for p in self.proxies if p.checked and not p.alive]
        if not chosen:
            messagebox.showinfo(T("ti_recheck"), T("mb_recheck_nodata"),
                                parent=self.root)
            return
        for p in chosen:
            self._retract(p)
            _reset_proxy(p)
        self.stop_event.clear()
        self.pause_event.clear()
        self.btn_pause["text"] = T("btn_pause")
        self.running = True
        self.t_start = time.monotonic()
        self.btn_start["state"] = "disabled"
        self.btn_recheck["state"] = "disabled"
        self.btn_export["state"] = "disabled"
        self.btn_stats["state"] = "disabled"
        self.btn_stop["state"] = "normal"
        self.btn_pause["state"] = "normal"
        self.mb_load["state"] = "disabled"
        self.btn_services["state"] = "disabled"        # фикс аудита
        self.pool.submit_many(chosen)
        self.set_event(T("rechecking", n=len(chosen)))

    # ------------------------------ воркеры -------------------------------
    def _task(self, p):
        if self.stop_event.is_set():
            return
        rid = self.run_id
        self.q.put(("start", rid, None))
        try:
            check_proxy(p, self.cfg, self.limiter, self.stop_event, self._get_real_ip)
        except Exception as exc:
            p.status, p.note = "error", repr(exc)[:100]
        self.q.put(("done", rid, p))

    def _get_real_ip(self):
        if self._real_ip_fetched:
            return self._real_ip
        with self._real_ip_lock:
            if self._real_ip_fetched:
                return self._real_ip
            ip = _direct_echo_ip()
            if ip is None and self.cfg and self.cfg.direct_geo:
                try:
                    self.limiter.wait()
                    g = _geo_direct("ip-api.com")
                    ip = g[3] if g else None
                except Exception:
                    ip = None
            self._real_ip, self._real_ip_fetched = ip, True
            return ip

    def _poll(self):
        try:
            while True:
                kind, rid, payload = self.q.get_nowait()
                if kind == "start":
                    if rid == self.run_id:
                        self.active += 1
                else:
                    self.active = max(0, self.active - 1)
                    if rid == self.run_id:
                        self._on_result(payload)
        except queue.Empty:
            pass
        self._update_progress()
        self.root.after(100, self._poll)

    # ------------------------------ скоринг -------------------------------
    _PROTO_SCORE = {"HTTPS": 100, "SOCKS5": 90, "HTTP": 70, "SOCKS4": 50}
    _ANON_SCORE = {"elite": 100, "anon": 60, "transp": 10}

    def score(self, p):
        if not p.alive:
            return 0
        ping = p.ping or 0
        sp = max(0.0, 100.0 - max(0.0, ping - 50.0) / 19.5)   # 50мс→100, 2000мс→0
        st = self._PROTO_SCORE.get(p.proto, 50)
        sa = self._ANON_SCORE.get(p.anon, 55)
        ss = (p.stable_ok * 100.0 / p.stable_total) if p.stable_total else 50.0
        return round(sp * 0.35 + st * 0.25 + sa * 0.20 + ss * 0.20)

    # ------------------------------ результаты ----------------------------
    def country_disp(self, p):
        if not p.country and not p.cc:
            return "—"
        name = p.country or p.cc
        if p.cc:
            return (flag_emoji(p.cc) + " " + name) if self.var_flags.get() \
                else f"[{p.cc}] {name}"
        return name

    def _tag_for(self, p):
        if p.alive:
            return "ok"
        return "warn" if p.status in ("auth_required", "auth_failed",
                                      "target_fail") else "bad"

    def _row_values(self, p):
        exit_s = p.exit_ip or "—"
        if p.exit_ip and self.exit_counts.get(p.exit_ip, 0) > 1:
            exit_s = f"{p.exit_ip} ×{self.exit_counts[p.exit_ip]}"
        ping = f"{p.ping} {T('ms')}" if p.ping is not None else "—"
        sc = str(self.score(p)) if p.alive else "—"
        anon = T("an_" + p.anon) if p.anon else "—"
        return (p.idx + 1, p.addr, p.proto or "—", status_disp(p.status), ping,
                sc, self.country_disp(p), p.city or "—", exit_s, anon,
                p.target or "—", note_disp(p.note))

    def _matches(self, p):
        if self.var_only_ok.get() and not p.alive:
            return False
        if self._fstatus_key != "all" and p.status != self._fstatus_key:
            return False
        q = self.var_filter.get().strip().lower()
        if q:
            hay = " ".join((p.addr, p.proto, status_disp(p.status),
                            p.country, p.cc, p.city, p.exit_ip,
                            T("an_" + p.anon) if p.anon else "",
                            note_disp(p.note))).lower()
            if q not in hay:
                return False
        return True

    def _upsert_row(self, p, tag=None):
        iid = str(p.idx)
        if not self._matches(p):
            if self.tree.exists(iid):
                self.tree.delete(iid)
                self._order_remove(iid)
            return
        if tag is None:
            tag = self._tag_for(p)
        vals = self._row_values(p)
        if self.tree.exists(iid):
            self.tree.item(iid, values=vals, tags=(tag,))
            if self._sort_state:                     # значение могло измениться
                self._order_remove(iid)
                self._order_insert(iid, vals)
                self.tree.move(iid, "", self._order.index(iid))
        else:
            self.tree.insert("", "end", iid=iid, values=vals, tags=(tag,))
            if self._sort_state:
                self._order_insert(iid, vals)
                self.tree.move(iid, "", self._order.index(iid))
            else:
                self._order.append(iid)

    def _apply_filter(self):
        self._filter_after = None
        self.tree.delete(*self.tree.get_children(""))
        self._order, self._order_keys = [], []
        for p in self.proxies:
            if p.checked and self._matches(p):
                self._upsert_row(p)

    def _refresh_exit_display(self, ip):
        for idx in list(self.exit_map.get(ip, ())):
            self._upsert_row(self.proxies[idx])

    def _err_key(self, p):
        return p.note or ("@" + p.status)

    def _retract(self, p):
        if not p.checked:
            return
        self.done -= 1
        p.checked = False
        if p.alive:
            self.ok -= 1
            if p.exit_ip:
                ip = p.exit_ip
                n = self.exit_counts.get(ip, 0) - 1
                self.exit_map.get(ip, set()).discard(p.idx)
                if n <= 0:
                    self.exit_counts.pop(ip, None)
                    self.exit_map.pop(ip, None)
                else:
                    self.exit_counts[ip] = n
                    self._refresh_exit_display(ip)
        else:
            key = self._err_key(p)
            n = self.err_counter.get(key, 0) - 1
            if n <= 0:
                self.err_counter.pop(key, None)
            else:
                self.err_counter[key] = n

    def _on_result(self, p):
        self._retract(p)
        self.done += 1
        p.checked = True
        p.stable_total += 1                        # история стабильности
        tag = self._tag_for(p)
        if p.alive:
            self.ok += 1
            p.stable_ok += 1
            if p.exit_ip:
                self.exit_counts[p.exit_ip] += 1
                self.exit_map[p.exit_ip].add(p.idx)
            if self.autosave_fh:
                try:
                    self.autosave_fh.write(_auto_line(p) + "\n")
                except OSError:
                    pass
        else:
            self.fail += 1
            self.err_counter[self._err_key(p)] += 1
        self._upsert_row(p, tag)
        if p.exit_ip and self.exit_counts.get(p.exit_ip, 0) > 1:
            self._refresh_exit_display(p.exit_ip)
        if p.alive:
            anon = f" ({T('an_' + p.anon)})" if p.anon else ""
            self.set_event(T("ok_found", a=p.addr, proto=p.proto,
                             ping=f"{p.ping} {T('ms')}",
                             geo=self.country_disp(p), anon=anon))

    def _err_summary(self):
        if not self.err_counter:
            return T("err_none")
        parts = [f"{v} {note_disp(k)}" for k, v in self.err_counter.most_common(4)]
        extra = len(self.err_counter) - 4
        s = " • ".join(parts)
        if extra > 0:
            s += T("err_more", n=extra)
        return T("err_prefix") + s

    def _update_progress(self):
        self.lbl_err.configure(text=self._err_summary()
                               if (self.err_counter or self.done) else T("err_dash"))
        total = len(self.proxies)
        if not total or not (self.running or self.done):
            return
        self.progress.configure(value=max(0, self.done))
        self.lbl_prog.configure(text=T("prog", d=self.done, n=total,
                                       ok=self.ok, fail=self.fail))
        if self.pause_event.is_set() and self.running:
            self.lbl_live.configure(text=T("paused_label"))
            return
        if self.running:
            elapsed = time.monotonic() - self.t_start
            speed = self.done / elapsed * 60 if elapsed > 0.5 and self.done else 0.0
            eta = (total - self.done) / (self.done / elapsed) \
                if self.done and elapsed > 0 else 0.0
            self.lbl_live.configure(text=T("live", a=self.active,
                                           s=f"{speed:.0f}", t=fmt_time(eta)))
            if self.done >= total and self.active == 0:
                self._finish()

    def _finish(self):
        self.running = False
        self._close_autosave()
        self._save_settings()
        self.btn_stop["state"] = "disabled"
        self.btn_pause["state"] = "disabled"
        self.btn_start["state"] = "normal"
        self.btn_recheck["state"] = "normal"
        self.btn_export["state"] = "normal"
        self.btn_stats["state"] = "normal"
        self.mb_load["state"] = "normal"
        self.btn_services["state"] = "normal"          # фикс аудита
        self.lbl_live.configure(text="")
        ev = T("done", ok=self.ok, n=len(self.proxies),
               t=fmt_time(time.monotonic() - self.t_start))
        if self.err_counter:
            ev += "  " + self._err_summary()
        self.set_event(ev)

    # ------------------------------ диалоги -------------------------------
    def export_dialog(self):
        if not self.proxies:
            messagebox.showinfo(T("ti_export"), T("mb_load_first"), parent=self.root)
            return
        ExportDialog(self)

    def _stats_dialog(self):
        if not any(p.checked for p in self.proxies):
            messagebox.showinfo(T("ti_stats"), T("stats_nodata"), parent=self.root)
            return
        StatsDialog(self)


# --------------------------------------------------------------------------
# Диалоги
# --------------------------------------------------------------------------
class URLDialog(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app.root)
        self.app = app
        self.title(T("url_title"))
        self.configure(bg=C_BG)
        self.resizable(False, False)
        self.transient(app.root)
        self.grab_set()
        frm = tk.Frame(self, bg=C_BG)
        frm.pack(fill="both", expand=True, padx=16, pady=14)
        tk.Label(frm, justify="left", bg=C_BG, fg=C_DIM, font=FONT,
                 text=T("url_label")).pack(anchor="w")
        self.ent = ttk.Entry(frm, width=58)
        self.ent.pack(fill="x", pady=(4, 10))
        self.ent.focus_set()
        self.ent.bind("<Return>", lambda e: self._ok())
        row = tk.Frame(frm, bg=C_BG)
        row.pack()
        ttk.Button(row, text=T("btn_ok"), style="Accent.TButton",
                   command=self._ok).pack(side="left", padx=(0, 8))
        ttk.Button(row, text=T("btn_cancel"), command=self.destroy).pack(side="left")

    def _ok(self):
        url = self.ent.get().strip()
        if not url:
            return
        m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://", url)
        if m:
            if m.group(1).lower() not in ("http", "https"):
                messagebox.showwarning(T("ti_url"), T("url_bad_scheme"), parent=self)
                return
        else:
            url = "https://" + url
        self.destroy()
        self.app.load_url(url)


class BufferDialog(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app.root)
        self.app = app
        self.title(T("buf_title"))
        self.configure(bg=C_BG)
        self.transient(app.root)
        self.grab_set()
        frm = tk.Frame(self, bg=C_BG)
        frm.pack(fill="both", expand=True, padx=16, pady=14)
        tk.Label(frm, text=T("buf_label"), bg=C_BG, fg=C_DIM,
                 font=FONT).pack(anchor="w")
        self.txt = tk.Text(frm, width=60, height=12, bg=C_CARD, fg=C_TEXT,
                           relief="flat", padx=8, pady=6, insertbackground=C_TEXT)
        self.txt.pack(fill="both", expand=True, pady=(4, 10))
        try:
            self.txt.insert("1.0", app.root.clipboard_get())
        except Exception:
            pass
        row = tk.Frame(frm, bg=C_BG)
        row.pack()
        ttk.Button(row, text=T("btn_ok"), style="Accent.TButton",
                   command=self._ok).pack(side="left", padx=(0, 8))
        ttk.Button(row, text=T("btn_cancel"), command=self.destroy).pack(side="left")

    def _ok(self):
        text = self.txt.get("1.0", "end")
        self.destroy()
        self.app._load_text(text)


class TargetDialog(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app.root)
        self.app = app
        self.title(T("tgt_title"))
        self.configure(bg=C_BG)
        self.transient(app.root)
        self.grab_set()
        frm = tk.Frame(self, bg=C_BG)
        frm.pack(fill="both", expand=True, padx=16, pady=14)
        tk.Label(frm, justify="left", fg=C_DIM, bg=C_BG, font=FONT,
                 text=T("tgt_help")).pack(anchor="w")
        self.txt = tk.Text(frm, width=58, height=8, bg=C_CARD, fg=C_TEXT,
                           relief="flat", padx=8, pady=6, insertbackground=C_TEXT)
        self.txt.pack(fill="both", expand=True, pady=(6, 4))
        if app.targets:
            self.txt.insert("1.0", "\n".join(app.targets))
        prow = tk.Frame(frm, bg=C_BG)
        prow.pack(fill="x", pady=(0, 8))
        tk.Label(prow, text=T("tgt_scheme"), bg=C_BG, fg=C_DIM,
                 font=FONT).pack(side="left")
        self.var_prefix = tk.StringVar(value="https://")
        ttk.Combobox(prow, textvariable=self.var_prefix, state="readonly",
                     values=("https://", "http://"), width=9
                     ).pack(side="left", padx=(6, 0))
        row = tk.Frame(frm, bg=C_BG)
        row.pack()
        ttk.Button(row, text=T("btn_save"), style="Accent.TButton",
                   command=self._save).pack(side="left", padx=(0, 8))
        ttk.Button(row, text=T("btn_cancel"), command=self.destroy).pack(side="left")

    def _save(self):
        prefix = self.var_prefix.get()
        urls, bad = [], []
        for line in self.txt.get("1.0", "end").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://", s)
            if m:
                if m.group(1).lower() in ("http", "https"):
                    urls.append(s.rstrip("/"))
                else:
                    bad.append(s)
            else:
                urls.append((prefix + s).rstrip("/"))
        if bad:
            messagebox.showwarning(T("ti_targets"), T("tgt_bad")
                                   + "\n".join(bad[:5]), parent=self)
        self.app.targets = urls
        self.app.btn_targets.configure(text=T("btn_targets", n=len(urls)))
        self.app._save_settings()
        self.destroy()


class ServicesDialog(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app.root)
        self.app = app
        self.title(T("svc_title"))
        self.configure(bg=C_BG)
        self.transient(app.root)
        self.grab_set()
        frm = tk.Frame(self, bg=C_BG)
        frm.pack(fill="both", expand=True, padx=16, pady=14)
        tk.Label(frm, justify="left", fg=C_DIM, bg=C_BG, font=FONT,
                 text=T("svc_help"), wraplength=520).pack(anchor="w", pady=(0, 8))
        tk.Label(frm, justify="left", fg=C_TEXT, bg=C_BG, font=FONT,
                 text=T("svc_alive")).pack(anchor="w")
        self.txt_alive = tk.Text(frm, width=64, height=4, bg=C_CARD, fg=C_TEXT,
                                 relief="flat", padx=8, pady=6,
                                 insertbackground=C_TEXT)
        self.txt_alive.pack(fill="x", pady=(2, 8))
        self.txt_alive.insert("1.0", "\n".join(ALIVE_URLS))
        tk.Label(frm, justify="left", fg=C_TEXT, bg=C_BG, font=FONT,
                 text=T("svc_echo")).pack(anchor="w")
        self.txt_echo = tk.Text(frm, width=64, height=3, bg=C_CARD, fg=C_TEXT,
                                relief="flat", padx=8, pady=6,
                                insertbackground=C_TEXT)
        self.txt_echo.pack(fill="x", pady=(2, 8))
        self.txt_echo.insert("1.0", "\n".join(ECHO_URLS))
        tk.Label(frm, justify="left", fg=C_TEXT, bg=C_BG, font=FONT,
                 text=T("svc_geo")).pack(anchor="w")
        self.ent_geo = ttk.Entry(frm, width=64)
        self.ent_geo.pack(fill="x", pady=(2, 10))
        self.ent_geo.insert(0, GEO_BASE)
        row = tk.Frame(frm, bg=C_BG)
        row.pack()
        ttk.Button(row, text=T("btn_save"), style="Accent.TButton",
                   command=self._save).pack(side="left", padx=(0, 8))
        ttk.Button(row, text=T("btn_cancel"), command=self.destroy).pack(side="left")

    def _parse_urls(self, text):
        ok, bad = [], []
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = _split_target(s)
            if parts:
                ok.append(s.rstrip("/"))
            else:
                bad.append(s)
        return ok, bad

    def _save(self):
        alive, bad1 = self._parse_urls(self.txt_alive.get("1.0", "end"))
        echo, bad2 = self._parse_urls(self.txt_echo.get("1.0", "end"))
        geo = self.ent_geo.get().strip()
        bad = bad1 + bad2
        if not _split_target(geo):
            bad.append(geo)
            geo = None
        if not alive:
            messagebox.showwarning(T("ti_services"), T("svc_need_alive"), parent=self)
            return
        if geo:
            geo = geo.rstrip("/") + "/"
        else:
            geo = GEO_BASE
        self.app._apply_services(alive, echo, geo)
        self.app._save_settings()
        if bad:
            messagebox.showwarning(T("ti_services"), T("svc_bad") + "\n".join(bad[:5]),
                                   parent=self)
        else:
            messagebox.showinfo(T("ti_services"), T("svc_saved"), parent=self)
        self.destroy()


class ExportDialog(tk.Toplevel):
    def __init__(self, app, rows=None):
        super().__init__(app.root)
        self.app = app
        self.rows = rows
        self.title(T("exp_title"))
        self.configure(bg=C_BG)
        self.resizable(False, False)
        self.transient(app.root)
        self.grab_set()
        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True, padx=16, pady=14)
        r0 = 0
        if rows is not None:
            ttk.Label(frm, text=T("exp_selected", n=len(rows))
                      ).grid(row=0, column=0, sticky="w", pady=(0, 6))
            r0 = 1
        ttk.Label(frm, text=T("exp_format")).grid(row=r0, column=0,
                                                  sticky="w", pady=(0, 4))
        self.var_fmt = tk.StringVar(value="plain")
        for i, (val, txt) in enumerate([
                ("plain", "ip:port"),
                ("proto", T("fmt_proto")),
                ("full",  T("fmt_full")),
                ("csv",   T("fmt_csv"))], start=r0 + 1):
            ttk.Radiobutton(frm, text=txt, value=val,
                            variable=self.var_fmt).grid(row=i, column=0, sticky="w")
        self.var_only = tk.BooleanVar(value=True)
        if rows is None:
            ttk.Checkbutton(frm, text=T("exp_only"), variable=self.var_only
                            ).grid(row=r0 + 5, column=0, sticky="w", pady=(8, 12))
            r_btn = r0 + 6
        else:
            r_btn = r0 + 5
        ttk.Button(frm, text=T("btn_saveas"), style="Accent.TButton",
                   command=self.save).grid(row=r_btn, column=0, sticky="ew")

    def save(self):
        fmt = self.var_fmt.get()
        if self.rows is not None:
            rows = list(self.rows)
        else:
            only_ok = self.var_only.get()
            rows = [p for p in self.app.proxies
                    if (p.alive if only_ok else p.checked)]
        if not rows:
            messagebox.showinfo(T("ti_export"), T("exp_none"), parent=self)
            return
        ext = ".csv" if fmt == "csv" else ".txt"
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=ext,
            initialfile=("working_proxies" if (self.rows is None and
                                               self.var_only.get())
                         else "proxies") + ext,
            filetypes=[("CSV", "*.csv"), (T("ft_text"), "*.txt"),
                       (T("ft_all"), "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8", newline="") as f:
                if fmt == "csv":
                    w = csv.writer(f, delimiter=";")
                    w.writerow(["proxy", "protocol", "status", "ping_ms", "score",
                                "anon", "target", "country", "city", "exit_ip",
                                "note"])
                    for p in rows:
                        w.writerow([p.addr, p.proto, status_disp(p.status),
                                    p.ping if p.ping is not None else "",
                                    self.app.score(p) if p.alive else "",
                                    T("an_" + p.anon) if p.anon else "",
                                    p.target, p.country, p.city,
                                    p.exit_ip, note_disp(p.note)])
                else:
                    for p in rows:
                        f.write(_export_line(p, fmt) + "\n")
        except OSError as e:
            messagebox.showerror(T("ti_export"), T("exp_error", e=e), parent=self)
            return
        messagebox.showinfo(T("ti_export"), T("exp_saved", n=len(rows), p=path),
                            parent=self)
        self.destroy()


class StatsDialog(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app.root)
        self.title(T("stats_title"))
        self.configure(bg=C_BG)
        self.transient(app.root)
        txt = tk.Text(self, width=84, height=28, bg=C_CARD, fg=C_TEXT,
                      font=("Consolas", 9), relief="flat", padx=12, pady=10)
        txt.pack(fill="both", expand=True, padx=8, pady=(8, 4))
        txt.insert("1.0", self._build(app))
        txt.configure(state="disabled")
        ttk.Button(self, text=T("btn_close"), command=self.destroy).pack(pady=(0, 10))

    def _build(self, app):
        ps = app.proxies
        checked = [p for p in ps if p.checked]
        ok = [p for p in checked if p.alive]
        L = []
        L.append(f"{T('st_total')} {len(ps)}")
        L.append(f"{T('st_checked')} {len(checked)}")
        pct = f"  ({len(ok) * 100 // len(checked)}%)" if checked else ""
        L.append(f"{T('st_working')} {len(ok)}{pct}")
        if ok:
            scores = [app.score(p) for p in ok]
            L.append(f"{T('st_score')} {round(sum(scores) / len(scores))} (0–100)")
            pings = sorted(p.ping for p in ok if p.ping is not None)
            if pings:
                n = len(pings)
                med = pings[n // 2] if n % 2 else (pings[n // 2 - 1] + pings[n // 2]) / 2
                L.append(f"{T('st_ping')} {T('st_min')} {pings[0]} • "
                         f"{T('st_med')} {med:.0f} • {T('st_max')} {pings[-1]} {T('ms')}")
            types = Counter(p.proto for p in ok if p.proto)
            L.append(f"{T('st_types')} " + ", ".join(f"{k} — {v}"
                                                     for k, v in types.most_common()))
            anon = Counter(T("an_" + p.anon) for p in ok if p.anon)
            if anon:
                L.append(f"{T('st_anon')} " + ", ".join(f"{k} — {v}"
                                                        for k, v in anon.most_common()))
            cc = Counter(app.country_disp(p) for p in ok)
            L.append(T("st_countries") + ", ".join(f"{c} {v}"
                                                   for c, v in cc.most_common(10)))
            L.append("")
            L.append(T("st_fast"))
            fast = sorted(ok, key=lambda x: x.ping if x.ping is not None else 10 ** 9)
            for p in fast[:10]:
                a = T("an_" + p.anon) if p.anon else "—"
                L.append(f"   {p.addr:<23} {p.ping:>5} {T('ms')}  "
                         f"{app.score(p):>3}  {app.country_disp(p):<18} "
                         f"{p.proto:<7} {a}")
        if app.err_counter:
            L.append("")
            L.append(T("st_reasons"))
            for k, v in app.err_counter.most_common(12):
                L.append(f"   {v:>6}  {note_disp(k)}")
        return "\n".join(L) or T("st_nodata")

# --------------------------------------------------------------------------
def main():
    if HAS_DND:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    root.title("Proxy Checker")
    root.geometry("1220x700")
    root.minsize(1000, 560)
    App(root, dnd=HAS_DND)
    root.mainloop()


if __name__ == "__main__":
    main()
