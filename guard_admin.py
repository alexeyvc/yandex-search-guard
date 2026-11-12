"""Account sessions, event selection and XLSX export; standard library only."""
import hashlib
import hmac
import io
import json
import re
import secrets
import time
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from xml.sax.saxutils import escape

ADMIN_FIELDS = frozenset({"llm_url", "llm_model", "llm_key", "timeout", "json_mode",
                          "yandex_key", "folder_id", "search_type", "region"})
FILTERS = {"ALL", "BLOCK", "ALLOW", "ERROR", "AUTH"}


def merge_settings(old, patch, is_admin):
    if not isinstance(patch, dict) or set(patch) - set(old):
        raise ValueError("Invalid settings fields")
    if not is_admin and set(patch) & ADMIN_FIELDS:
        raise PermissionError("Connection settings require administrator")
    merged = {**old, **patch}
    for name in ("llm_key", "yandex_key"):
        if name in patch and patch[name] == "":
            merged[name] = old[name]
    return merged


def _object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate account")
        result[key] = value
    return result


@dataclass(frozen=True)
class User:
    username: str
    is_admin: bool
    csrf_token: str



def event_rows(connect, decision="ALL", username="", date_from="", date_to="", limit=None):
    if decision not in FILTERS or len(username) > 64:
        raise ValueError("Invalid filter")
    clauses, args = [], []
    if decision == "AUTH":
        clauses.append("event_type='AUTH'")
    elif decision != "ALL":
        clauses.append("event_type='SEARCH' AND decision=?")
        args.append(decision)
    if username:
        clauses.append("username=?")
        args.append(username)
    start = end = None
    for key, text in (("from", date_from), ("to", date_to)):
        if not text:
            continue
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            raise ValueError("Expected YYYY-MM-DD")
        value = datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if key == "from":
            start = value
            clauses.append("ts>=?"); args.append(value.timestamp())
        else:
            end = value
            try:
                exclusive_end = value + timedelta(days=1)
            except OverflowError as exc:
                raise ValueError("End date is outside supported range") from exc
            clauses.append("ts<?"); args.append(exclusive_end.timestamp())
    if start and end and start > end:
        raise ValueError("Invalid date interval")
    sql = "SELECT id,ts,request_id,origin,decision,code,ms,query_text,event_type,username,model_decision,model_flags,model_status FROM events"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id DESC"
    if limit is not None:
        if not 1 <= limit <= 10000:
            raise ValueError("Invalid row limit")
        sql += " LIMIT ?"; args.append(limit)
    c = connect()
    try:
        return [dict(row) for row in c.execute(sql, args)]
    finally:
        c.close()


def _xml_text(value):
    text = "" if value is None else str(value)
    text = "".join(ch for ch in text if ch in "\t\n\r" or 0x20 <= ord(ch) <= 0xD7FF
                   or 0xE000 <= ord(ch) <= 0xFFFD or 0x10000 <= ord(ch) <= 0x10FFFF)
    return escape(text[:32767])


def xlsx_bytes(rows):
    headers = ["Дата/время UTC", "Тип события", "Логин", "Источник", "Решение",
               "Код", "Длительность, мс", "ID запроса", "Текст запроса", "Проверка модели", "Флаги модели", "Вердикт модели (история)"]
    ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '''<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>''')
        z.writestr("_rels/.rels", '''<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>''')
        z.writestr("xl/workbook.xml", f'<workbook xmlns="{ns}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Журнал" sheetId="1" r:id="rId1"/></sheets></workbook>')
        z.writestr("xl/_rels/workbook.xml.rels", '''<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>''')
        with z.open("xl/worksheets/sheet1.xml", "w") as sheet:
            sheet.write(f'<worksheet xmlns="{ns}"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" state="frozen"/></sheetView></sheetViews><sheetData>'.encode())
            def write_row(number, values):
                cells = ''.join(f'<c r="{chr(65+i)}{number}" t="inlineStr"><is><t xml:space="preserve">{_xml_text(v)}</t></is></c>' for i,v in enumerate(values))
                sheet.write(f'<row r="{number}">{cells}</row>'.encode('utf-8'))
            write_row(1, headers)
            for number, row in enumerate(rows, 2):
                timestamp = datetime.fromtimestamp(row['ts'], timezone.utc).isoformat(timespec='seconds')
                write_row(number, [timestamp, row['event_type'], row['username'], row['origin'],
                                   row['decision'], row['code'], row['ms'], row['request_id'], row['query_text'], row.get('model_status') or ('legacy' if row.get('model_decision') or row.get('model_flags') else 'not_checked'), row.get('model_flags'), row.get('model_decision')])
            sheet.write(f'</sheetData><autoFilter ref="A1:L{len(rows)+1}"/></worksheet>'.encode())
    return output.getvalue()

