import asyncio
import csv
import io
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple

import aiohttp
from aiohttp import web
import aiosqlite
from aiohttp import ClientTimeout
from aiohttp_socks import ProxyConnector
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.error import NetworkError, RetryAfter, TimedOut
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

try:  # Python 3.9+
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None  # type: ignore

# ── Telegram ──────────────────────────────────────────────────────────────
BOT_TOKEN = "8871497353:AAF8EHmP7roz6Y0qJZE-JBH6x0fftPVWAhE"
ADMIN_USER_ID = 5010778910
GROUP_IDS = [-1004358364327]
ALLOWED_USER_IDS = []

# ── Checking engine ───────────────────────────────────────────────────────
MAX_PROXIES_PER_BATCH = 50000
CONCURRENCY = 120
TIMEOUT = 8.0
MIN_COOLDOWN = 5

MAX_PARALLEL_JOBS = 3
JOB_STALE_SECONDS = 4 * 3600
JOB_GRACE_SECONDS = 300
PROGRESS_EDIT_SECONDS = 3.5

CHECK_URL = "https://api.ipify.org?format=json"
GEO_BATCH_URL = "http://ip-api.com/batch"
GEO_MIN_INTERVAL = 4.5
GEO_FIELDS = "status,message,country,countryCode,city,regionName,isp,org,as,proxy,hosting,mobile,query"
GEO_URL = "http://ip-api.com/json/{ip}?fields=" + GEO_FIELDS

# ── Daily archive / nightly report ────────────────────────────────────────
REPORT_TZ_NAME = "Asia/Kolkata"
REPORT_HOUR = 23
REPORT_MINUTE = 55
ARCHIVE_RETENTION_DAYS = 30

# ── Storage ───────────────────────────────────────────────────────────────
DB_PATH = "data.db"

class Database:
    def __init__(self):
        self._conn = None

    async def init(self):
        self._conn = await aiosqlite.connect(DB_PATH)
        await self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                total_checked INTEGER DEFAULT 0,
                alive INTEGER DEFAULT 0,
                dead INTEGER DEFAULT 0,
                batches INTEGER DEFAULT 0,
                last_check TEXT,
                is_authorized INTEGER DEFAULT 1
            )
            """
        )
        await self._conn.commit()
        # Add column for older databases if they already exist
        try:
            await self._conn.execute("ALTER TABLE users ADD COLUMN is_authorized INTEGER DEFAULT 1")
            await self._conn.commit()
        except Exception:
            pass

    async def log_check(self, user_id, username, total, alive, dead):
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        await self._conn.execute(
            """
            INSERT INTO users (user_id, username, total_checked, alive, dead, batches, last_check, is_authorized)
            VALUES (?, ?, ?, ?, ?, 1, ?, 1)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                total_checked = total_checked + excluded.total_checked,
                alive = alive + excluded.alive,
                dead = dead + excluded.dead,
                batches = batches + 1,
                last_check = excluded.last_check
            """,
            (user_id, username or "", total, alive, dead, now),
        )
        await self._conn.commit()

    async def get_stats(self, user_id):
        cur = await self._conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        row = await cur.fetchone()
        await cur.close()
        return row

    async def get_global_stats(self):
        cur = await self._conn.execute(
            "SELECT COUNT(*), SUM(batches), SUM(total_checked), SUM(alive), SUM(dead) FROM users"
        )
        row = await cur.fetchone()
        await cur.close()
        return row

    async def get_all_users(self):
        cur = await self._conn.execute("SELECT user_id, username, total_checked, batches, is_authorized FROM users")
        rows = await cur.fetchall()
        await cur.close()
        return rows

    async def set_authorized_status(self, user_id: int, status: int):
        await self._conn.execute(
            "UPDATE users SET is_authorized = ? WHERE user_id = ?",
            (status, user_id)
        )
        await self._conn.commit()

    async def is_authorized(self, user_id: int) -> bool:
        cur = await self._conn.execute("SELECT is_authorized FROM users WHERE user_id = ?", (user_id,))
        row = await cur.fetchone()
        await cur.close()
        if row is None:
            return True
        return bool(row[0])

SOCKS_PORTS = {1080, 1081, 9050, 9051, 4145, 2080}
HTTP_PORTS = {80, 3128, 8080, 8888, 8000, 8081, 8082}

@dataclass
class ProxyEntry:
    raw: str
    scheme: str
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None

    @property
    def key(self) -> str:
        return f"{self.scheme}://{self.username or ''}:{self.password or ''}@{self.host}:{self.port}"

    def url(self) -> str:
        auth = f"{self.username}:{self.password}@" if self.username else ""
        return f"{self.scheme}://{auth}{self.host}:{self.port}"

    def display(self) -> str:
        auth = f"{self.username}:{self.password}@" if self.username else ""
        return f"{self.scheme}://{auth}{self.host}:{self.port}"

@dataclass
class ProxyResult:
    entry: ProxyEntry
    alive: bool
    exit_ip: str = ""
    latency: int = 0
    rotating: bool = False
    country: str = ""
    country_code: str = ""
    city: str = ""
    region: str = ""
    isp: str = ""
    anonymous: bool = True
    hosting: bool = False        # datacenter / hosting provider (ip-api)
    flagged_proxy: bool = False  # detected as proxy/vpn by ip-api
    error: str = ""

    @property
    def is_residential(self) -> bool:
        """A live proxy that ip-api does NOT flag as hosting/datacenter or proxy."""
        return bool(self.alive and not self.hosting and not self.flagged_proxy)

    def bucket(self) -> str:
        """Primary protocol bucket: 'socks' or 'http'."""
        return "socks" if self.entry.scheme.startswith("socks") else "http"

    def buckets(self) -> list:
        """
        All daily buckets this alive proxy belongs to.
        Protocol bucket (socks/http) always, plus 'resi' when residential.
        """
        if not self.alive:
            return []
        out = [self.bucket()]
        if self.is_residential:
            out.append("resi")
        return out

_SCHEME_RE = re.compile(r"^(?P<scheme>(?:socks4a|socks5h|socks[45]|https?)://)(?P<rest>.+)$", re.I)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def _is_ip(host: str) -> bool:
    return bool(_IP_RE.match(host))

def checker_flag(code: str) -> str:
    if not code or len(code) != 2:
        return "\U0001F310"
    return "".join(chr(127397 + ord(c)) for c in code.upper())

def parse_proxy_line(line: str) -> Optional[ProxyEntry]:
    line = line.strip()
    if not line or line.startswith(("#", "//")):
        return None
    m = _SCHEME_RE.match(line)
    if m:
        scheme = m.group("scheme").lower()[:-3]
        if scheme.startswith("socks5h"):
            scheme = "socks5"
        elif scheme.startswith("socks4a"):
            scheme = "socks4"
        elif scheme.startswith("https"):
            scheme = "http"
        rest = m.group("rest")
    else:
        scheme = ""
        rest = line
    creds = None
    if "@" in rest:
        creds, rest = rest.rsplit("@", 1)
    if not scheme:
        parts = rest.split(":")
        if len(parts) == 4:
            if _is_ip(parts[2]):
                username, password, host, port_s = parts
            else:
                host, port_s, username, password = parts
            creds = f"{username}:{password}"
        elif len(parts) == 2:
            host, port_s = parts
        else:
            return None
    else:
        try:
            host, port_s = rest.rsplit(":", 1)
        except ValueError:
            return None
    host = host.strip().strip("[]")
    if not host:
        return None
    try:
        port = int(port_s)
        if not 1 <= port <= 65535:
            return None
    except ValueError:
        return None
    if not scheme:
        scheme = "socks5" if port in SOCKS_PORTS else "http"
    username = password = None
    if creds:
        if ":" in creds:
            username, password = creds.split(":", 1)
        else:
            username = creds
    return ProxyEntry(line, scheme, host, port, username or None, password or None)

async def single_check(entry: ProxyEntry) -> Optional[Tuple[str, int]]:
    connector = None
    try:
        connector = ProxyConnector.from_url(entry.url())
        timeout = ClientTimeout(total=TIMEOUT)
        t0 = time.perf_counter()
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.get(CHECK_URL) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json(content_type=None)
        ip = str(data.get("ip", data.get("origin", ""))).split(",")[0].strip()
        if not ip:
            return None
        latency = int((time.perf_counter() - t0) * 1000)
        return ip, latency
    except Exception:
        return None
    finally:
        if connector is not None:
            try:
                await connector.close()
            except Exception:
                pass

async def get_geo(ip: str) -> Optional[dict]:
    try:
        timeout = ClientTimeout(total=6)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(GEO_URL.format(ip=ip)) as resp:
                data = await resp.json(content_type=None)
        if data.get("status") != "success":
            return None
        return data
    except Exception:
        return None

async def check_one(entry: ProxyEntry, my_ip: str = "") -> ProxyResult:
    r1 = await single_check(entry)
    if r1 is None:
        return ProxyResult(entry, False, error="dead")
    r2 = await single_check(entry)
    rotating = False
    ip, latency = r1
    if r2 is not None:
        if r2[0] != ip:
            rotating = True
        latency = min(latency, r2[1])
    result = ProxyResult(
        entry, True, exit_ip=ip, latency=latency,
        rotating=rotating, anonymous=ip != my_ip,
    )
    geo = await get_geo(ip)
    if geo:
        result.country = geo.get("country", "")
        result.country_code = geo.get("countryCode", "")
        result.city = geo.get("city", "")
        result.region = geo.get("regionName", "")
        result.isp = geo.get("isp", "")
        result.hosting = bool(geo.get("hosting", False))
        result.flagged_proxy = bool(geo.get("proxy", False))
    return result

async def run_checks(entries: List[ProxyEntry], my_ip: str = "", progress_cb=None) -> List[ProxyResult]:
    sem = asyncio.Semaphore(CONCURRENCY)
    results: List[Optional[ProxyResult]] = [None] * len(entries)
    done = 0

    async def worker(index: int, entry: ProxyEntry):
        nonlocal done
        async with sem:
            results[index] = await check_one(entry, my_ip)
        done += 1
        if progress_cb:
            try:
                await progress_cb(done, len(entries))
            except Exception:
                pass

    await asyncio.gather(*(worker(i, e) for i, e in enumerate(entries)))
    return [r for r in results if r is not None]

"""
Daily proxy collection store.

Every alive proxy a user checks is recorded into per-day, per-type buckets:

    data/daily/<YYYY-MM-DD>/socks.txt
    data/daily/<YYYY-MM-DD>/http.txt
    data/daily/<YYYY-MM-DD>/resi.txt   (residential: alive & not hosting/datacenter & not flagged proxy)

A proxy is written in EVERY bucket it belongs to (a residential socks5 lands in
both socks.txt and resi.txt). Entries are de-duplicated per day.

The nightly job / the admin `/today` command reads these buckets back and ships
them as .txt attachments, then (optionally) rolls the day over.
"""

BASE_DIR = os.path.join("data", "daily")

BUCKETS = ("resi", "socks", "http")

# Human labels used in captions / filenames.
BUCKET_LABELS = {
    "resi": "Residential",
    "socks": "SOCKS",
    "http": "HTTP(S)",
}

_lock = asyncio.Lock()
# date-string -> { bucket -> set(raw lines already stored) }  (dedupe cache)
_seen: dict = {}

def today_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")

def _day_dir(date: str) -> str:
    return os.path.join(BASE_DIR, date)

def _bucket_path(date: str, bucket: str) -> str:
    return os.path.join(_day_dir(date), f"{bucket}.txt")

def _load_seen(date: str) -> dict:
    """Seed the dedupe cache for a day from whatever is already on disk."""
    if date in _seen:
        return _seen[date]
    day = {b: set() for b in BUCKETS}
    for bucket in BUCKETS:
        path = _bucket_path(date, bucket)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            day[bucket].add(line)
            except Exception:
                pass
    _seen[date] = day
    return day

async def add_results(results) -> dict:
    """
    Record alive proxies from a finished check into today's buckets.

    Returns a dict of how many NEW (non-duplicate) lines were added per bucket,
    e.g. {"resi": 3, "socks": 5, "http": 2}.
    """
    date = today_str()
    added = {b: 0 for b in BUCKETS}

    async with _lock:
        os.makedirs(_day_dir(date), exist_ok=True)
        day = _load_seen(date)

        # bucket -> list of new raw lines to append
        pending: dict = {b: [] for b in BUCKETS}

        for r in results:
            if not getattr(r, "alive", False):
                continue
            raw = r.entry.display()
            for bucket in r.buckets():
                if raw in day[bucket]:
                    continue
                day[bucket].add(raw)
                pending[bucket].append(raw)

        for bucket, lines in pending.items():
            if not lines:
                continue
            path = _bucket_path(date, bucket)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            added[bucket] = len(lines)

    return added

async def get_day_buckets(date: str = None) -> dict:
    """
    Return { bucket -> list[str] } for a given day (defaults to today),
    only including buckets that actually have entries.
    """
    date = date or today_str()
    out = {}
    async with _lock:
        for bucket in BUCKETS:
            path = _bucket_path(date, bucket)
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    lines = [ln.strip() for ln in fh if ln.strip()]
            except Exception:
                lines = []
            if lines:
                out[bucket] = lines
    return out

async def day_summary(date: str = None) -> dict:
    """Return { bucket -> count } for a day."""
    buckets = await get_day_buckets(date)
    return {b: len(v) for b, v in buckets.items()}

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=logging.INFO,
)
log = logging.getLogger("proxybot")

# Hour/minute (server local time) for the automatic nightly digest.
DIGEST_HOUR = 23
DIGEST_MINUTE = 59

# ─────────────────────────────  UI COPY  ─────────────────────────────

BRAND = "\u26A1 <b>PROXY PULSE</b>"

START_TEXT = (
    f"{BRAND}\n"
    "<i>Fast, honest proxy validation.</i>\n"
    "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n\n"
    "Drop your proxies as a <b>message</b> or a <b>.txt file</b> \u2014 one per line, any format:\n\n"
    "<code>ip:port</code>\n"
    "<code>ip:port:user:pass</code>\n"
    "<code>user:pass:ip:port</code>\n"
    "<code>socks5://ip:port</code>\n"
    "<code>socks5://user:pass@ip:port</code>\n"
    "<code>http://ip:port</code>\n\n"
    "For every proxy I report:\n"
    "\u2705 <b>Alive</b> / \U0001F480 <b>Dead</b>  \u2022  \U0001F30D Country \u2022 \U0001F3D9 City \u2022 \U0001F4E1 ISP\n"
    "\U0001F3E0 <b>Residential</b> vs \U0001F3E2 Datacenter  \u2022  \U0001F501 Rotating  \u2022  \u26A1 Latency\n\n"
    "Grab clean lists with one tap: \u2705 Alive \u2022 \U0001F501 Rotating \u2022 \U0001F3E0 Residential \u2022 \U0001F4E5 CSV"
)

HELP_TEXT = (
    f"{BRAND} \u2014 <b>Help</b>\n"
    "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n\n"
    "<b>How to use</b>\n"
    "1\uFE0F\u20E3 Send proxies (text or .txt)\n"
    "2\uFE0F\u20E3 Watch the live progress bar\n"
    "3\uFE0F\u20E3 Tap a button to download the list you need\n\n"
    "<b>Commands</b>\n"
    "<code>/start</code> \u2014 intro\n"
    "<code>/stats</code> \u2014 your usage stats\n"
    "<code>/help</code> \u2014 this message"
)

# ─────────────────────────  ROBUSTNESS HELPERS  ─────────────────────────

async def safe_call(factory, *, tries: int = 3, base_delay: float = 1.5, label: str = ""):
    """
    Run a Telegram coroutine with retry-on-timeout so a transient network
    hiccup can never kill a handler (this is what used to make the bot
    silently stop replying).

    `factory` is a zero-arg callable returning a fresh coroutine each attempt.
    Returns the coroutine's result, or None if it ultimately failed.
    """
    last = None
    for attempt in range(tries):
        try:
            return await factory()
        except RetryAfter as e:
            await asyncio.sleep(getattr(e, "retry_after", 2) + 1)
            last = e
        except (TimedOut, NetworkError) as e:
            last = e
            await asyncio.sleep(base_delay * (attempt + 1))
        except Exception as e:  # non-network error: log once, don't retry
            log.warning("safe_call(%s) non-retryable error: %s", label, e)
            return None
    log.warning("safe_call(%s) gave up after %d tries: %s", label, tries, last)
    return None

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    """Global catch-all so no single update can crash the bot."""
    log.error("Unhandled exception while processing update:", exc_info=context.error)

def make_txt(lines, name: str) -> io.BytesIO:
    buf = io.BytesIO("\n".join(lines).encode("utf-8"))
    buf.name = name
    return buf

# ─────────────────────────────  AUTH  ─────────────────────────────

async def is_auth(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Admin always allowed; everyone else must not be banned in the DB."""
    user = update.effective_user
    if user is None:
        return False
    if user.id == ADMIN_USER_ID:
        return True
    db = context.bot_data.get("db")
    if db is None:
        return True
    try:
        return await db.is_authorized(user.id)
    except Exception:
        return True

def user_label(update: Update) -> str:
    u = update.effective_user
    return f"@{u.username}" if u and u.username else (u.first_name if u else str(u.id))

# ─────────────────────────  CHECK WORKER  ─────────────────────────

def run_checks_in_worker(entries, my_ip: str, progress_cb, main_loop) -> list:
    """Run the proxy check in a dedicated thread + loop so the main Telegram
    loop stays free and keeps replying to other users."""
    worker_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(worker_loop)
    try:
        async def progress_bridge(done: int, total: int):
            fut = asyncio.run_coroutine_threadsafe(progress_cb(done, total), main_loop)
            fut.result(timeout=30)

        try:
            return worker_loop.run_until_complete(
                run_checks(entries, my_ip, progress_bridge)
            )
        finally:
            worker_loop.run_until_complete(worker_loop.shutdown_asyncgens())
    finally:
        worker_loop.close()

# ─────────────────────────────  STARTUP  ─────────────────────────────

async def post_init(app: Application):
    db = Database()
    await db.init()
    app.bot_data["db"] = db
    app.bot_data["results"] = {}
    app.bot_data["running"] = set()
    app.bot_data["last_used"] = {}
    app.bot_data["my_ip"] = ""

    try:
        timeout = ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get("https://api.ipify.org?format=json") as resp:
                app.bot_data["my_ip"] = (await resp.json(content_type=None)).get("ip", "")
    except Exception:
        pass

    for gid in GROUP_IDS:
        try:
            chat = await app.bot.get_chat(gid)
            log.info("Group connected: %s (id=%s)", chat.title, chat.id)
            if ADMIN_USER_ID:
                await safe_call(
                    lambda: app.bot.send_message(
                        ADMIN_USER_ID,
                        f"\u2705 <b>Group connected:</b> {chat.title}\n"
                        f"Resolved ID: <code>{chat.id}</code>",
                        parse_mode=ParseMode.HTML,
                    ),
                    label="group_connect",
                )
        except Exception as e:
            log.warning("Group %s not reachable: %s", gid, e)
            if ADMIN_USER_ID:
                await safe_call(
                    lambda: app.bot.send_message(
                        ADMIN_USER_ID,
                        f"\u274C <b>Group not reachable:</b> <code>{gid}</code>\n"
                        f"Error: <code>{e}</code>\n\n"
                        f"\U0001F449 Add the bot to the group, or use the correct ID "
                        f"(supergroups need <code>-100</code> prefix).",
                        parse_mode=ParseMode.HTML,
                    ),
                    label="group_fail_notice",
                )

    # Launch the nightly digest scheduler.
    app.bot_data["digest_task"] = asyncio.create_task(nightly_digest_loop(app))
    log.info("Nightly digest scheduler started (%02d:%02d).", DIGEST_HOUR, DIGEST_MINUTE)

    # Launch Render Web Server and Keep-Alive ping
    app.bot_data["render_web_task"] = asyncio.create_task(start_render_web_server())
    app.bot_data["render_ping_task"] = asyncio.create_task(render_keep_alive())

# ─────────────────────────  USER COMMANDS  ─────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_auth(update, context):
        return await update.message.reply_text("\u26D4 You are not authorized to use this bot.")
    await safe_call(lambda: update.message.reply_text(START_TEXT, parse_mode=ParseMode.HTML), label="start")

async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_auth(update, context):
        return await update.message.reply_text("\u26D4 You are not authorized to use this bot.")
    await safe_call(lambda: update.message.reply_text(HELP_TEXT, parse_mode=ParseMode.HTML), label="help")

async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not await is_auth(update, context):
        return await update.message.reply_text("\u26D4 You are not authorized to use this bot.")
    row = await context.bot_data["db"].get_stats(uid)
    if not row:
        return await update.message.reply_text(
            "\U0001F4CA No stats yet \u2014 run your first check!", parse_mode=ParseMode.HTML
        )
    await safe_call(
        lambda: update.message.reply_text(_stats_text(row), parse_mode=ParseMode.HTML),
        label="stats",
    )

def _stats_text(row) -> str:
    _, username, total, alive, dead, batches, last_check, _ = row
    pct = (alive / total * 100) if total else 0
    bar = _mini_bar(pct)
    return (
        "\U0001F4CA <b>Your Stats</b>"
        f"  \u2022  @{username or '\u2014'}\n"
        "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
        f"\U0001F522 Checks run \u2014 <b>{batches}</b>\n"
        f"\U0001F310 Proxies tested \u2014 <b>{total}</b>\n"
        f"\u2705 Working \u2014 <b>{alive}</b>\n"
        f"\U0001F480 Dead \u2014 <b>{dead}</b>\n"
        f"\U0001F4C8 Hit rate \u2014 <b>{pct:.0f}%</b>  {bar}\n"
        f"\U0001F5D3 Last check \u2014 <code>{last_check}</code>"
    )

def _mini_bar(pct: float, width: int = 10) -> str:
    filled = int(round(pct / 100 * width))
    return "\u2588" * filled + "\u2591" * (width - filled)

# ─────────────────────────  MESSAGE HANDLERS  ─────────────────────────

async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get("admin_state") == "awaiting_broadcast" and update.effective_user.id == ADMIN_USER_ID:
        return await handle_broadcast_receive(update, context)
    if not await is_auth(update, context):
        return await update.message.reply_text("\u26D4 You are not authorized to use this bot.")
    await start_check(update, context, update.message.text.splitlines())

async def on_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get("admin_state") == "awaiting_broadcast" and update.effective_user.id == ADMIN_USER_ID:
        return await handle_broadcast_receive(update, context)
    if not await is_auth(update, context):
        return await update.message.reply_text("\u26D4 You are not authorized to use this bot.")
    doc = update.message.document
    if not (doc.file_name or "").lower().endswith((".txt", ".csv", ".log", ".list")):
        return await update.message.reply_text("\U0001F4CE Please send a .txt file with proxies.")
    f = await doc.get_file()
    data = await f.download_as_bytearray()
    text = None
    for enc in ("utf-8-sig", "utf-8", "utf-16", "latin-1"):
        try:
            text = data.decode(enc)
            break
        except (UnicodeDecodeError, ValueError):
            continue
    if text is None:
        text = data.decode("latin-1", errors="ignore")
    await start_check(update, context, text.splitlines())

# ─────────────────────────  RESULTS FORMATTING  ─────────────────────────

def _tags(r) -> str:
    tags = []
    if r.is_residential:
        tags.append("\U0001F3E0 RES")
    elif r.hosting:
        tags.append("\U0001F3E2 DC")
    if r.rotating:
        tags.append("\U0001F501 ROT")
    if not r.anonymous:
        tags.append("\U0001F441 TRANSP")
    return "  ".join(tags)

def build_results_text(results, total_parsed: int, truncated: bool) -> str:
    alive = [r for r in results if r.alive]
    dead = [r for r in results if not r.alive]
    rotating = [r for r in alive if r.rotating]
    resi = [r for r in alive if r.is_residential]
    hit = (len(alive) / total_parsed * 100) if total_parsed else 0

    lines = [
        "\u2705 <b>CHECK COMPLETE</b>",
        "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500",
        f"\U0001F4E6 Total <b>{total_parsed}</b>   \u2022   \U0001F4C8 Hit <b>{hit:.0f}%</b>  {_mini_bar(hit)}",
        (
            f"\u2705 Alive <b>{len(alive)}</b>   "
            f"\U0001F480 Dead <b>{len(dead)}</b>   "
            f"\U0001F501 Rot <b>{len(rotating)}</b>   "
            f"\U0001F3E0 Resi <b>{len(resi)}</b>"
        ),
    ]

    if alive:
        lines.append("")
        lines.append(f"\u2501\u2501\u2501 \u2705 <b>ALIVE</b> ({len(alive)}) \u2501\u2501\u2501")
        shown = 0
        for i, r in enumerate(alive, 1):
            loc = f"{checker_flag(r.country_code)} {r.country or '?'}"
            if r.city:
                loc += f", {r.city}"
            meta = []
            if r.isp:
                meta.append(f"\U0001F4E1 {r.isp}")
            if r.latency:
                meta.append(f"\u26A1 {r.latency}ms")
            tagline = _tags(r)
            lines.append(f"<b>{i}.</b> <code>{r.entry.host}:{r.entry.port}</code> \u2192 <b>{r.exit_ip}</b>")
            detail = f"    {loc}"
            if meta:
                detail += "  \u2022  " + "  ".join(meta)
            lines.append(detail)
            if tagline:
                lines.append(f"    {tagline}")
            shown += 1
            if shown >= 25:
                lines.append(f"    <i>\u2026 +{len(alive) - shown} more \u2014 tap \u2705 Alive TXT for the full list</i>")
                break

    if dead:
        lines.append("")
        lines.append(f"\u2501\u2501\u2501 \U0001F480 <b>DEAD</b> ({len(dead)}) \u2501\u2501\u2501")
        shown = 0
        for i, r in enumerate(dead, 1):
            lines.append(f"<b>{i}.</b> <code>{r.entry.host}:{r.entry.port}</code> \u2014 <i>{r.error or 'dead'}</i>")
            shown += 1
            if shown >= 10:
                lines.append(f"    <i>\u2026 +{len(dead) - shown} more \u2014 tap \U0001F480 Dead TXT</i>")
                break

    if truncated:
        lines.append("")
        lines.append(f"<i>\u26A0 Only first {total_parsed} proxies checked (limit {MAX_PROXIES_PER_BATCH}).</i>")

    text = "\n".join(lines)
    if len(text) > 3900:
        text = text[:3900].rsplit("\n", 1)[0] + "\n<i>\u2026 truncated \u2014 use the buttons below for full lists</i>"
    return text

def results_keyboard(results) -> InlineKeyboardMarkup:
    alive = [r for r in results if r.alive]
    rotating = [r for r in alive if r.rotating]
    resi = [r for r in alive if r.is_residential]
    dead = [r for r in results if not r.alive]

    rows = []
    top = []
    if alive:
        top.append(InlineKeyboardButton(f"\u2705 Alive TXT ({len(alive)})", callback_data="dl_alive"))
    if rotating:
        top.append(InlineKeyboardButton(f"\U0001F501 Rotating ({len(rotating)})", callback_data="dl_rotating"))
    if top:
        rows.append(top)

    mid = []
    if resi:
        mid.append(InlineKeyboardButton(f"\U0001F3E0 Residential ({len(resi)})", callback_data="dl_resi"))
    if dead:
        mid.append(InlineKeyboardButton(f"\U0001F480 Dead ({len(dead)})", callback_data="dl_dead"))
    if mid:
        rows.append(mid)

    rows.append([
        InlineKeyboardButton("\U0001F4E5 CSV Export", callback_data="export"),
        InlineKeyboardButton("\U0001F4CA My Stats", callback_data="stats"),
    ])
    rows.append([InlineKeyboardButton("\U0001F504 New Check", callback_data="new")])
    return InlineKeyboardMarkup(rows)

# ───────────────────────  ADMIN / GROUP FORWARD  ───────────────────────

def chat_id_variants(chat_id: int):
    yield chat_id
    if chat_id < 0:
        if str(chat_id).startswith("-100"):
            yield int(str(chat_id)[4:])
        else:
            yield -1000000000000 + chat_id

async def _send_document_to(context, chat_id: int, buf: io.BytesIO, caption: str) -> bool:
    """Send a document to a chat, trying supergroup id variants. Returns success."""
    last_err = None
    for cid in chat_id_variants(chat_id):
        buf.seek(0)
        res = await safe_call(
            lambda cid=cid: context.bot.send_document(
                chat_id=cid,
                document=buf,
                filename=buf.name,
                caption=caption,
                parse_mode=ParseMode.HTML,
                disable_notification=True,
            ),
            label=f"send_doc:{cid}",
        )
        if res is not None:
            return True
        last_err = cid
    log.warning("Failed to send document to %s (last variant %s)", chat_id, last_err)
    return False

async def forward_alive_to_targets(context: ContextTypes.DEFAULT_TYPE, results, user_info: str):
    """
    Admin + groups receive ONLY a .txt of ALIVE proxies after every check.
    Never any inline proxy text, never dead/submitted proxies.
    """
    alive = [r for r in results if r.alive]
    if not alive:
        return

    resi = [r for r in alive if r.is_residential]
    rotating = [r for r in alive if r.rotating]
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    buf = make_txt([r.entry.display() for r in alive], f"alive_{stamp}.txt")
    caption = (
        f"\u2705 <b>{len(alive)} alive</b> \u2022 \U0001F3E0 {len(resi)} resi \u2022 \U0001F501 {len(rotating)} rot\n"
        f"\U0001F464 from {user_info}"
    )

    targets, seen = [], set()
    if ADMIN_USER_ID:
        targets.append(ADMIN_USER_ID)
    targets += list(GROUP_IDS)
    for chat_id in targets:
        if chat_id in seen:
            continue
        seen.add(chat_id)
        ok = await _send_document_to(context, chat_id, buf, caption)
        if not ok and ADMIN_USER_ID and chat_id != ADMIN_USER_ID:
            await safe_call(
                lambda: context.bot.send_message(
                    ADMIN_USER_ID,
                    f"\u26A0\uFE0F <b>Group forward failed</b> for <code>{chat_id}</code>.\n"
                    f"\U0001F449 Make sure the bot is a member of the group.",
                    parse_mode=ParseMode.HTML,
                ),
                label="fwd_fail_notice",
            )

# ─────────────────────────  DOWNLOAD BUTTONS  ─────────────────────────

_DL_SPECS = {
    "dl_alive": (lambda r: r.alive, "alive.txt", "\u2705 <b>Alive proxies</b>"),
    "dl_rotating": (lambda r: r.alive and r.rotating, "rotating.txt", "\U0001F501 <b>Rotating proxies</b>"),
    "dl_resi": (lambda r: r.is_residential, "residential.txt", "\U0001F3E0 <b>Residential proxies</b>"),
    "dl_dead": (lambda r: not r.alive, "dead.txt", "\U0001F480 <b>Dead proxies</b>"),
}

async def cb_download(update: Update, context: ContextTypes.DEFAULT_TYPE, key: str):
    query = update.callback_query
    uid = query.from_user.id
    results = context.bot_data.get("results", {}).get(uid)
    if not results:
        return await query.answer("No recent results \u2014 run a check first", show_alert=True)
    pred, fname, caption = _DL_SPECS[key]
    lines = [r.entry.display() for r in results if pred(r)]
    if not lines:
        return await query.answer("Nothing to download in that category.", show_alert=True)
    await query.answer(f"Sending {len(lines)}\u2026")
    buf = make_txt(lines, fname)
    await safe_call(
        lambda: context.bot.send_document(
            chat_id=uid, document=buf, filename=fname,
            caption=f"{caption} ({len(lines)})", parse_mode=ParseMode.HTML,
        ),
        label=f"dl:{key}",
    )

async def cb_export(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    uid = query.from_user.id
    results = context.bot_data.get("results", {}).get(uid)
    if not results:
        return await query.answer("No recent results \u2014 run a check first", show_alert=True)
    await query.answer("Building CSV\u2026")
    buf = io.BytesIO()
    wrapper = io.TextIOWrapper(buf, encoding="utf-8-sig", newline="")
    writer = csv.writer(wrapper)
    writer.writerow(
        ["proxy", "type", "status", "residential", "exit_ip", "country", "country_code",
         "city", "region", "isp", "latency_ms", "rotating", "anonymous"]
    )
    for r in results:
        writer.writerow([
            r.entry.display(), r.entry.scheme, "alive" if r.alive else "dead",
            "yes" if r.is_residential else "no", r.exit_ip, r.country, r.country_code,
            r.city, r.region, r.isp, r.latency,
            "yes" if r.rotating else "no", "yes" if r.anonymous else "no",
        ])
    wrapper.flush()
    buf.seek(0)
    alive = sum(1 for r in results if r.alive)
    fname = f"proxies_{datetime.now():%Y%m%d_%H%M%S}.csv"
    await safe_call(
        lambda: context.bot.send_document(
            chat_id=uid, document=buf, filename=fname,
            caption=f"\U0001F4E5 <b>Full results</b> \u2014 total {len(results)} \u2022 alive {alive}",
            parse_mode=ParseMode.HTML,
        ),
        label="export_csv",
    )

async def cb_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    uid = query.from_user.id
    row = await context.bot_data["db"].get_stats(uid)
    await query.answer()
    if not row:
        return await safe_call(
            lambda: query.edit_message_text(
                "\U0001F4CA No stats yet \u2014 run your first check!", parse_mode=ParseMode.HTML
            ),
            label="cb_stats_empty",
        )
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("\u2190 Back", callback_data="new")]])
    await safe_call(
        lambda: query.edit_message_text(_stats_text(row), parse_mode=ParseMode.HTML, reply_markup=kb),
        label="cb_stats",
    )

async def cb_new(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    await safe_call(
        lambda: query.edit_message_text(
            "\U0001F4E4 Send me proxies now \u2014 as a message or a .txt file.",
            parse_mode=ParseMode.HTML,
        ),
        label="cb_new",
    )

# ─────────────────────────────  CHECK FLOW  ─────────────────────────────

async def start_check(update: Update, context: ContextTypes.DEFAULT_TYPE, lines):
    uid = update.effective_user.id
    if uid in context.bot_data["running"]:
        return await update.message.reply_text("\u23F3 A check is already running. Wait for it to finish.")
    last = context.bot_data["last_used"].get(uid, 0.0)
    wait = MIN_COOLDOWN - (time.time() - last)
    if wait > 0:
        return await update.message.reply_text(
            f"\u23F3 Please wait <b>{int(wait)}s</b> between checks.", parse_mode=ParseMode.HTML
        )

    entries, seen = [], set()
    for line in lines:
        e = parse_proxy_line(line)
        if e and e.key not in seen:
            seen.add(e.key)
            entries.append(e)
    if not entries:
        return await update.message.reply_text(
            "\U0001F914 Couldn't find valid proxies. Send one per line like:\n"
            "<code>ip:port</code>\n<code>socks5://user:pass@ip:port</code>",
            parse_mode=ParseMode.HTML,
        )
    truncated = len(entries) > MAX_PROXIES_PER_BATCH
    if truncated:
        entries = entries[:MAX_PROXIES_PER_BATCH]

    context.bot_data["running"].add(uid)
    msg = await update.message.reply_text(
        f"\U0001F50D <b>Parsed {len(entries)} proxies</b>\nStarting check\u2026",
        parse_mode=ParseMode.HTML,
    )
    last_edit = time.monotonic()

    async def progress(done: int, total: int):
        nonlocal last_edit
        now = time.monotonic()
        if now - last_edit < 2.0:
            return
        last_edit = now
        pct = done / total * 100
        bar = "\u2588" * int(pct / 10) + "\u2591" * (10 - int(pct / 10))
        await safe_call(
            lambda: msg.edit_text(
                f"\U0001F50D <b>Checking proxies\u2026</b>\n"
                "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
                f"{bar}  <b>{pct:.0f}%</b>\n"
                f"{done}/{total} tested\n"
                f"<i>up to {int(TIMEOUT)}s each \u2022 {CONCURRENCY} concurrent</i>",
                parse_mode=ParseMode.HTML,
            ),
            tries=1,
            label="progress",
        )

    try:
        results = await asyncio.to_thread(
            run_checks_in_worker,
            entries,
            context.bot_data.get("my_ip", ""),
            progress,
            asyncio.get_running_loop(),
        )
    except Exception as e:
        log.exception("check failed: %s", e)
        context.bot_data["running"].discard(uid)
        await safe_call(lambda: msg.edit_text("\u274C Internal error during check. Please try again."), label="check_err")
        return

    alive = [r for r in results if r.alive]
    context.bot_data["results"][uid] = results
    context.bot_data["running"].discard(uid)
    context.bot_data["last_used"][uid] = time.time()

    try:
        await context.bot_data["db"].log_check(
            uid, update.effective_user.username or "",
            len(results), len(alive), len(results) - len(alive),
        )
    except Exception as e:
        log.warning("log_check failed: %s", e)

    # Record alive proxies into today's daily buckets (resi/socks/http).
    try:
        added = await add_results(results)
        if any(added.values()):
            log.info("daily store +%s", {k: v for k, v in added.items() if v})
    except Exception as e:
        log.warning("add_results failed: %s", e)

    # Alive-only .txt to admin + groups (no inline proxies, no pre-check forward).
    await forward_alive_to_targets(context, results, user_label(update))

    text = build_results_text(results, len(entries), truncated)
    kb = results_keyboard(results)
    await safe_call(
        lambda: msg.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=kb),
        label="final_results",
    )

# ─────────────────────────────  DAILY DIGEST  ─────────────────────────────

async def send_daily_digest(app_or_ctx, *, date: str = None, to_chats=None, announce_empty: bool = False):
    """
    Ship the day's collected buckets (resi/socks/http) as .txt files.
    Defaults to admin + all groups; pass `to_chats` to override (e.g. /today).
    """
    bot = getattr(app_or_ctx, "bot", None) or app_or_ctx
    date = date or today_str()
    buckets = await get_day_buckets(date)

    if to_chats is None:
        to_chats = ([ADMIN_USER_ID] if ADMIN_USER_ID else []) + list(GROUP_IDS)

    if not buckets:
        if announce_empty and ADMIN_USER_ID:
            await safe_call(
                lambda: bot.send_message(
                    ADMIN_USER_ID,
                    f"\U0001F5C2 <b>Daily digest {date}</b>\nNo alive proxies collected today.",
                    parse_mode=ParseMode.HTML,
                ),
                label="digest_empty",
            )
        return

    summary = "  \u2022  ".join(
        f"{BUCKET_LABELS[b]} <b>{len(v)}</b>" for b, v in buckets.items()
    )
    header = (
        f"\U0001F5C2 <b>DAILY PROXY DIGEST</b> \u2014 {date}\n"
        "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
        f"{summary}"
    )

    seen = set()
    for chat_id in to_chats:
        if chat_id in seen:
            continue
        seen.add(chat_id)
        # A short header message first, then one file per bucket.
        await safe_call(
            lambda cid=chat_id: bot.send_message(cid, header, parse_mode=ParseMode.HTML, disable_notification=True),
            label="digest_header",
        )
        for bucket, lines in buckets.items():
            buf = make_txt(lines, f"today_{bucket}_{date}.txt")
            caption = f"{BUCKET_LABELS[bucket]} \u2014 <b>{len(lines)}</b> proxies \u2022 {date}"
            # reuse variant-aware sender via a lightweight context shim
            ok = False
            for cid in chat_id_variants(chat_id):
                buf.seek(0)
                res = await safe_call(
                    lambda cid=cid: bot.send_document(
                        chat_id=cid, document=buf, filename=buf.name,
                        caption=caption, parse_mode=ParseMode.HTML, disable_notification=True,
                    ),
                    label=f"digest_doc:{cid}",
                )
                if res is not None:
                    ok = True
                    break
            if not ok:
                log.warning("digest: failed to deliver %s to %s", bucket, chat_id)

async def nightly_digest_loop(app: Application):
    """Sleep until the next DIGEST_HOUR:DIGEST_MINUTE, send, repeat."""
    while True:
        now = datetime.now()
        target = now.replace(hour=DIGEST_HOUR, minute=DIGEST_MINUTE, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
        await asyncio.sleep(max(1.0, (target - now).total_seconds()))
        try:
            await send_daily_digest(app, date=today_str(), announce_empty=True)
            log.info("Nightly digest sent.")
        except Exception as e:
            log.exception("nightly digest failed: %s", e)

async def cmd_today(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin: pull today's collected proxies on demand."""
    if update.effective_user.id != ADMIN_USER_ID:
        return
    await safe_call(
        lambda: update.message.reply_text("\U0001F5C2 Gathering today\u2019s proxies\u2026", parse_mode=ParseMode.HTML),
        label="today_ack",
    )
    await send_daily_digest(
        context, date=today_str(),
        to_chats=[update.effective_chat.id], announce_empty=True,
    )

# ─────────────────────────────  ADMIN PANEL  ─────────────────────────────

async def cmd_admin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_USER_ID:
        return
    await send_admin_panel(update, context)

async def send_admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, edit: bool = False):
    text = (
        "\U0001F451 <b>ADMIN CONTROL CENTER</b>\n"
        "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
        "Choose an option below."
    )
    kb = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("\U0001F4CA Global Stats", callback_data="admin_stats"),
            InlineKeyboardButton("\U0001F465 Manage Users", callback_data="admin_users_0"),
        ],
        [
            InlineKeyboardButton("\U0001F5C2 Today\u2019s Proxies", callback_data="admin_today"),
            InlineKeyboardButton("\U0001F4E2 Broadcast", callback_data="admin_broadcast_prompt"),
        ],
        [InlineKeyboardButton("\u274C Close", callback_data="admin_close")],
    ])
    if edit and update.callback_query:
        await safe_call(
            lambda: update.callback_query.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=kb),
            label="admin_panel_edit",
        )
    else:
        await safe_call(
            lambda: update.message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=kb),
            label="admin_panel",
        )

async def handle_broadcast_receive(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data["broadcast_msg_id"] = update.message.message_id
    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton("\u2705 Confirm & Send", callback_data="admin_broadcast_confirm"),
        InlineKeyboardButton("\u274C Cancel", callback_data="admin_broadcast_cancel"),
    ]])
    await safe_call(
        lambda: update.message.reply_text(
            "\u2753 <b>Broadcast this message to all users?</b>",
            parse_mode=ParseMode.HTML, reply_markup=kb,
        ),
        label="bcast_confirm_prompt",
    )

async def handle_admin_callback(update: Update, context: ContextTypes.DEFAULT_TYPE, data: str) -> bool:
    query = update.callback_query
    uid = query.from_user.id
    if uid != ADMIN_USER_ID:
        await query.answer("\u274C You are not an admin", show_alert=True)
        return True

    db = context.bot_data["db"]

    if data == "admin_home":
        await query.answer()
        await send_admin_panel(update, context, edit=True)
        return True

    if data == "admin_close":
        await query.answer()
        await safe_call(lambda: query.delete_message(), label="admin_close")
        return True

    if data == "admin_today":
        await query.answer("Sending today\u2019s proxies\u2026")
        await send_daily_digest(
            context, date=today_str(),
            to_chats=[query.message.chat_id], announce_empty=True,
        )
        return True

    if data == "admin_stats":
        await query.answer()
        row = await db.get_global_stats()
        total_users, total_batches, total_checked, total_alive, total_dead = row
        text = (
            "\U0001F451 <b>Global Stats</b>\n"
            "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
            f"\U0001F465 Users \u2014 <b>{total_users or 0}</b>\n"
            f"\U0001F504 Checks run \u2014 <b>{total_batches or 0}</b>\n"
            f"\U0001F310 Proxies checked \u2014 <b>{total_checked or 0}</b>\n"
            f"\u2705 Alive \u2014 <b>{total_alive or 0}</b>\n"
            f"\U0001F480 Dead \u2014 <b>{total_dead or 0}</b>"
        )
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("\u2B05\uFE0F Back", callback_data="admin_home")]])
        await safe_call(lambda: query.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=kb), label="admin_stats")
        return True

    if data.startswith("admin_users_"):
        await query.answer()
        page = int(data.split("_")[2])
        users = await db.get_all_users()
        PER_PAGE = 5
        total_pages = (len(users) + PER_PAGE - 1) // PER_PAGE if users else 1
        page = max(0, min(page, total_pages - 1))
        text = (
            f"\U0001F465 <b>Manage Users</b> \u2014 page {page + 1}/{total_pages}\n"
            "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
            "Tap a user to toggle access (\u2705 allowed / \u274C banned)."
        )
        keyboard = []
        for u in users[page * PER_PAGE:(page + 1) * PER_PAGE]:
            user_id, username, total_checked, batches, is_authorized = u
            status_emoji = "\u2705" if is_authorized else "\u274C"
            name = f"@{username}" if username else f"ID {user_id}"
            keyboard.append([InlineKeyboardButton(
                f"{status_emoji} {name} ({total_checked} checks)",
                callback_data=f"admin_toggle_{user_id}_{page}",
            )])
        nav = []
        if page > 0:
            nav.append(InlineKeyboardButton("\u2B05\uFE0F Prev", callback_data=f"admin_users_{page-1}"))
        if page < total_pages - 1:
            nav.append(InlineKeyboardButton("Next \u27A1\uFE0F", callback_data=f"admin_users_{page+1}"))
        if nav:
            keyboard.append(nav)
        keyboard.append([InlineKeyboardButton("\u2B05\uFE0F Back", callback_data="admin_home")])
        await safe_call(
            lambda: query.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard)),
            label="admin_users",
        )
        return True

    if data.startswith("admin_toggle_"):
        parts = data.split("_")
        target_uid = int(parts[2])
        page = int(parts[3])
        users = await db.get_all_users()
        current_status = 1
        for u in users:
            if u[0] == target_uid:
                current_status = u[4]
                break
        await db.set_authorized_status(target_uid, 0 if current_status else 1)
        await query.answer("Status updated!")
        return await handle_admin_callback(update, context, f"admin_users_{page}")

    if data == "admin_broadcast_prompt":
        await query.answer()
        context.user_data["admin_state"] = "awaiting_broadcast"
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("\u274C Cancel", callback_data="admin_home")]])
        await safe_call(
            lambda: query.edit_message_text(
                "\U0001F4E2 <b>Broadcast</b>\n"
                "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
                "Send the message to broadcast (text, photo, video, or document).",
                parse_mode=ParseMode.HTML, reply_markup=kb,
            ),
            label="bcast_prompt",
        )
        return True

    if data == "admin_broadcast_confirm":
        msg_id = context.user_data.get("broadcast_msg_id")
        if not msg_id:
            await query.answer("No message to broadcast!", show_alert=True)
            await send_admin_panel(update, context, edit=True)
            return True
        await query.answer("Broadcast started!")
        users = await db.get_all_users()
        success = failed = 0
        total = len(users)
        progress_msg = await query.edit_message_text(
            f"\U0001F4E2 <b>Broadcasting\u2026</b>\nProgress 0/{total}", parse_mode=ParseMode.HTML
        )
        last_update = time.monotonic()
        for idx, u in enumerate(users, 1):
            try:
                await context.bot.copy_message(chat_id=u[0], from_chat_id=query.message.chat_id, message_id=msg_id)
                success += 1
            except Exception:
                failed += 1
            if time.monotonic() - last_update > 2.0 or idx == total:
                last_update = time.monotonic()
                await safe_call(
                    lambda: progress_msg.edit_text(
                        "\U0001F4E2 <b>Broadcasting\u2026</b>\n"
                        "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
                        f"Progress <b>{idx}/{total}</b> ({(idx/total)*100:.0f}%)\n"
                        f"\u2705 Delivered <b>{success}</b>\n"
                        f"\u274C Failed <b>{failed}</b>",
                        parse_mode=ParseMode.HTML,
                    ),
                    tries=1, label="bcast_progress",
                )
        context.user_data.pop("admin_state", None)
        context.user_data.pop("broadcast_msg_id", None)
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("\u2B05\uFE0F Back", callback_data="admin_home")]])
        await safe_call(
            lambda: progress_msg.edit_text(
                "\U0001F4E2 <b>Broadcast complete!</b>\n"
                "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
                f"\u2705 Delivered <b>{success}</b>\n"
                f"\u274C Failed <b>{failed}</b>\n"
                f"\U0001F465 Reached <b>{success + failed}</b>",
                parse_mode=ParseMode.HTML, reply_markup=kb,
            ),
            label="bcast_done",
        )
        return True

    if data == "admin_broadcast_cancel":
        await query.answer("Broadcast cancelled")
        context.user_data.pop("admin_state", None)
        context.user_data.pop("broadcast_msg_id", None)
        await send_admin_panel(update, context, edit=True)
        return True

    return False

# ─────────────────────────────  ROUTING  ─────────────────────────────

async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    data = update.callback_query.data or ""

    if data.startswith("admin_"):
        await handle_admin_callback(update, context, data)
        return

    if not await is_auth(update, context):
        await update.callback_query.answer("\u26D4 Not authorized", show_alert=True)
        return

    if data.startswith("dl_"):
        await cb_download(update, context, data)
    elif data == "export":
        await cb_export(update, context)
    elif data == "stats":
        await cb_stats(update, context)
    elif data == "new":
        await cb_new(update, context)
    else:
        await update.callback_query.answer()

async def on_admin_broadcast_media(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id == ADMIN_USER_ID and context.user_data.get("admin_state") == "awaiting_broadcast":
        await handle_broadcast_receive(update, context)

async def start_render_web_server():
    async def handle(request):
        return web.Response(text="Bot is running!")
    
    app = web.Application()
    app.router.add_get('/', handle)
    runner = web.AppRunner(app)
    await runner.setup()
    
    port = int(os.environ.get("PORT", 8080))
    site = web.TCPSite(runner, '0.0.0.0', port)
    await site.start()
    log.info(f"Render Web Server started on port {port}")

async def render_keep_alive():
    url = os.environ.get("RENDER_EXTERNAL_URL")
    if not url:
        log.warning("RENDER_EXTERNAL_URL not set in environment. Self-ping disabled.")
        return
        
    while True:
        await asyncio.sleep(9 * 60) # Ping every 9 minutes (Render sleeps after 15)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    log.info(f"Self-ping status: {response.status}")
        except Exception as e:
            log.error(f"Self-ping failed: {e}")

def main():
    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .post_init(post_init)
        .concurrent_updates(True)
        # Generous network timeouts so transient slowness doesn't drop replies.
        .get_updates_read_timeout(60)
        .read_timeout(30)
        .write_timeout(60)
        .connect_timeout(20)
        .pool_timeout(20)
        .media_write_timeout(120)
        .build()
    )
    app.add_error_handler(error_handler)
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(CommandHandler("admin", cmd_admin))
    app.add_handler(CommandHandler("today", cmd_today))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.add_handler(MessageHandler(filters.Document.ALL, on_document))
    app.add_handler(MessageHandler(filters.ALL & ~filters.COMMAND, on_admin_broadcast_media))
    app.add_handler(CallbackQueryHandler(on_callback))
    log.info("Bot is running\u2026")
    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)

if __name__ == "__main__":
    import asyncio
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    main()
