import asyncio
import io
import os
import re
import secrets
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Optional, Any

import aiohttp
import discord
import imagehash
import libsql
import markovify
from PIL import Image, UnidentifiedImageError
from discord.ext import commands

from keep_alive import keep_alive

# ============================================================
# CONFIG
# ============================================================
PREFIX = ".n "

MUTE_ROLE_ID = 1483621610819948635
LOG_CHANNELS = [1541275389450649680, 1483728856962826240]
MOD_ROLES = [1483621610975002771, 1483621610975002772]
APPEAL_ACCEPT_ROLE = 1483621610975002772
PHASH_LIST_ROLE = 1483701058852356276

AWARN_ROLES = [
    1483621610975002769,
    1483621610975002770,
    1483621610975002771,
    1483621610975002772,
]

TURSO_URL = os.getenv("TURSO_DATABASE_URL")
TURSO_TOKEN = os.getenv("TURSO_AUTH_TOKEN")

MAX_IMAGE_BYTES = 10 * 1024 * 1024
PHASH_HASH_SIZE = 8
PHASH_MAX_DISTANCE = 8
WARN_EXPIRE_DAYS = 60

MUTE_1H = 60 * 60
MUTE_1D = 24 * 60 * 60
BAN_1D = 24 * 60 * 60
BAN_31D = 31 * 24 * 60 * 60

# ==================== MARKOV ====================
markov_enabled: set[int] = set()
markov_models: dict[int, Any] = {}
markov_corpus: dict[int, str] = defaultdict(str)
markov_message_count: dict[int, int] = defaultdict(int)
markov_last_reply: dict[int, float] = defaultdict(float)
MARKOV_MAX_CHARS = 10 * 1024 * 1024
MARKOV_EVERY = 15
MARKOV_COOLDOWN = 2.0

# ============================================================
# DISCORD
# ============================================================
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix=PREFIX, intents=intents, help_command=None)

punishment_tasks: dict[tuple[int, int], asyncio.Task] = {}
phash_scan_lock = asyncio.Lock()

# ============================================================
# DATABASE (Turso / libsql)
# ============================================================
def _get_conn():
    if not TURSO_URL or not TURSO_TOKEN:
        raise RuntimeError("Faltan TURSO_DATABASE_URL o TURSO_AUTH_TOKEN")
    return libsql.connect(database=TURSO_URL, auth_token=TURSO_TOKEN)


@asynccontextmanager
async def db_connect():
    conn = await asyncio.to_thread(_get_conn)
    try:
        yield conn
    finally:
        await asyncio.to_thread(conn.close)


async def db_execute(conn, sql: str, params: tuple = ()):
    def _exec():
        cur = conn.execute(sql, params)
        conn.commit()
        return cur
    return await asyncio.to_thread(_exec)


async def db_fetchall(conn, sql: str, params: tuple = ()):
    def _fetch():
        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        if cur.description:
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in rows]
        return rows
    return await asyncio.to_thread(_fetch)


async def db_fetchone(conn, sql: str, params: tuple = ()):
    rows = await db_fetchall(conn, sql, params)
    return rows[0] if rows else None


async def init_db():
    async with db_connect() as db:
        await db_execute(db, """
            CREATE TABLE IF NOT EXISTS warns (
                warn_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                mod_id INTEGER NOT NULL,
                guild_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                timestamp REAL NOT NULL,
                weight INTEGER NOT NULL DEFAULT 1,
                source TEXT NOT NULL DEFAULT 'manual',
                message_id INTEGER,
                expired INTEGER NOT NULL DEFAULT 0
            )
        """)
        await db_execute(db, """
            CREATE TABLE IF NOT EXISTS phashes (
                hash TEXT PRIMARY KEY,
                sanctions TEXT NOT NULL,
                added_by INTEGER NOT NULL,
                guild_id INTEGER NOT NULL,
                timestamp REAL NOT NULL,
                image_blob BLOB
            )
        """)
        await db_execute(db, """
            CREATE TABLE IF NOT EXISTS whitelist (
                hash TEXT PRIMARY KEY,
                guild_id INTEGER NOT NULL,
                added_by INTEGER NOT NULL,
                timestamp REAL NOT NULL,
                reason TEXT
            )
        """)
        await db_execute(db, """
            CREATE TABLE IF NOT EXISTS sanctions (
                user_id INTEGER PRIMARY KEY,
                guild_id INTEGER NOT NULL,
                sanction_type TEXT NOT NULL,
                expires_at REAL,
                reason TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
        """)
        await db_execute(db, """
            CREATE TABLE IF NOT EXISTS appeals (
                appeal_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                guild_id INTEGER NOT NULL,
                warn_id TEXT,
                detected_hash TEXT,
                blacklist_hash TEXT,
                message_id INTEGER,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at REAL NOT NULL
            )
        """)
        await db_execute(db, """
            CREATE TABLE IF NOT EXISTS awarns (
                awarn_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                mod_id INTEGER NOT NULL,
                guild_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                timestamp REAL NOT NULL,
                weight INTEGER NOT NULL DEFAULT 1
            )
        """)


# ============================================================
# HELPERS
# ============================================================
def now_ts() -> float:
    return time.time()


def discord_timestamp(ts: float) -> str:
    return f"<t:{int(ts)}:f>"


def has_mod_role(member: discord.Member) -> bool:
    return any(role.id in MOD_ROLES for role in getattr(member, "roles", []))


def can_accept_appeals(member: discord.Member) -> bool:
    return any(role.id == APPEAL_ACCEPT_ROLE for role in getattr(member, "roles", []))


def can_use_phash_list(member: discord.Member) -> bool:
    return any(role.id == PHASH_LIST_ROLE for role in getattr(member, "roles", []))


def get_staff_level(member: discord.Member) -> int:
    for i, rid in enumerate(AWARN_ROLES):
        if any(r.id == rid for r in member.roles):
            return i
    return -1


async def resolve_member(guild: discord.Guild, query: str) -> Optional[discord.Member]:
    query = query.strip()
    match = re.fullmatch(r"<@!?([0-9]{15,25})>", query)
    if match:
        uid = int(match.group(1))
        member = guild.get_member(uid)
        if member:
            return member
        try:
            return await guild.fetch_member(uid)
        except Exception:
            return None
    if query.isdigit():
        uid = int(query)
        member = guild.get_member(uid)
        if member:
            return member
        try:
            return await guild.fetch_member(uid)
        except Exception:
            return None
    lowered = query.casefold()
    for m in guild.members:
        if lowered in {m.name.casefold(), m.display_name.casefold(), str(m).casefold()}:
            return m
    matches = [m for m in guild.members if lowered in m.name.casefold() or lowered in m.display_name.casefold()]
    return matches[0] if len(matches) == 1 else None


async def send_logs(guild: Optional[discord.Guild], embed: discord.Embed, view: Optional[discord.ui.View] = None):
    if not guild:
        return
    for cid in LOG_CHANNELS:
        channel = guild.get_channel(cid)
        if channel:
            try:
                await channel.send(embed=embed, view=view)
            except Exception:
                pass


def generate_id() -> str:
    return secrets.token_hex(8)


# ============================================================
# MARKOV HELPERS
# ============================================================
def build_markov_model(text: str):
    if not text or len(text) < 80:
        return None
    try:
        return markovify.Text(text, state_size=3)
    except Exception:
        return None


def generate_markov_sentence(channel_id: int, max_words: int = 75) -> Optional[str]:
    model = markov_models.get(channel_id)
    if not model:
        # intentar construir al vuelo
        corpus = markov_corpus.get(channel_id, "")
        model = build_markov_model(corpus)
        if model:
            markov_models[channel_id] = model
        else:
            return None
    try:
        return model.make_sentence(tries=40, max_words=max_words)
    except Exception:
        return None


# ============================================================
# SANCIONES pHash
# ============================================================
PHASH_MAP = {
    "a": ("warn", 1, "Warn"),
    "b": ("warn", 2, "2 Warns"),
    "c": ("kick", 0, "Expulsión"),
    "d": ("mute_1h", 0, "Mute 1h"),
    "e": ("mute_1d", 0, "Mute 1d"),
    "f": ("ban_1d", 0, "Baneo 1 día"),
    "g": ("ban_31d", 0, "Baneo 1 mes"),
    "h": ("ban_permanent", 0, "Baneo permanente"),
}

SEVERITY = {
    "none": 0, "warn": 1, "mute_1h": 2, "mute_1d": 3,
    "kick": 4, "ban_1d": 5, "ban_31d": 6, "ban_permanent": 7
}


def parse_phash_letters(letters: str) -> tuple[str, int, str]:
    letters = letters.lower().replace(" ", "").replace(",", "")
    best_type = "warn"
    best_rank = 0
    total_weight = 0
    labels = []
    for ch in letters:
        if ch not in PHASH_MAP:
            continue
        tipo, w, label = PHASH_MAP[ch]
        rank = SEVERITY.get(tipo, 0)
        if rank > best_rank:
            best_rank = rank
            best_type = tipo
        if tipo == "warn":
            total_weight += w
        labels.append(label)
    if best_type == "warn" and total_weight == 0:
        total_weight = 1
    return best_type, total_weight, " + ".join(labels) if labels else "Warn"


def punishment_label(kind: str) -> str:
    return {
        "none": "Ninguna", "warn": "Advertencia",
        "mute_1h": "Mute 1 hora", "mute_1d": "Mute 1 día",
        "kick": "Expulsión", "ban_1d": "Baneo 1 día",
        "ban_31d": "Baneo 31 días", "ban_permanent": "Baneo permanente"
    }.get(kind, kind)


# ============================================================
# WARN / AWARN
# ============================================================
async def create_warn(guild, user, moderator, reason: str, weight: int = 1, source: str = "manual", message_id: int = None):
    warn_id = generate_id()
    ts = now_ts()
    async with db_connect() as db:
        await db_execute(
            db,
            "INSERT INTO warns (warn_id, user_id, mod_id, guild_id, reason, timestamp, weight, source, message_id) VALUES (?,?,?,?,?,?,?,?,?)",
            (warn_id, user.id, moderator.id, guild.id, reason[:96], ts, weight, source, message_id)
        )
    return warn_id


async def get_user_points(guild_id: int, user_id: int) -> int:
    async with db_connect() as db:
        row = await db_fetchone(
            db,
            "SELECT COALESCE(SUM(weight),0) as total FROM warns WHERE guild_id=? AND user_id=? AND expired=0",
            (guild_id, user_id)
        )
    return int(row["total"] if row else 0)


async def expire_old_warns():
    cutoff = now_ts() - (WARN_EXPIRE_DAYS * 86400)
    async with db_connect() as db:
        await db_execute(db, "UPDATE warns SET expired=1 WHERE timestamp < ? AND expired=0", (cutoff,))


# ============================================================
# SANCTIONS
# ============================================================
async def get_active_sanction(guild_id: int, user_id: int):
    async with db_connect() as db:
        return await db_fetchone(db, "SELECT * FROM sanctions WHERE guild_id=? AND user_id=?", (guild_id, user_id))


async def save_sanction(guild_id, user_id, sanction_type, expires_at, reason):
    ts = now_ts()
    async with db_connect() as db:
        await db_execute(db, """
            INSERT INTO sanctions(user_id, guild_id, sanction_type, expires_at, reason, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(user_id) DO UPDATE SET
                guild_id=excluded.guild_id, sanction_type=excluded.sanction_type,
                expires_at=excluded.expires_at, reason=excluded.reason, updated_at=excluded.updated_at
        """, (user_id, guild_id, sanction_type, expires_at, reason, ts, ts))


async def clear_sanction(user_id: int):
    async with db_connect() as db:
        await db_execute(db, "DELETE FROM sanctions WHERE user_id=?", (user_id,))
    for key in list(punishment_tasks.keys()):
        if key[1] == user_id:
            t = punishment_tasks.pop(key, None)
            if t and not t.done():
                t.cancel()


async def remove_effect(guild, user_id, sanction_type):
    if sanction_type.startswith("mute"):
        member = guild.get_member(user_id)
        if member:
            role = guild.get_role(MUTE_ROLE_ID)
            if role and role in member.roles:
                try:
                    await member.remove_roles(role, reason="Sanción finalizada / apelación")
                except Exception:
                    pass
    elif sanction_type.startswith("ban"):
        try:
            user = await bot.fetch_user(user_id)
            await guild.unban(user, reason="Sanción finalizada / apelación")
        except Exception:
            pass


async def schedule_expiry(guild, user_id, sanction_type, expires_at):
    key = (guild.id, user_id)
    old = punishment_tasks.get(key)
    if old and not old.done():
        old.cancel()
    if sanction_type == "ban_permanent" or expires_at is None:
        return

    async def worker():
        try:
            await asyncio.sleep(max(0, expires_at - now_ts()))
            cur = await get_active_sanction(guild.id, user_id)
            if not cur or cur["sanction_type"] != sanction_type:
                return
            await remove_effect(guild, user_id, sanction_type)
            await clear_sanction(user_id)
            embed = discord.Embed(title="Sanción finalizada", color=discord.Color.green())
            embed.add_field(name="Usuario", value=f"<@{user_id}>")
            embed.add_field(name="Sanción", value=punishment_label(sanction_type))
            await send_logs(guild, embed)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[timer] {e}")

    punishment_tasks[key] = bot.loop.create_task(worker())


async def apply_punishment(guild, user, desired: str, reason: str) -> str:
    current = await get_active_sanction(guild.id, user.id)
    current_type = current["sanction_type"] if current else "none"
    if current and SEVERITY.get(current_type, 0) >= SEVERITY.get(desired, 0):
        return punishment_label(current_type)

    if current and current_type != desired:
        await remove_effect(guild, user.id, current_type)

    if desired in ("none", "warn"):
        return punishment_label(desired)

    expiry = None
    if desired == "mute_1h":
        expiry = now_ts() + MUTE_1H
    elif desired == "mute_1d":
        expiry = now_ts() + MUTE_1D
    elif desired == "ban_1d":
        expiry = now_ts() + BAN_1D
    elif desired == "ban_31d":
        expiry = now_ts() + BAN_31D

    try:
        if desired.startswith("mute"):
            role = guild.get_role(MUTE_ROLE_ID)
            if role:
                await user.add_roles(role, reason=reason)
        elif desired.startswith("ban"):
            await guild.ban(user, reason=reason, delete_message_days=0)
        elif desired == "kick":
            await user.kick(reason=reason)
    except Exception as e:
        return f"Error: {e}"

    await save_sanction(guild.id, user.id, desired, expiry, reason)
    await schedule_expiry(guild, user.id, desired, expiry)
    return punishment_label(desired)


# ============================================================
# IMAGE / pHash
# ============================================================
async def download_bytes(url: str) -> Optional[bytes]:
    try:
        timeout = aiohttp.ClientTimeout(total=25)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return None
                data = await resp.read()
                return data if len(data) <= MAX_IMAGE_BYTES else None
    except Exception:
        return None


async def get_image(ctx, ref: str):
    target_msg = None
    if ctx.message.reference and ctx.message.reference.message_id:
        try:
            target_msg = await ctx.channel.fetch_message(ctx.message.reference.message_id)
        except Exception:
            pass
    if not target_msg and ref.lower().startswith("http"):
        m = re.search(r"channels/(\d+)/(\d+)", ref)
        if m:
            try:
                ch = bot.get_channel(int(m.group(1))) or await bot.fetch_channel(int(m.group(1)))
                target_msg = await ch.fetch_message(int(m.group(2)))
            except Exception:
                pass
    if not target_msg and ref.isdigit():
        try:
            target_msg = await ctx.channel.fetch_message(int(ref))
        except Exception:
            pass
    if not target_msg or not target_msg.attachments:
        return target_msg, None
    att = next((a for a in target_msg.attachments if (a.content_type and a.content_type.startswith("image/")) or a.filename.lower().endswith((".png",".jpg",".jpeg",".webp",".gif",".bmp"))), None)
    if not att or att.size > MAX_IMAGE_BYTES:
        return target_msg, None
    data = await download_bytes(att.url)
    return target_msg, data


async def make_phash(data: bytes) -> str:
    def _h():
        with Image.open(io.BytesIO(data)) as img:
            img.load()
            return str(imagehash.phash(img, hash_size=PHASH_HASH_SIZE))
    return await asyncio.to_thread(_h)


def hamming(a: str, b: str) -> int:
    try:
        return (int(a, 16) ^ int(b, 16)).bit_count()
    except Exception:
        return 999


async def find_match(guild_id: int, current: str):
    async with db_connect() as db:
        rows = await db_fetchall(db, "SELECT * FROM phashes WHERE guild_id=?", (guild_id,))
    best = None
    best_d = 999
    for r in rows:
        d = hamming(current, r["hash"])
        if d <= PHASH_MAX_DISTANCE and d < best_d:
            best = r
            best_d = d
    return best


async def is_whitelisted(guild_id: int, h: str) -> bool:
    async with db_connect() as db:
        row = await db_fetchone(db, "SELECT 1 FROM whitelist WHERE guild_id=? AND hash=?", (guild_id, h))
        return row is not None


# ============================================================
# VIEWS
# ============================================================
class AppealView(discord.ui.View):
    def __init__(self, warn_id, user_id, detected_hash, blacklist_hash, message_id):
        super().__init__(timeout=None)
        self.warn_id = warn_id
        self.user_id = user_id
        self.detected_hash = detected_hash
        self.blacklist_hash = blacklist_hash
        self.message_id = message_id

    @discord.ui.button(label="Apelar", style=discord.ButtonStyle.secondary)
    async def appeal(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.user_id:
            return await interaction.response.send_message("Solo el sancionado puede apelar.", ephemeral=True)
        appeal_id = generate_id()
        async with db_connect() as db:
            await db_execute(
                db,
                "INSERT INTO appeals (appeal_id,user_id,guild_id,warn_id,detected_hash,blacklist_hash,message_id,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (appeal_id, self.user_id, interaction.guild.id, self.warn_id, self.detected_hash, self.blacklist_hash, self.message_id, "pending", now_ts())
            )
        embed = discord.Embed(title="Nueva apelación", color=discord.Color.orange())
        embed.add_field(name="Usuario", value=f"<@{self.user_id}>")
        embed.add_field(name="Warn ID", value=f"`{self.warn_id}`")
        embed.add_field(name="Hash detectado", value=f"`{self.detected_hash}`")
        embed.add_field(name="Hash blacklist", value=f"`{self.blacklist_hash}`")
        view = AppealModView(appeal_id, self.user_id, self.detected_hash, self.warn_id)
        await send_logs(interaction.guild, embed, view=view)
        await interaction.response.send_message("Apelación enviada a los moderadores.", ephemeral=True)


class AppealModView(discord.ui.View):
    def __init__(self, appeal_id, user_id, detected_hash, warn_id):
        super().__init__(timeout=None)
        self.appeal_id = appeal_id
        self.user_id = user_id
        self.detected_hash = detected_hash
        self.warn_id = warn_id

    @discord.ui.button(label="Aceptar apelación", style=discord.ButtonStyle.success)
    async def accept(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not can_accept_appeals(interaction.user):
            return await interaction.response.send_message("Solo el rol autorizado puede aceptar apelaciones.", ephemeral=True)
        async with db_connect() as db:
            await db_execute(
                db,
                "INSERT OR IGNORE INTO whitelist (hash, guild_id, added_by, timestamp, reason) VALUES (?,?,?,?,?)",
                (self.detected_hash, interaction.guild.id, interaction.user.id, now_ts(), f"Apelación aceptada {self.appeal_id}")
            )
            await db_execute(db, "DELETE FROM warns WHERE warn_id=?", (self.warn_id,))
            await db_execute(db, "UPDATE appeals SET status='accepted' WHERE appeal_id=?", (self.appeal_id,))
        cur = await get_active_sanction(interaction.guild.id, self.user_id)
        if cur:
            await remove_effect(interaction.guild, self.user_id, cur["sanction_type"])
            await clear_sanction(self.user_id)
        embed = discord.Embed(title="Apelación aceptada", color=discord.Color.green())
        embed.add_field(name="Usuario", value=f"<@{self.user_id}>")
        embed.add_field(name="Hash añadido a whitelist", value=f"`{self.detected_hash}`")
        embed.add_field(name="Moderador", value=interaction.user.mention)
        await send_logs(interaction.guild, embed)
        await interaction.response.send_message("Apelación aceptada. Hash detectado añadido a whitelist y sanción retirada.", ephemeral=True)
        self.stop()

    @discord.ui.button(label="Rechazar", style=discord.ButtonStyle.danger)
    async def reject(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not can_accept_appeals(interaction.user):
            return await interaction.response.send_message("Solo el rol autorizado puede rechazar apelaciones.", ephemeral=True)
        async with db_connect() as db:
            await db_execute(db, "UPDATE appeals SET status='rejected' WHERE appeal_id=?", (self.appeal_id,))
        await interaction.response.send_message("Apelación rechazada.", ephemeral=True)
        self.stop()


class MarkovView(discord.ui.View):
    def __init__(self, channel_id: int):
        super().__init__(timeout=120)
        self.channel_id = channel_id

    @discord.ui.button(label="Activar", style=discord.ButtonStyle.success)
    async def activate(self, interaction: discord.Interaction, button: discord.ui.Button):
        markov_enabled.add(self.channel_id)
        await interaction.response.edit_message(
            content=f"✅ **Modo Markov activado** en este canal.\nEnviaré un mensaje cada {MARKOV_EVERY} mensajes.",
            view=None
        )

    @discord.ui.button(label="Desactivar", style=discord.ButtonStyle.danger)
    async def deactivate(self, interaction: discord.Interaction, button: discord.ui.Button):
        markov_enabled.discard(self.channel_id)
        await interaction.response.edit_message(
            content="❌ **Modo Markov desactivado** en este canal.\nLa base de texto se mantiene.",
            view=None
        )


class WarnPaginationView(discord.ui.View):
    def __init__(self, data, is_global, user=None, page=1):
        super().__init__(timeout=300)
        self.data = data
        self.is_global = is_global
        self.user = user
        self.page = page
        self.per_page = 5
        self.total_pages = max(1, (len(data) + self.per_page - 1) // self.per_page)
        self.update_buttons()

    def update_buttons(self):
        self.clear_items()
        prev_b = discord.ui.Button(label="Anterior", style=discord.ButtonStyle.secondary, disabled=self.page <= 1)
        next_b = discord.ui.Button(label="Siguiente", style=discord.ButtonStyle.secondary, disabled=self.page >= self.total_pages)
        edit_b = discord.ui.Button(label="Editar", style=discord.ButtonStyle.primary)
        del_b = discord.ui.Button(label="Borrar", style=discord.ButtonStyle.danger)
        prev_b.callback = self.prev_page
        next_b.callback = self.next_page
        edit_b.callback = self.edit_warn
        del_b.callback = self.delete_warn
        self.add_item(prev_b)
        self.add_item(next_b)
        self.add_item(edit_b)
        self.add_item(del_b)

    def generate_embed(self):
        start = (self.page - 1) * self.per_page
        page_data = self.data[start:start + self.per_page]
        title = "Lista global de warns" if self.is_global else f"Warns de {self.user.display_name if self.user else 'usuario'}"
        total = sum(int(r.get("weight", 0)) for r in self.data if not r.get("expired"))
        embed = discord.Embed(title=title, color=discord.Color.orange(),
                              description=f"**Puntos activos:** {total}\n**Registros:** {len(self.data)}")
        embed.set_footer(text=f"Página {self.page}/{self.total_pages}")
        for r in page_data:
            expired = " (CADUCADO)" if r.get("expired") else ""
            embed.add_field(
                name=f"ID: `{r['warn_id']}`{expired}",
                value=(f"**Usuario:** <@{r['user_id']}>\n"
                       f"**Mod:** <@{r['mod_id']}>\n"
                       f"**Motivo:** {r['reason']}\n"
                       f"**Peso:** {r['weight']}\n"
                       f"**Fecha:** {discord_timestamp(r['timestamp'])}"),
                inline=False
            )
        return embed

    async def check_mod(self, interaction):
        if not isinstance(interaction.user, discord.Member) or not has_mod_role(interaction.user):
            await interaction.response.send_message("No tienes permisos.", ephemeral=True)
            return False
        return True

    async def prev_page(self, interaction):
        if not await self.check_mod(interaction):
            return
        if self.page > 1:
            self.page -= 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.generate_embed(), view=self)

    async def next_page(self, interaction):
        if not await self.check_mod(interaction):
            return
        if self.page < self.total_pages:
            self.page += 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.generate_embed(), view=self)

    async def edit_warn(self, interaction):
        if not await self.check_mod(interaction):
            return
        await interaction.response.send_modal(EditWarnModal())

    async def delete_warn(self, interaction):
        if not await self.check_mod(interaction):
            return
        await interaction.response.send_modal(DeleteWarnModal())


class EditWarnModal(discord.ui.Modal, title="Editar Warn"):
    warn_id = discord.ui.TextInput(label="Warn ID (16 hex)", min_length=16, max_length=16)
    new_reason = discord.ui.TextInput(label="Nuevo motivo", max_length=96)

    async def on_submit(self, interaction: discord.Interaction):
        if not has_mod_role(interaction.user):
            return await interaction.response.send_message("Sin permisos.", ephemeral=True)
        wid = self.warn_id.value.strip().lower()
        async with db_connect() as db:
            row = await db_fetchone(db, "SELECT * FROM warns WHERE warn_id=?", (wid,))
            if not row:
                return await interaction.response.send_message("Warn no encontrado.", ephemeral=True)
            if row["user_id"] == interaction.user.id:
                return await interaction.response.send_message("No puedes editar un warn dirigido a ti mismo.", ephemeral=True)
            await db_execute(db, "UPDATE warns SET reason=? WHERE warn_id=?", (self.new_reason.value[:96], wid))
        embed = discord.Embed(title="Warn editado", color=discord.Color.blue())
        embed.add_field(name="ID", value=f"`{wid}`")
        embed.add_field(name="Nuevo motivo", value=self.new_reason.value)
        embed.add_field(name="Moderador", value=interaction.user.mention)
        await send_logs(interaction.guild, embed)
        await interaction.response.send_message(f"Warn `{wid}` actualizado.", ephemeral=True)


class DeleteWarnModal(discord.ui.Modal, title="Borrar Warn"):
    warn_id = discord.ui.TextInput(label="Warn ID (16 hex)", min_length=16, max_length=16)

    async def on_submit(self, interaction: discord.Interaction):
        if not has_mod_role(interaction.user):
            return await interaction.response.send_message("Sin permisos.", ephemeral=True)
        wid = self.warn_id.value.strip().lower()
        async with db_connect() as db:
            row = await db_fetchone(db, "SELECT * FROM warns WHERE warn_id=?", (wid,))
            if not row:
                return await interaction.response.send_message("Warn no encontrado.", ephemeral=True)
            if row["user_id"] == interaction.user.id:
                return await interaction.response.send_message("No puedes borrar un warn dirigido a ti mismo.", ephemeral=True)
            await db_execute(db, "DELETE FROM warns WHERE warn_id=?", (wid,))
        embed = discord.Embed(title="Warn eliminado", color=discord.Color.red())
        embed.add_field(name="ID", value=f"`{wid}`")
        embed.add_field(name="Usuario", value=f"<@{row['user_id']}>")
        embed.add_field(name="Moderador", value=interaction.user.mention)
        await send_logs(interaction.guild, embed)
        await interaction.response.send_message(f"Warn `{wid}` eliminado.", ephemeral=True)


class PHashPaginationView(discord.ui.View):
    def __init__(self, data, page=1):
        super().__init__(timeout=300)
        self.data = data
        self.page = page
        self.per_page = 8
        self.total_pages = max(1, (len(data) + self.per_page - 1) // self.per_page)
        self.update_buttons()

    def update_buttons(self):
        self.clear_items()
        prev_b = discord.ui.Button(label="Anterior", style=discord.ButtonStyle.secondary, disabled=self.page <= 1)
        next_b = discord.ui.Button(label="Siguiente", style=discord.ButtonStyle.secondary, disabled=self.page >= self.total_pages)
        del_b = discord.ui.Button(label="Borrar hash", style=discord.ButtonStyle.danger)
        prev_b.callback = self.prev_page
        next_b.callback = self.next_page
        del_b.callback = self.delete_hash
        self.add_item(prev_b)
        self.add_item(next_b)
        self.add_item(del_b)

    def generate_embed(self):
        start = (self.page - 1) * self.per_page
        page_data = self.data[start:start + self.per_page]
        embed = discord.Embed(title="Lista de pHash (blacklist)", color=discord.Color.purple(),
                              description=f"**Total:** {len(self.data)}")
        embed.set_footer(text=f"Página {self.page}/{self.total_pages}")
        for r in page_data:
            embed.add_field(
                name=f"`{r['hash']}`",
                value=f"**Sanciones:** `{r['sanctions']}`\n**Por:** <@{r['added_by']}>\n**Fecha:** {discord_timestamp(r['timestamp'])}",
                inline=False
            )
        return embed

    async def check(self, interaction):
        if not can_use_phash_list(interaction.user):
            await interaction.response.send_message("No tienes permiso para ver esta lista.", ephemeral=True)
            return False
        return True

    async def prev_page(self, interaction):
        if not await self.check(interaction):
            return
        if self.page > 1:
            self.page -= 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.generate_embed(), view=self)

    async def next_page(self, interaction):
        if not await self.check(interaction):
            return
        if self.page < self.total_pages:
            self.page += 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.generate_embed(), view=self)

    async def delete_hash(self, interaction):
        if not await self.check(interaction):
            return
        await interaction.response.send_modal(DeleteHashModal())


class DeleteHashModal(discord.ui.Modal, title="Borrar pHash"):
    hash_val = discord.ui.TextInput(label="Hash a borrar", min_length=16, max_length=16)

    async def on_submit(self, interaction: discord.Interaction):
        if not can_use_phash_list(interaction.user):
            return await interaction.response.send_message("Sin permiso.", ephemeral=True)
        h = self.hash_val.value.strip().lower()
        async with db_connect() as db:
            await db_execute(db, "DELETE FROM phashes WHERE hash=?", (h,))
        embed = discord.Embed(title="pHash eliminado", color=discord.Color.red())
        embed.add_field(name="Hash", value=f"`{h}`")
        embed.add_field(name="Por", value=interaction.user.mention)
        await send_logs(interaction.guild, embed)
        await interaction.response.send_message(f"Hash `{h}` eliminado de la blacklist.", ephemeral=True)


# ============================================================
# EVENTS
# ============================================================
@bot.event
async def on_ready():
    await init_db()
    await expire_old_warns()
    print(f"Bot listo | {bot.user} | Turso | Hamming ≤ {PHASH_MAX_DISTANCE} | Markov listo")


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        await bot.process_commands(message)
        return

    # ==================== pHash auto ====================
    if message.attachments:
        att = next((a for a in message.attachments if (a.content_type and a.content_type.startswith("image/")) or a.filename.lower().endswith((".png",".jpg",".jpeg",".webp",".gif",".bmp"))), None)
        if att and att.size <= MAX_IMAGE_BYTES:
            async with phash_scan_lock:
                try:
                    blob = await download_bytes(att.url)
                    if blob:
                        current = await make_phash(blob)
                        if await is_whitelisted(message.guild.id, current):
                            await bot.process_commands(message)
                            return
                        match = await find_match(message.guild.id, current)
                        if match:
                            tipo, weight, label = parse_phash_letters(match["sanctions"])
                            warn_id = await create_warn(
                                message.guild, message.author, bot.user,
                                reason=f"Imagen similar a blacklist (Hamming ≤ {PHASH_MAX_DISTANCE})",
                                weight=weight if tipo == "warn" else 1,
                                source="phash",
                                message_id=message.id
                            )
                            action = await apply_punishment(
                                message.guild, message.author,
                                tipo if tipo != "warn" else "none",
                                reason=f"pHash {match['hash']} | {warn_id}"
                            )
                            embed = discord.Embed(
                                title="Imagen en lista negra detectada",
                                description=(
                                    f"El usuario {message.author.mention} ha sido sancionado por el mensaje `{message.id}` "
                                    f"porque publicó una imagen suficientemente parecida a otra en la lista negra.\n\n"
                                    f"**Acción:** {label} → {action}\n**Warn ID:** `{warn_id}`"
                                ),
                                color=discord.Color.red()
                            )
                            view = AppealView(warn_id, message.author.id, current, match["hash"], message.id)
                            await message.channel.send(embed=embed, view=view)

                            log = discord.Embed(title="Auto-moderación pHash", color=discord.Color.red())
                            log.add_field(name="Usuario", value=f"{message.author.mention} ({message.author.id})")
                            log.add_field(name="Hash detectado", value=f"`{current}`")
                            log.add_field(name="Hash blacklist", value=f"`{match['hash']}`")
                            log.add_field(name="Distancia", value=str(hamming(current, match["hash"])))
                            log.add_field(name="Sanción", value=f"{label} → {action}")
                            await send_logs(message.guild, log)
                except Exception as e:
                    print(f"[pHash auto] {e}")

    # ==================== MARKOV ====================
    if message.channel.id in markov_enabled and not message.author.bot:
        content = message.content.strip()
        if content and not content.startswith(PREFIX):
            current_text = markov_corpus[message.channel.id]
            if len(current_text) < MARKOV_MAX_CHARS:
                markov_corpus[message.channel.id] = (current_text + " " + content).strip()
                # reconstruir modelo de vez en cuando
                if markov_message_count[message.channel.id] % 25 == 0:
                    markov_models[message.channel.id] = build_markov_model(markov_corpus[message.channel.id])

        markov_message_count[message.channel.id] += 1

        # enviar cadena cada X mensajes
        if markov_message_count[message.channel.id] % MARKOV_EVERY == 0:
            sentence = generate_markov_sentence(message.channel.id)
            if sentence:
                try:
                    await message.channel.send(sentence)
                except Exception:
                    pass

        # responder si contestan a un mensaje de Markov del bot
        if message.reference and message.reference.message_id:
            try:
                ref = message.reference.resolved
                if ref is None:
                    ref = await message.channel.fetch_message(message.reference.message_id)
                if ref and ref.author.id == bot.user.id:
                    now = time.time()
                    if now - markov_last_reply[message.channel.id] >= MARKOV_COOLDOWN:
                        markov_last_reply[message.channel.id] = now
                        reply = generate_markov_sentence(message.channel.id, max_words=55)
                        if reply:
                            await message.reply(reply)
            except Exception:
                pass

    await bot.process_commands(message)


# ============================================================
# COMMANDS
# ============================================================
@bot.command(name="markov")
@commands.has_permissions(manage_messages=True)
async def markov_command(ctx: commands.Context):
    if not ctx.guild:
        return await ctx.send("Solo en servidor.")
    view = MarkovView(ctx.channel.id)
    status = "activado" if ctx.channel.id in markov_enabled else "desactivado"
    await ctx.send(
        f"¿Activar modo de cadena de Markov?\n"
        f"Estado actual: **{status}**\n"
        f"Enviaré un mensaje cada {MARKOV_EVERY} mensajes (solo en este canal).",
        view=view
    )
    
@bot.command(name="phrase")
@commands.has_permissions(manage_messages=True)
async def phrase_command(ctx: commands.Context):
    """Fuerza al bot a generar una frase de Markov en este canal."""
    if not ctx.guild:
        return await ctx.send("Solo en servidor.")

    channel_id = ctx.channel.id

    # Intentar generar
    sentence = generate_markov_sentence(channel_id, max_words=70)

    if sentence:
        await ctx.send(sentence)
    else:
        # Mensajes chistosos cuando no hay suficiente texto o falla
        frases_error = [
            "Todavía no he absorbido suficiente caos de este canal... escribid más.",
            "Mi cerebro de Markov está vacío. Alimentadme con mensajes.",
            "Error 404: Personalidad no encontrada. Necesito más texto.",
            "Aún no tengo suficiente material para decir estupideces de calidad.",
            "Estoy en modo silencio porque este canal es demasiado aburrido todavía.",
            "O me alimentan con texto, ¡o me convierto en Manolo la alpaca!",
            "Texto, texto 🔔",
            "DENME MÁS TEXTO, CHAVALES.",
            "Les pediré amablemente que compartáis más texto y mensajes, así me permitiré armar cadenas de Markov. 🧐",
            "DADME TEXTO 😈👌",
            "Hola pibe, dame texto 😛"
            "No tengo frases. Solo vacío existencial. Escribid más."
        ]
        import random
        await ctx.send(random.choice(frases_error))


@bot.command(name="warn")
@commands.has_permissions(manage_messages=True)
async def warn_command(ctx: commands.Context, user_query: str, *, rest: str):
    try:
        if not ctx.guild:
            return await ctx.send("Solo en servidor.")
        parts = rest.rsplit(maxsplit=1)
        if len(parts) < 2 or not parts[1].isdigit():
            return await ctx.send("Uso: `.n warn <usuario> <motivo (máx 96)> <cantidad (1-2)>`")
        reason = parts[0].strip()[:96]
        amount = int(parts[1])
        if amount < 1 or amount > 2:
            return await ctx.send("La cantidad debe ser 1 o 2.")
        user = await resolve_member(ctx.guild, user_query)
        if not user:
            return await ctx.send("Usuario no encontrado.")
        warn_id = await create_warn(ctx.guild, user, ctx.author, reason=reason, weight=amount)
        points = await get_user_points(ctx.guild.id, user.id)
        embed = discord.Embed(title="Usuario advertido", color=discord.Color.orange())
        embed.add_field(name="Usuario", value=f"{user.mention} ({user.id})")
        embed.add_field(name="Moderador", value=ctx.author.mention)
        embed.add_field(name="Motivo", value=reason)
        embed.add_field(name="Warns aplicados", value=str(amount))
        embed.add_field(name="Puntos totales", value=str(points))
        embed.add_field(name="Warn ID", value=f"`{warn_id}`")
        await send_logs(ctx.guild, embed)
        await ctx.send(f"⚠️ {user.mention} recibió **{amount}** warn(s).\nMotivo: {reason}\nID: `{warn_id}` | Puntos: **{points}**")
    except Exception as e:
        await ctx.send(f"Error: `{e}`")


@bot.command(name="warns")
@commands.has_permissions(manage_messages=True)
async def warns_command(ctx: commands.Context, subcommand: str = "", *, user_query: str = ""):
    try:
        if not ctx.guild:
            return await ctx.send("Solo en servidor.")
        if subcommand.casefold() != "list":
            return await ctx.send("Uso: `.n warns list` o `.n warns list <usuario>`")
        user = None
        if user_query.strip():
            user = await resolve_member(ctx.guild, user_query.strip())
            if not user:
                return await ctx.send("Usuario no encontrado.")
        async with db_connect() as db:
            if user:
                data = await db_fetchall(db, "SELECT * FROM warns WHERE guild_id=? AND user_id=? ORDER BY timestamp DESC", (ctx.guild.id, user.id))
            else:
                data = await db_fetchall(db, "SELECT * FROM warns WHERE guild_id=? ORDER BY timestamp DESC LIMIT 100", (ctx.guild.id,))
        if not data:
            return await ctx.send("No hay warns." if not user else f"{user.display_name} no tiene warns.")
        view = WarnPaginationView(data, is_global=user is None, user=user)
        await ctx.send(embed=view.generate_embed(), view=view)
    except Exception as e:
        await ctx.send(f"Error: `{e}`")


@bot.command(name="pHash")
@commands.has_permissions(manage_messages=True)
async def phash_command(ctx: commands.Context, target: str, *, sanctions: str = ""):
    try:
        if not ctx.guild:
            return await ctx.send("Solo en servidor.")

        if target.casefold() == "list":
            if not can_use_phash_list(ctx.author):
                return await ctx.send("No tienes permiso para ver la lista de pHash.")
            async with db_connect() as db:
                data = await db_fetchall(db, "SELECT * FROM phashes WHERE guild_id=? ORDER BY timestamp DESC", (ctx.guild.id,))
            if not data:
                return await ctx.send("No hay hashes registrados.")
            view = PHashPaginationView(data)
            return await ctx.send(embed=view.generate_embed(), view=view)

        if not sanctions:
            return await ctx.send(
                "Uso: `.n pHash <ID|link|respuesta> <letras>`\n"
                "a=Warn  b=2Warns  c=Kick  d=Mute1h  e=Mute1d  f=Ban1d  g=Ban1mes  h=Ban permanente\n"
                "Ejemplo: `.n pHash 123456789 fh`"
            )

        target_msg, image_bytes = await get_image(ctx, target)
        if not image_bytes:
            return await ctx.send(
                "No se pudo obtener la imagen.\n"
                "• Responde a un mensaje con imagen, o\n"
                "• Pasa el ID del mensaje, o\n"
                "• Pasa el link completo del mensaje."
            )

        img_hash = await make_phash(image_bytes)
        tipo, weight, label = parse_phash_letters(sanctions)

        async with db_connect() as db:
            try:
                await db_execute(
                    db,
                    "INSERT INTO phashes (hash, sanctions, added_by, guild_id, timestamp, image_blob) VALUES (?,?,?,?,?,?)",
                    (img_hash, sanctions.lower(), ctx.author.id, ctx.guild.id, now_ts(), image_bytes)
                )
            except Exception as e:
                if "UNIQUE" in str(e).upper() or "constraint" in str(e).lower():
                    return await ctx.send(f"El hash `{img_hash}` ya existe.")
                raise

        embed = discord.Embed(title="pHash añadido a blacklist", color=discord.Color.green())
        embed.add_field(name="Hash", value=f"`{img_hash}`")
        embed.add_field(name="Sanciones", value=f"`{sanctions}` → **{label}**")
        embed.add_field(name="Por", value=ctx.author.mention)
        if target_msg:
            embed.add_field(name="Mensaje", value=str(target_msg.id))
        await send_logs(ctx.guild, embed)
        await ctx.send(f"✅ Hash `{img_hash}` registrado.\nSanciones: `{sanctions}` → **{label}**\nDistancia máxima: {PHASH_MAX_DISTANCE}")
    except Exception as e:
        await ctx.send(f"Error: `{e}`")


@bot.command(name="awarn")
@commands.has_permissions(manage_messages=True)
async def awarn_command(ctx: commands.Context, user_query: str, *, rest: str):
    try:
        if not ctx.guild:
            return await ctx.send("Solo en servidor.")
        parts = rest.rsplit(maxsplit=1)
        if len(parts) < 2 or not parts[1].isdigit():
            return await ctx.send("Uso: `.n awarn <usuario> <motivo> <cantidad>`")
        reason = parts[0].strip()[:96]
        amount = int(parts[1])
        if amount < 1 or amount > 5:
            return await ctx.send("Cantidad entre 1 y 5.")

        user = await resolve_member(ctx.guild, user_query)
        if not user:
            return await ctx.send("Usuario no encontrado.")

        level = get_staff_level(user)
        if level == -1:
            return await ctx.send("Ese usuario no tiene ninguno de los roles de staff del sistema awarn.")

        awarn_id = generate_id()
        async with db_connect() as db:
            await db_execute(
                db,
                "INSERT INTO awarns (awarn_id, user_id, mod_id, guild_id, reason, timestamp, weight) VALUES (?,?,?,?,?,?,?)",
                (awarn_id, user.id, ctx.author.id, ctx.guild.id, reason, now_ts(), amount)
            )
            row = await db_fetchone(db, "SELECT COALESCE(SUM(weight),0) as total FROM awarns WHERE guild_id=? AND user_id=?", (ctx.guild.id, user.id))
            total = int(row["total"] if row else 0)

        demote_msg = ""
        if total >= 3 and level > 0:
            current_role = ctx.guild.get_role(AWARN_ROLES[level])
            lower_role = ctx.guild.get_role(AWARN_ROLES[level - 1])
            try:
                if current_role:
                    await user.remove_roles(current_role, reason="3+ awarns → demote")
                if lower_role:
                    await user.add_roles(lower_role, reason="3+ awarns → demote")
                demote_msg = f"\n⚠️ **Demote:** bajó de nivel (ahora tiene el rol inferior)."
            except Exception as e:
                demote_msg = f"\nNo se pudo demotear automáticamente: {e}"

        embed = discord.Embed(title="Awarn aplicado", color=discord.Color.dark_orange())
        embed.add_field(name="Usuario", value=f"{user.mention}")
        embed.add_field(name="Moderador", value=ctx.author.mention)
        embed.add_field(name="Motivo", value=reason)
        embed.add_field(name="Cantidad", value=str(amount))
        embed.add_field(name="Total awarns", value=str(total))
        embed.add_field(name="ID", value=f"`{awarn_id}`")
        await send_logs(ctx.guild, embed)
        await ctx.send(f"Awarn aplicado a {user.mention}. Total: **{total}**{demote_msg}")
    except Exception as e:
        await ctx.send(f"Error: `{e}`")


@bot.command(name="awarns")
@commands.has_permissions(manage_messages=True)
async def awarns_command(ctx: commands.Context, subcommand: str = "", *, user_query: str = ""):
    try:
        if not ctx.guild:
            return await ctx.send("Solo en servidor.")
        if subcommand.casefold() != "list":
            return await ctx.send("Uso: `.n awarns list` o `.n awarns list <usuario>`")
        user = None
        if user_query.strip():
            user = await resolve_member(ctx.guild, user_query.strip())
            if not user:
                return await ctx.send("Usuario no encontrado.")
        async with db_connect() as db:
            if user:
                data = await db_fetchall(db, "SELECT * FROM awarns WHERE guild_id=? AND user_id=? ORDER BY timestamp DESC", (ctx.guild.id, user.id))
            else:
                data = await db_fetchall(db, "SELECT * FROM awarns WHERE guild_id=? ORDER BY timestamp DESC LIMIT 50", (ctx.guild.id,))
        if not data:
            return await ctx.send("No hay awarns.")
        lines = []
        for r in data[:15]:
            lines.append(f"`{r['awarn_id']}` • <@{r['user_id']}> • peso {r['weight']} • {r['reason'][:40]} • {discord_timestamp(r['timestamp'])}")
        embed = discord.Embed(title="Lista de awarns", description="\n".join(lines), color=discord.Color.dark_orange())
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"Error: `{e}`")


# ============================================================
# ERROR HANDLING
# ============================================================
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    if isinstance(error, commands.MissingPermissions):
        return await ctx.send("Necesitas permiso **Gestionar mensajes**.")
    if isinstance(error, commands.MissingRequiredArgument):
        return await ctx.send("Faltan argumentos.")
    await ctx.send(f"Error: `{error}`")
    print(f"[error] {error}")


# ============================================================
# START
# ============================================================
keep_alive()
TOKEN = os.getenv("DISCORD_TOKEN")
if not TOKEN:
    raise RuntimeError("Falta DISCORD_TOKEN")
if not TURSO_URL or not TURSO_TOKEN:
    raise RuntimeError("Faltan TURSO_DATABASE_URL o TURSO_AUTH_TOKEN")
bot.run(TOKEN)
