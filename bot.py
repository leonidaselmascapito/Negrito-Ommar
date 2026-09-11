import asyncio
import io
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from typing import Optional

import aiohttp
import aiosqlite
import discord
import imagehash
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

DB_PATH = os.getenv("MODERATION_DB_PATH", "/var/data/moderation.db" if os.path.isdir("/var/data") else "moderation.db")
MAX_IMAGE_BYTES = 10 * 1024 * 1024
PHASH_HASH_SIZE = 8          # 8x8 = 64 bits
PHASH_MAX_DISTANCE = 8       # distancia Hamming máxima para considerar "parecida"

MUTE_1H = 60 * 60
MUTE_1D = 24 * 60 * 60
BAN_1D = 24 * 60 * 60
BAN_31D = 31 * 24 * 60 * 60

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
# DATABASE
# ============================================================
@asynccontextmanager
async def db_connect():
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    try:
        yield db
    finally:
        await db.close()


async def init_db():
    async with db_connect() as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS warns (
                warn_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                mod_id INTEGER NOT NULL,
                guild_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                timestamp REAL NOT NULL,
                weight INTEGER NOT NULL,
                source TEXT NOT NULL DEFAULT 'manual',
                message_id INTEGER
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS phashes (
                hash TEXT PRIMARY KEY,
                hash_algo TEXT NOT NULL DEFAULT 'phash',
                hash_bits INTEGER NOT NULL DEFAULT 64,
                sanctions TEXT NOT NULL,
                added_by INTEGER NOT NULL,
                guild_id INTEGER NOT NULL,
                timestamp REAL NOT NULL,
                image_blob BLOB
            )
        """)

        await db.execute("""
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

        await db.execute("""
            CREATE TABLE IF NOT EXISTS appeals (
                appeal_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                guild_id INTEGER NOT NULL,
                warn_id TEXT,
                phash TEXT,
                message_id INTEGER,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at REAL NOT NULL
            )
        """)

        # Migraciones suaves
        for col, defn in [
            ("reason", "TEXT NOT NULL DEFAULT ''"),
            ("weight", "INTEGER NOT NULL DEFAULT 1"),
            ("source", "TEXT NOT NULL DEFAULT 'manual'"),
            ("message_id", "INTEGER"),
        ]:
            await _add_column_if_missing(db, "warns", col, defn)

        await db.commit()


async def _add_column_if_missing(db, table: str, column: str, definition: str):
    async with db.execute(f"PRAGMA table_info({table})") as cursor:
        columns = {row[1] for row in await cursor.fetchall()}
    if column not in columns:
        try:
            await db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        except Exception:
            pass


# ============================================================
# HELPERS
# ============================================================
def now_ts() -> float:
    return time.time()


def discord_timestamp(ts: float) -> str:
    return f"<t:{int(ts)}:f>"


def has_mod_role(member: discord.Member) -> bool:
    return any(role.id in MOD_ROLES for role in getattr(member, "roles", []))


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
        except (discord.NotFound, discord.HTTPException):
            return None

    if query.isdigit():
        uid = int(query)
        member = guild.get_member(uid)
        if member:
            return member
        try:
            return await guild.fetch_member(uid)
        except (discord.NotFound, discord.HTTPException):
            return None

    lowered = query.casefold()
    for member in guild.members:
        if lowered in {member.name.casefold(), member.display_name.casefold(), str(member).casefold()}:
            return member

    matches = [m for m in guild.members if lowered in m.name.casefold() or lowered in m.display_name.casefold()]
    return matches[0] if len(matches) == 1 else None


# ============================================================
# SANCIONES pHash (letras)
# ============================================================
PHASH_SANCTION_MAP = {
    "a": ("warn", 1, "Warn"),
    "b": ("warn", 2, "2 Warns"),
    "c": ("kick", 0, "Expulsión"),
    "d": ("mute_1h", 0, "Mute 1 hora"),
    "e": ("mute_1d", 0, "Mute 1 día"),
    "f": ("ban_1d", 0, "Baneo 1 día"),
    "g": ("ban_31d", 0, "Baneo 1 mes"),
    "h": ("ban_permanent", 0, "Baneo permanente"),
}

SEVERITY_RANK = {
    "warn": 1,
    "mute_1h": 2,
    "mute_1d": 3,
    "kick": 4,
    "ban_1d": 5,
    "ban_31d": 6,
    "ban_permanent": 7,
}


def parse_phash_sanctions(letters: str) -> tuple[str, int, str]:
    """Devuelve (tipo_mas_grave, peso_warns, label)"""
    letters = letters.lower().replace(" ", "").replace(",", "")
    best_type = "warn"
    best_rank = 0
    total_warn_weight = 0
    labels = []

    for ch in letters:
        if ch not in PHASH_SANCTION_MAP:
            continue
        tipo, weight, label = PHASH_SANCTION_MAP[ch]
        rank = SEVERITY_RANK.get(tipo, 0)
        if rank > best_rank:
            best_rank = rank
            best_type = tipo
        if tipo == "warn":
            total_warn_weight += weight
        labels.append(label)

    if best_type == "warn" and total_warn_weight == 0:
        total_warn_weight = 1

    label_str = " + ".join(labels) if labels else "Warn"
    return best_type, total_warn_weight, label_str


def punishment_label(kind: str) -> str:
    return {
        "none": "Ninguna",
        "warn": "Advertencia",
        "mute_1h": "Mute de 1 hora",
        "mute_1d": "Mute de 1 día",
        "kick": "Expulsión",
        "ban_1d": "Baneo de 1 día",
        "ban_31d": "Baneo de 31 días",
        "ban_permanent": "Baneo permanente",
    }.get(kind, kind)


# ============================================================
# LOGGING
# ============================================================
async def send_logs(guild: Optional[discord.Guild], embed: discord.Embed, view: Optional[discord.ui.View] = None):
    if not guild:
        return
    for channel_id in LOG_CHANNELS:
        channel = guild.get_channel(channel_id)
        if channel:
            try:
                await channel.send(embed=embed, view=view)
            except Exception:
                pass


# ============================================================
# WARN DB
# ============================================================
async def generate_id() -> str:
    return secrets.token_hex(8)


async def get_user_points(guild_id: int, user_id: int) -> int:
    async with db_connect() as db:
        async with db.execute(
            "SELECT COALESCE(SUM(weight), 0) FROM warns WHERE guild_id = ? AND user_id = ?",
            (guild_id, user_id),
        ) as cursor:
            row = await cursor.fetchone()
    return int(row[0] or 0)


async def create_warn(
    guild: discord.Guild,
    user: discord.Member,
    moderator: discord.abc.User,
    reason: str,
    weight: int = 1,
    source: str = "manual",
    message_id: Optional[int] = None,
) -> tuple[str, int]:
    warn_id = await generate_id()
    ts = now_ts()

    async with db_connect() as db:
        await db.execute(
            """
            INSERT INTO warns (warn_id, user_id, mod_id, guild_id, reason, timestamp, weight, source, message_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (warn_id, user.id, moderator.id, guild.id, reason[:96], ts, weight, source, message_id),
        )
        await db.commit()

    points = await get_user_points(guild.id, user.id)
    return warn_id, points


# ============================================================
# SANCTIONS (mute / ban / kick)
# ============================================================
async def get_active_sanction(guild_id: int, user_id: int) -> Optional[aiosqlite.Row]:
    async with db_connect() as db:
        async with db.execute(
            "SELECT * FROM sanctions WHERE guild_id = ? AND user_id = ?",
            (guild_id, user_id),
        ) as cursor:
            return await cursor.fetchone()


async def save_sanction(guild_id: int, user_id: int, sanction_type: str, expires_at: Optional[float], reason: str):
    ts = now_ts()
    async with db_connect() as db:
        await db.execute(
            """
            INSERT INTO sanctions(user_id, guild_id, sanction_type, expires_at, reason, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                guild_id=excluded.guild_id,
                sanction_type=excluded.sanction_type,
                expires_at=excluded.expires_at,
                reason=excluded.reason,
                updated_at=excluded.updated_at
            """,
            (user_id, guild_id, sanction_type, expires_at, reason, ts, ts),
        )
        await db.commit()


async def clear_sanction(user_id: int):
    async with db_connect() as db:
        await db.execute("DELETE FROM sanctions WHERE user_id = ?", (user_id,))
        await db.commit()
    for key in list(punishment_tasks.keys()):
        if key[1] == user_id:
            task = punishment_tasks.pop(key)
            if task and not task.done():
                task.cancel()


async def remove_bot_sanction_effect(guild: discord.Guild, user_id: int, sanction_type: str):
    if sanction_type.startswith("mute"):
        member = guild.get_member(user_id)
        if member:
            role = guild.get_role(MUTE_ROLE_ID)
            if role and role in member.roles:
                try:
                    await member.remove_roles(role, reason="Sanción finalizada / apelación aceptada")
                except Exception:
                    pass
    elif sanction_type.startswith("ban"):
        try:
            user = await bot.fetch_user(user_id)
            await guild.unban(user, reason="Sanción finalizada / apelación aceptada")
        except Exception:
            pass


async def schedule_sanction_expiry(guild: discord.Guild, user_id: int, sanction_type: str, expires_at: Optional[float]):
    key = (guild.id, user_id)
    old = punishment_tasks.get(key)
    if old and not old.done():
        old.cancel()

    if sanction_type == "ban_permanent" or expires_at is None:
        punishment_tasks.pop(key, None)
        return

    async def worker():
        try:
            await asyncio.sleep(max(0, expires_at - now_ts()))
            current = await get_active_sanction(guild.id, user_id)
            if not current or current["sanction_type"] != sanction_type:
                return
            await remove_bot_sanction_effect(guild, user_id, sanction_type)
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


async def apply_punishment(guild: discord.Guild, user: discord.Member, desired: str, reason: str) -> str:
    current = await get_active_sanction(guild.id, user.id)
    current_type = current["sanction_type"] if current else "none"

    if current and SEVERITY_RANK.get(current_type, 0) >= SEVERITY_RANK.get(desired, 0):
        return punishment_label(current_type)

    if current and current_type != desired:
        await remove_bot_sanction_effect(guild, user.id, current_type)

    if desired == "none" or desired == "warn":
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
        return f"Error al aplicar: {e}"

    await save_sanction(guild.id, user.id, desired, expiry, reason)
    await schedule_sanction_expiry(guild, user.id, desired, expiry)
    return punishment_label(desired)


async def restore_active_sanctions():
    async with db_connect() as db:
        async with db.execute("SELECT * FROM sanctions") as cursor:
            rows = await cursor.fetchall()

    for row in rows:
        guild = bot.get_guild(row["guild_id"])
        if not guild:
            continue
        try:
            if row["sanction_type"].startswith("mute"):
                member = guild.get_member(row["user_id"])
                role = guild.get_role(MUTE_ROLE_ID)
                if member and role and role not in member.roles:
                    await member.add_roles(role, reason="Restauración tras reinicio")
            if row["expires_at"] and row["expires_at"] <= now_ts():
                await remove_bot_sanction_effect(guild, row["user_id"], row["sanction_type"])
                await clear_sanction(row["user_id"])
            else:
                await schedule_sanction_expiry(guild, row["user_id"], row["sanction_type"], row["expires_at"])
        except Exception as e:
            print(f"[restore] {e}")


# ============================================================
# IMAGE / pHash
# ============================================================
async def download_image_bytes(url: str) -> Optional[bytes]:
    try:
        timeout = aiohttp.ClientTimeout(total=25)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return None
                data = await resp.read()
                if len(data) > MAX_IMAGE_BYTES:
                    return None
                return data
    except Exception:
        return None


async def get_image_from_message_ref(ctx: commands.Context, ref: str) -> tuple[Optional[discord.Message], Optional[bytes]]:
    target_msg = None

    # 1. Respuesta a un mensaje
    if ctx.message.reference and ctx.message.reference.message_id:
        try:
            target_msg = await ctx.channel.fetch_message(ctx.message.reference.message_id)
        except Exception:
            pass

    # 2. Link de mensaje de Discord
    if not target_msg and ref.lower().startswith("http"):
        match = re.search(r"channels/(\d+)/(\d+)", ref)
        if match:
            try:
                channel = bot.get_channel(int(match.group(1))) or await bot.fetch_channel(int(match.group(1)))
                target_msg = await channel.fetch_message(int(match.group(2)))
            except Exception:
                pass

    # 3. ID numérico de mensaje
    if not target_msg and ref.isdigit():
        try:
            target_msg = await ctx.channel.fetch_message(int(ref))
        except Exception:
            pass

    if not target_msg or not target_msg.attachments:
        return target_msg, None

    attachment = next(
        (a for a in target_msg.attachments
         if (a.content_type and a.content_type.startswith("image/"))
         or a.filename.lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"))),
        None,
    )
    if not attachment or attachment.size > MAX_IMAGE_BYTES:
        return target_msg, None

    data = await download_image_bytes(attachment.url)
    return target_msg, data


async def make_phash(image_bytes: bytes) -> str:
    def _hash():
        with Image.open(io.BytesIO(image_bytes)) as img:
            img.load()
            return str(imagehash.phash(img, hash_size=PHASH_HASH_SIZE))
    return await asyncio.to_thread(_hash)


def hamming(a: str, b: str) -> int:
    try:
        return (int(a, 16) ^ int(b, 16)).bit_count()
    except Exception:
        return 999


async def find_matching_phash(guild_id: int, current_hash: str) -> Optional[aiosqlite.Row]:
    async with db_connect() as db:
        async with db.execute(
            "SELECT * FROM phashes WHERE guild_id = ?",
            (guild_id,),
        ) as cursor:
            rows = await cursor.fetchall()

    best = None
    best_dist = 999
    for row in rows:
        dist = hamming(current_hash, row["hash"])
        if dist <= PHASH_MAX_DISTANCE and dist < best_dist:
            best = row
            best_dist = dist
    return best


# ============================================================
# VIEWS - APELACIÓN
# ============================================================
class AppealView(discord.ui.View):
    def __init__(self, warn_id: str, user_id: int, phash: str, message_id: int):
        super().__init__(timeout=None)
        self.warn_id = warn_id
        self.user_id = user_id
        self.phash = phash
        self.message_id = message_id

    @discord.ui.button(label="Apelar", style=discord.ButtonStyle.secondary, custom_id="appeal_btn")
    async def appeal_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.user_id:
            return await interaction.response.send_message("Solo el usuario sancionado puede apelar.", ephemeral=True)

        appeal_id = await generate_id()
        async with db_connect() as db:
            await db.execute(
                "INSERT INTO appeals (appeal_id, user_id, guild_id, warn_id, phash, message_id, status, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (appeal_id, self.user_id, interaction.guild.id, self.warn_id, self.phash, self.message_id, "pending", now_ts()),
            )
            await db.commit()

        embed = discord.Embed(title="Nueva apelación", color=discord.Color.orange())
        embed.add_field(name="Usuario", value=f"<@{self.user_id}>")
        embed.add_field(name="Warn ID", value=f"`{self.warn_id}`")
        embed.add_field(name="pHash", value=f"`{self.phash}`")
        embed.add_field(name="Mensaje original", value=f"`{self.message_id}`")
        embed.add_field(name="Appeal ID", value=f"`{appeal_id}`")

        view = AppealModView(appeal_id, self.user_id, self.phash, self.warn_id)
        await send_logs(interaction.guild, embed, view=view)
        await interaction.response.send_message("Tu apelación ha sido enviada a los moderadores.", ephemeral=True)


class AppealModView(discord.ui.View):
    def __init__(self, appeal_id: str, user_id: int, phash: str, warn_id: str):
        super().__init__(timeout=None)
        self.appeal_id = appeal_id
        self.user_id = user_id
        self.phash = phash
        self.warn_id = warn_id

    @discord.ui.button(label="Aceptar apelación", style=discord.ButtonStyle.success)
    async def accept(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not has_mod_role(interaction.user):
            return await interaction.response.send_message("Solo moderadores.", ephemeral=True)

        # Quitar el hash de la lista negra
        async with db_connect() as db:
            await db.execute("DELETE FROM phashes WHERE hash = ?", (self.phash,))
            await db.execute("DELETE FROM warns WHERE warn_id = ?", (self.warn_id,))
            await db.execute("UPDATE appeals SET status = 'accepted' WHERE appeal_id = ?", (self.appeal_id,))
            await db.commit()

        # Quitar sanción activa si existe
        guild = interaction.guild
        current = await get_active_sanction(guild.id, self.user_id)
        if current:
            await remove_bot_sanction_effect(guild, self.user_id, current["sanction_type"])
            await clear_sanction(self.user_id)

        embed = discord.Embed(title="Apelación aceptada", color=discord.Color.green())
        embed.add_field(name="Usuario", value=f"<@{self.user_id}>")
        embed.add_field(name="pHash eliminado", value=f"`{self.phash}`")
        embed.add_field(name="Moderador", value=interaction.user.mention)
        await send_logs(guild, embed)

        await interaction.response.send_message("Apelación aceptada. Hash eliminado y sanción revertida.", ephemeral=True)
        self.stop()

    @discord.ui.button(label="Rechazar", style=discord.ButtonStyle.danger)
    async def reject(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not has_mod_role(interaction.user):
            return await interaction.response.send_message("Solo moderadores.", ephemeral=True)

        async with db_connect() as db:
            await db.execute("UPDATE appeals SET status = 'rejected' WHERE appeal_id = ?", (self.appeal_id,))
            await db.commit()

        await interaction.response.send_message("Apelación rechazada.", ephemeral=True)
        self.stop()


# ============================================================
# EVENTS
# ============================================================
@bot.event
async def on_ready():
    await init_db()
    await restore_active_sanctions()
    print(f"Bot listo | {bot.user} | pHash distancia ≤ {PHASH_MAX_DISTANCE}")


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        await bot.process_commands(message)
        return

    # Auto pHash scan
    if message.attachments:
        att = next(
            (a for a in message.attachments
             if (a.content_type and a.content_type.startswith("image/"))
             or a.filename.lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"))),
            None,
        )
        if att and att.size <= MAX_IMAGE_BYTES:
            async with phash_scan_lock:
                try:
                    blob = await download_image_bytes(att.url)
                    if blob:
                        current = await make_phash(blob)
                        match = await find_matching_phash(message.guild.id, current)
                        if match:
                            # Aplicar sanción guardada en el hash
                            tipo, weight, label = parse_phash_sanctions(match["sanctions"])

                            warn_id, points = await create_warn(
                                message.guild,
                                message.author,
                                bot.user,
                                reason=f"Imagen similar a blacklist (distancia Hamming ≤ {PHASH_MAX_DISTANCE})",
                                weight=weight if tipo == "warn" else 1,
                                source="phash",
                                message_id=message.id,
                            )

                            action = await apply_punishment(
                                message.guild,
                                message.author,
                                tipo if tipo != "warn" else "none",
                                reason=f"pHash match {match['hash']} | Warn {warn_id}",
                            )

                            # Mensaje público con botón de apelación
                            embed = discord.Embed(
                                title="Imagen en lista negra detectada",
                                description=(
                                    f"El usuario {message.author.mention} ha sido sancionado por el mensaje de ID `{message.id}` "
                                    f"debido a que publicó una imagen suficientemente parecida a otra en la lista negra.\n\n"
                                    f"**Acción:** {label} → {action}\n"
                                    f"**Warn ID:** `{warn_id}`"
                                ),
                                color=discord.Color.red(),
                            )
                            view = AppealView(warn_id, message.author.id, match["hash"], message.id)
                            await message.channel.send(embed=embed, view=view)

                            # Log
                            log_embed = discord.Embed(title="Auto-moderación pHash", color=discord.Color.red())
                            log_embed.add_field(name="Usuario", value=f"{message.author.mention} ({message.author.id})")
                            log_embed.add_field(name="Hash detectado", value=f"`{current}`")
                            log_embed.add_field(name="Hash blacklist", value=f"`{match['hash']}`")
                            log_embed.add_field(name="Distancia", value=str(hamming(current, match["hash"])))
                            log_embed.add_field(name="Sanción aplicada", value=f"{label} → {action}")
                            log_embed.add_field(name="Warn ID", value=f"`{warn_id}`")
                            await send_logs(message.guild, log_embed)
                except Exception as e:
                    print(f"[pHash auto] {e}")

    await bot.process_commands(message)


# ============================================================
# COMMANDS
# ============================================================
@bot.command(name="warn")
@commands.has_permissions(manage_messages=True)
async def warn_command(ctx: commands.Context, user_query: str, *, rest: str):
    """
    Uso: .n warn <usuario> "motivo hasta 96 caracteres" <cantidad>
    Ejemplo: .n warn @user "spam de imágenes" 2
    """
    try:
        if not ctx.guild:
            return await ctx.send("Solo en servidor.")

        # Extraer motivo entre comillas y la cantidad
        match = re.search(r'"([^"]{1,96})"\s+(\d+)', rest)
        if not match:
            return await ctx.send('Uso correcto:\n`.n warn <usuario> "motivo (máx 96 caracteres)" <cantidad de warns>`')

        reason = match.group(1).strip()
        amount = int(match.group(2))
        if amount < 1 or amount > 20:
            return await ctx.send("La cantidad de warns debe estar entre 1 y 20.")

        user = await resolve_member(ctx.guild, user_query)
        if not user:
            return await ctx.send("Usuario no encontrado.")

        warn_id, points = await create_warn(
            ctx.guild, user, ctx.author, reason=reason, weight=amount, source="manual"
        )

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
        print(f"[warn] {e}")


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
                async with db.execute(
                    "SELECT * FROM warns WHERE guild_id = ? AND user_id = ? ORDER BY timestamp DESC",
                    (ctx.guild.id, user.id),
                ) as cursor:
                    data = await cursor.fetchall()
            else:
                async with db.execute(
                    "SELECT * FROM warns WHERE guild_id = ? ORDER BY timestamp DESC LIMIT 50",
                    (ctx.guild.id,),
                ) as cursor:
                    data = await cursor.fetchall()

        if not data:
            return await ctx.send("No hay warns." if not user else f"{user.display_name} no tiene warns.")

        lines = []
        total = 0
        for row in data[:15]:
            total += row["weight"]
            lines.append(
                f"`{row['warn_id']}` • <@{row['user_id']}> • peso {row['weight']} • {row['reason'][:40]} • {discord_timestamp(row['timestamp'])}"
            )

        embed = discord.Embed(
            title="Lista de warns" if not user else f"Warns de {user.display_name}",
            description="\n".join(lines) or "Vacío",
            color=discord.Color.orange(),
        )
        embed.set_footer(text=f"Mostrando {len(lines)} | Puntos totales en lista: {total}")
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"Error: `{e}`")


@bot.command(name="pHash")
@commands.has_permissions(manage_messages=True)
async def phash_command(ctx: commands.Context, target: str, *, sanctions: str = ""):
    """
    Uso: .n pHash <ID|link|respuesta> <letras>
    Letras: a=Warn  b=2warns  c=Kick  d=Mute1h  e=Mute1d  f=Ban1d  g=Ban1mes  h=Ban permanente
    Ejemplo: .n pHash 123456789 abc
    """
    try:
        if not ctx.guild:
            return await ctx.send("Solo en servidor.")

        if target.casefold() == "list":
            async with db_connect() as db:
                async with db.execute(
                    "SELECT hash, sanctions, added_by, timestamp FROM phashes WHERE guild_id = ? ORDER BY timestamp DESC LIMIT 30",
                    (ctx.guild.id,),
                ) as cursor:
                    rows = await cursor.fetchall()
            if not rows:
                return await ctx.send("No hay hashes registrados.")
            lines = [f"`{r['hash']}` → `{r['sanctions']}` • <@{r['added_by']}> • {discord_timestamp(r['timestamp'])}" for r in rows]
            embed = discord.Embed(title="pHash registrados", description="\n".join(lines), color=discord.Color.purple())
            return await ctx.send(embed=embed)

        if not sanctions:
            return await ctx.send(
                "Uso: `.n pHash <ID|link|respuesta> <letras>`\n"
                "Letras disponibles:\n"
                "a = Warn\nb = 2 Warns\nc = Expulsión\nd = Mute 1h\ne = Mute 1d\n"
                "f = Baneo 1 día\ng = Baneo 1 mes\nh = Baneo permanente\n"
                "Ejemplo: `.n pHash 123456789 fh`"
            )

        target_msg, image_bytes = await get_image_from_message_ref(ctx, target)
        if not image_bytes:
            return await ctx.send(
                "No se pudo obtener la imagen.\n"
                "• Responde a un mensaje que contenga una imagen, **o**\n"
                "• Pasa el ID del mensaje, **o**\n"
                "• Pasa el link completo del mensaje de Discord."
            )

        img_hash = await make_phash(image_bytes)
        tipo, weight, label = parse_phash_sanctions(sanctions)

        async with db_connect() as db:
            try:
                await db.execute(
                    """
                    INSERT INTO phashes (hash, hash_algo, hash_bits, sanctions, added_by, guild_id, timestamp, image_blob)
                    VALUES (?, 'phash', 64, ?, ?, ?, ?, ?)
                    """,
                    (img_hash, sanctions.lower(), ctx.author.id, ctx.guild.id, now_ts(), image_bytes),
                )
                await db.commit()
            except aiosqlite.IntegrityError:
                return await ctx.send(f"El hash `{img_hash}` ya está registrado.")

        embed = discord.Embed(title="pHash añadido a la lista negra", color=discord.Color.green())
        embed.add_field(name="Hash", value=f"`{img_hash}`")
        embed.add_field(name="Sanciones", value=f"`{sanctions}` → **{label}**")
        embed.add_field(name="Registrado por", value=ctx.author.mention)
        if target_msg:
            embed.add_field(name="Mensaje origen", value=str(target_msg.id))
        await send_logs(ctx.guild, embed)

        await ctx.send(
            f"✅ Imagen registrada.\n"
            f"Hash: `{img_hash}`\n"
            f"Sanciones: `{sanctions}` → **{label}**\n"
            f"Cualquier imagen con distancia Hamming ≤ {PHASH_MAX_DISTANCE} será sancionada automáticamente."
        )
    except Exception as e:
        await ctx.send(f"Error: `{e}`")
        print(f"[pHash] {e}")


# ============================================================
# ERROR HANDLING
# ============================================================
@bot.event
async def on_command_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.CommandNotFound):
        return
    if isinstance(error, commands.MissingPermissions):
        return await ctx.send("Necesitas permiso **Gestionar mensajes**.")
    if isinstance(error, commands.MissingRequiredArgument):
        return await ctx.send("Faltan argumentos. Revisa la sintaxis.")
    await ctx.send(f"Error: `{error}`")
    print(f"[cmd error] {error}")


# ============================================================
# START
# ============================================================
keep_alive()
TOKEN = os.getenv("DISCORD_TOKEN")
if not TOKEN:
    raise RuntimeError("Falta DISCORD_TOKEN")
bot.run(TOKEN)
