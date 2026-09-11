import asyncio
import io
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
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
PHASH_HASH_SIZE = 8  # 8x8 = 64 bits = 16 hex chars
PHASH_MAX_DISTANCE = int(os.getenv("PHASH_MAX_DISTANCE", "0"))

MUTE_1H = 60 * 60
MUTE_1D = 24 * 60 * 60
BAN_3D = 3 * 24 * 60 * 60
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
                rules TEXT NOT NULL,
                timestamp REAL NOT NULL,
                weight INTEGER NOT NULL,
                source TEXT NOT NULL DEFAULT 'manual'
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS phashes (
                hash TEXT PRIMARY KEY,
                hash_algo TEXT NOT NULL DEFAULT 'phash',
                hash_bits INTEGER NOT NULL DEFAULT 64,
                rules TEXT NOT NULL,
                added_by INTEGER NOT NULL,
                guild_id INTEGER NOT NULL,
                timestamp REAL NOT NULL,
                image_blob BLOB NOT NULL
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

        await _add_column_if_missing(db, "warns", "guild_id", "INTEGER NOT NULL DEFAULT 0")
        await _add_column_if_missing(db, "warns", "source", "TEXT NOT NULL DEFAULT 'manual'")

        await _add_column_if_missing(db, "phashes", "hash_algo", "TEXT NOT NULL DEFAULT 'phash'")
        await _add_column_if_missing(db, "phashes", "hash_bits", "INTEGER NOT NULL DEFAULT 64")
        await _add_column_if_missing(db, "phashes", "guild_id", "INTEGER NOT NULL DEFAULT 0")
        await _add_column_if_missing(db, "phashes", "image_blob", "BLOB NOT NULL DEFAULT X''")

        await db.commit()


async def _add_column_if_missing(db, table: str, column: str, definition: str):
    async with db.execute(f"PRAGMA table_info({table})") as cursor:
        columns = {row[1] for row in await cursor.fetchall()}
    if column not in columns:
        await db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


# ============================================================
# GENERAL HELPERS
# ============================================================
def now_ts() -> float:
    return time.time()


def discord_timestamp(ts: float) -> str:
    return f"<t:{int(ts)}:f>"


def calculate_warn_weight(rules_str: str) -> tuple[int, Optional[str]]:
    rules = [r.strip() for r in rules_str.split(",") if r.strip()]
    weight = 0
    direct_punishment = None

    for rule in rules:
        if rule in {"1", "5"}:
            weight += 2
        elif rule == "3":
            direct_punishment = "ban_3d"
        else:
            weight += 1

    return weight, direct_punishment


def punishment_rank(kind: str) -> int:
    return {
        "none": 0,
        "mute_1h": 1,
        "mute_1d": 2,
        "kick": 3,
        "ban_1d": 4,
        "ban_3d": 5,
        "ban_31d": 6,
        "ban_permanent": 7,
    }.get(kind, 0)


def punishment_label(kind: str) -> str:
    return {
        "none": "Ninguna (solo advertencia)",
        "mute_1h": "Mute de 1 hora",
        "mute_1d": "Mute de 1 día",
        "kick": "Kick",
        "ban_1d": "Baneo de 1 día",
        "ban_3d": "Baneo de 3 días",
        "ban_31d": "Baneo de 31 días",
        "ban_permanent": "Baneo permanente",
    }.get(kind, kind)


def choose_punishment(total_points: int, direct_punishment: Optional[str]) -> str:
    selected = "none"

    if total_points >= 13:
        selected = "ban_permanent"
    elif total_points >= 10:
        selected = "ban_31d"
    elif total_points >= 7:
        selected = "ban_1d"
    elif total_points >= 5:
        selected = "kick"
    elif total_points >= 4:
        selected = "mute_1d"
    elif total_points >= 3:
        selected = "mute_1h"

    if direct_punishment and punishment_rank(direct_punishment) > punishment_rank(selected):
        selected = direct_punishment

    return selected


def punishment_expiry(kind: str, current_expiry: Optional[float] = None) -> Optional[float]:
    if kind == "ban_permanent":
        return None

    durations = {
        "mute_1h": MUTE_1H,
        "mute_1d": MUTE_1D,
        "ban_1d": BAN_1D,
        "ban_3d": BAN_3D,
        "ban_31d": BAN_31D,
    }
    if kind in durations:
        if current_expiry and current_expiry > now_ts():
            return current_expiry
        return now_ts() + durations[kind]
    return None


def has_mod_role(member: discord.Member) -> bool:
    return any(role.id in MOD_ROLES for role in getattr(member, "roles", []))


def normalize_user_query(value: str) -> str:
    return value.strip().strip("<@!>")


async def resolve_member(guild: discord.Guild, query: str) -> Optional[discord.Member]:
    query = query.strip()

    match = re.fullmatch(r"<@!?([0-9]{15,25})>", query)
    if match:
        member = guild.get_member(int(match.group(1)))
        if member:
            return member
        try:
            return await guild.fetch_member(int(match.group(1)))
        except (discord.NotFound, discord.HTTPException):
            return None

    if query.isdigit():
        user_id = int(query)
        member = guild.get_member(user_id)
        if member:
            return member
        try:
            return await guild.fetch_member(user_id)
        except (discord.NotFound, discord.HTTPException):
            return None

    lowered = query.casefold()

    for member in guild.members:
        candidates = {
            member.name.casefold(),
            member.display_name.casefold(),
            str(member).casefold(),
        }
        if lowered in candidates:
            return member

    matches = [
        member for member in guild.members
        if lowered in member.name.casefold() or lowered in member.display_name.casefold()
    ]
    return matches[0] if len(matches) == 1 else None


def rules_to_text(rules: str) -> str:
    return ", ".join(r.strip() for r in rules.split(",") if r.strip())


# ============================================================
# LOGGING
# ============================================================
async def send_logs(guild: Optional[discord.Guild], embed: discord.Embed):
    if not guild:
        return

    for channel_id in LOG_CHANNELS:
        channel = guild.get_channel(channel_id)
        if not channel:
            continue
        try:
            await channel.send(embed=embed)
        except (discord.Forbidden, discord.HTTPException):
            pass


# ============================================================
# WARN DATABASE
# ============================================================
async def generate_warn_id() -> str:
    while True:
        warn_id = secrets.token_hex(8)
        async with db_connect() as db:
            async with db.execute("SELECT 1 FROM warns WHERE warn_id = ?", (warn_id,)) as cursor:
                if not await cursor.fetchone():
                    return warn_id


async def get_user_points(guild_id: int, user_id: int) -> int:
    async with db_connect() as db:
        async with db.execute(
            "SELECT COALESCE(SUM(weight), 0) FROM warns WHERE guild_id = ? AND user_id = ?",
            (guild_id, user_id),
        ) as cursor:
            row = await cursor.fetchone()
    return int(row[0] or 0)


async def get_user_warn_count(guild_id: int, user_id: int) -> int:
    async with db_connect() as db:
        async with db.execute(
            "SELECT COUNT(*) FROM warns WHERE guild_id = ? AND user_id = ?",
            (guild_id, user_id),
        ) as cursor:
            row = await cursor.fetchone()
    return int(row[0] or 0)


async def get_user_direct_rules(guild_id: int, user_id: int) -> Optional[str]:
    async with db_connect() as db:
        async with db.execute(
            "SELECT rules FROM warns WHERE guild_id = ? AND user_id = ?",
            (guild_id, user_id),
        ) as cursor:
            rows = await cursor.fetchall()

    for row in rows:
        rules = {r.strip() for r in row[0].split(",") if r.strip()}
        if "3" in rules:
            return "ban_3d"
    return None


async def get_user_punishment_target(guild_id: int, user_id: int) -> str:
    points = await get_user_points(guild_id, user_id)
    direct = await get_user_direct_rules(guild_id, user_id)
    return choose_punishment(points, direct)


async def create_warn(
    guild: discord.Guild,
    user: discord.Member,
    moderator: discord.abc.User,
    rules: str,
    source: str = "manual",
) -> tuple[str, int, str]:
    rules = rules_to_text(rules)
    if not rules:
        raise ValueError("Debes indicar al menos una regla.")

    warn_id = await generate_warn_id()
    weight, direct = calculate_warn_weight(rules)
    ts = now_ts()

    async with db_connect() as db:
        await db.execute(
            """
            INSERT INTO warns
                (warn_id, user_id, mod_id, guild_id, rules, timestamp, weight, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (warn_id, user.id, moderator.id, guild.id, rules, ts, weight, source),
        )
        await db.commit()

    points = await get_user_points(guild.id, user.id)
    punishment = choose_punishment(points, direct if direct else await get_user_direct_rules(guild.id, user.id))
    return warn_id, points, punishment


async def delete_warn(warn_id: str) -> Optional[aiosqlite.Row]:
    async with db_connect() as db:
        async with db.execute("SELECT * FROM warns WHERE warn_id = ?", (warn_id,)) as cursor:
            row = await cursor.fetchone()
        if not row:
            return None
        await db.execute("DELETE FROM warns WHERE warn_id = ?", (warn_id,))
        await db.commit()
        return row


async def update_warn_rules(warn_id: str, new_rules: str) -> Optional[aiosqlite.Row]:
    new_rules = rules_to_text(new_rules)
    if not new_rules:
        return None

    new_weight, _ = calculate_warn_weight(new_rules)

    async with db_connect() as db:
        async with db.execute("SELECT * FROM warns WHERE warn_id = ?", (warn_id,)) as cursor:
            old_row = await cursor.fetchone()
        if not old_row:
            return None

        await db.execute(
            "UPDATE warns SET rules = ?, weight = ? WHERE warn_id = ?",
            (new_rules, new_weight, warn_id),
        )
        await db.commit()
        return old_row


# ============================================================
# PERSISTENT SANCTIONS
# ============================================================
async def get_active_sanction(guild_id: int, user_id: int) -> Optional[aiosqlite.Row]:
    async with db_connect() as db:
        async with db.execute(
            "SELECT * FROM sanctions WHERE guild_id = ? AND user_id = ?",
            (guild_id, user_id),
        ) as cursor:
            return await cursor.fetchone()


async def save_sanction(
    guild_id: int,
    user_id: int,
    sanction_type: str,
    expires_at: Optional[float],
    reason: str,
):
    ts = now_ts()
    async with db_connect() as db:
        await db.execute(
            """
            INSERT INTO sanctions(user_id, guild_id, sanction_type, expires_at, reason, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                guild_id = excluded.guild_id,
                sanction_type = excluded.sanction_type,
                expires_at = excluded.expires_at,
                reason = excluded.reason,
                updated_at = excluded.updated_at
            """,
            (user_id, guild_id, sanction_type, expires_at, reason, ts, ts),
        )
        await db.commit()


async def clear_sanction(user_id: int):
    async with db_connect() as db:
        await db.execute("DELETE FROM sanctions WHERE user_id = ?", (user_id,))
        await db.commit()

    for key, task in list(punishment_tasks.items()):
        if key[1] == user_id:
            if not task.done():
                task.cancel()
            punishment_tasks.pop(key, None)


async def remove_bot_sanction_effect(guild: discord.Guild, user_id: int, sanction_type: str):
    if sanction_type.startswith("mute"):
        member = guild.get_member(user_id)
        if member:
            role = guild.get_role(MUTE_ROLE_ID)
            if role and role in member.roles:
                try:
                    await member.remove_roles(role, reason="Sanción de moderación del bot finalizada/recalculada")
                except discord.HTTPException:
                    pass

    elif sanction_type.startswith("ban_"):
        try:
            user = await bot.fetch_user(user_id)
            await guild.unban(user, reason="Sanción temporal del bot finalizada/recalculada")
        except (discord.NotFound, discord.HTTPException, discord.Forbidden):
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
            delay = max(0, expires_at - now_ts())
            await asyncio.sleep(delay)

            current = await get_active_sanction(guild.id, user_id)
            if not current:
                return
            if current["sanction_type"] != sanction_type:
                return
            if current["expires_at"] is not None and current["expires_at"] > now_ts() + 1:
                return

            await remove_bot_sanction_effect(guild, user_id, sanction_type)
            await clear_sanction(user_id)

            embed = discord.Embed(
                title="Sanción finalizada",
                color=discord.Color.green(),
            )
            embed.add_field(name="Usuario", value=f"<@{user_id}>")
            embed.add_field(name="Sanción", value=punishment_label(sanction_type))
            embed.add_field(name="Motivo", value="Tiempo de la sanción expirado")
            await send_logs(guild, embed)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print(f"[sanction timer] {guild.id}/{user_id}: {exc}")

    punishment_tasks[key] = bot.loop.create_task(worker())


async def apply_or_update_punishment(guild: discord.Guild, user: discord.Member, desired: str, reason: str) -> str:
    current = await get_active_sanction(guild.id, user.id)
    current_type = current["sanction_type"] if current else "none"

    if current and punishment_rank(current_type) >= punishment_rank(desired):
        if current_type != "none":
            await schedule_sanction_expiry(
                guild,
                user.id,
                current_type,
                current["expires_at"],
            )
            return punishment_label(current_type)

    if current and current_type != desired:
        await remove_bot_sanction_effect(guild, user.id, current_type)

    if desired == "none":
        await clear_sanction(user.id)
        return punishment_label(desired)

    expiry = punishment_expiry(desired, current["expires_at"] if current and current_type == desired else None)

    if desired.startswith("mute"):
        role = guild.get_role(MUTE_ROLE_ID)
        if not role:
            return "Mute solicitado, pero el rol de mute no existe"
        try:
            await user.add_roles(role, reason=reason)
        except discord.Forbidden:
            return "No se pudo aplicar el mute: el bot no puede asignar el rol"
        except discord.HTTPException:
            return "No se pudo aplicar el mute por un error de Discord"

    elif desired.startswith("ban_"):
        try:
            await guild.ban(user, reason=reason, delete_message_days=0)
        except discord.Forbidden:
            return "No se pudo aplicar el baneo: faltan permisos"
        except discord.HTTPException:
            return "No se pudo aplicar el baneo por un error de Discord"

    elif desired == "kick":
        try:
            await user.kick(reason=reason)
        except discord.Forbidden:
            return "No se pudo aplicar el kick: faltan permisos"
        except discord.HTTPException:
            return "No se pudo aplicar el kick por un error de Discord"

    await save_sanction(guild.id, user.id, desired, expiry, reason)
    await schedule_sanction_expiry(guild, user.id, desired, expiry)
    return punishment_label(desired)


async def reconcile_user_sanction(guild: discord.Guild, user_id: int) -> str:
    target = await get_user_punishment_target(guild.id, user_id)
    current = await get_active_sanction(guild.id, user_id)

    if target == "none":
        if current:
            await remove_bot_sanction_effect(guild, user_id, current["sanction_type"])
            await clear_sanction(user_id)
            return "Sanción retirada tras recalcular warns"
        return "Ninguna"

    member = guild.get_member(user_id)
    if not member:
        if current and punishment_rank(current["sanction_type"]) >= punishment_rank(target):
            return punishment_label(current["sanction_type"])
        return f"Debería aplicarse: {punishment_label(target)} (usuario no presente)"

    return await apply_or_update_punishment(
        guild,
        member,
        target,
        reason="Recalculo automático de sanción por edición/eliminación de warn",
    )


async def restore_active_sanctions():
    async with db_connect() as db:
        async with db.execute("SELECT * FROM sanctions") as cursor:
            rows = await cursor.fetchall()

    for row in rows:
        guild = bot.get_guild(row["guild_id"])
        if not guild:
            continue

        sanction_type = row["sanction_type"]
        expires_at = row["expires_at"]
        user_id = row["user_id"]

        try:
            if sanction_type.startswith("mute"):
                member = guild.get_member(user_id)
                role = guild.get_role(MUTE_ROLE_ID)
                if member and role and role not in member.roles:
                    await member.add_roles(role, reason="Restauración de sanción temporal tras reinicio")

            elif sanction_type.startswith("ban_"):
                try:
                    await guild.fetch_ban(await bot.fetch_user(user_id))
                except discord.NotFound:
                    try:
                        user = await bot.fetch_user(user_id)
                        await guild.ban(user, reason="Restauración de sanción tras reinicio")
                    except discord.HTTPException:
                        pass

            if sanction_type != "ban_permanent" and expires_at is not None:
                if expires_at <= now_ts():
                    await remove_bot_sanction_effect(guild, user_id, sanction_type)
                    await clear_sanction(user_id)
                else:
                    await schedule_sanction_expiry(guild, user_id, sanction_type, expires_at)
        except Exception as exc:
            print(f"[restore sanction] {guild.id}/{user_id}: {exc}")


# ============================================================
# EMBEDS / VIEWS
# ============================================================
class WarnModal(discord.ui.Modal, title="Editar Warn"):
    def __init__(self, warn_id: str, current_rules: str):
        super().__init__(timeout=180)
        self.warn_id = warn_id
        self.rules = discord.ui.TextInput(
            label="Nuevas reglas",
            default=current_rules,
            placeholder="Ej.: 1, 5",
            required=True,
            max_length=100,
        )
        self.add_item(self.rules)

    async def on_submit(self, interaction: discord.Interaction):
        if not isinstance(interaction.user, discord.Member) or not has_mod_role(interaction.user):
            return await interaction.response.send_message("No tienes permisos para esta acción.", ephemeral=True)

        old_row = await update_warn_rules(self.warn_id, self.rules.value)
        if not old_row:
            return await interaction.response.send_message("Warn no encontrado.", ephemeral=True)

        guild = interaction.guild
        if not guild:
            return await interaction.response.send_message("Este comando solo funciona en un servidor.", ephemeral=True)

        new_rules = rules_to_text(self.rules.value)
        new_weight, _ = calculate_warn_weight(new_rules)
        new_points = await get_user_points(guild.id, old_row["user_id"])
        new_punishment = await reconcile_user_sanction(guild, old_row["user_id"])

        embed = discord.Embed(title="Warn editado", color=discord.Color.blue())
        embed.add_field(name="ID", value=f"`{self.warn_id}`")
        embed.add_field(name="Usuario", value=f"<@{old_row['user_id']}>")
        embed.add_field(name="Reglas anteriores", value=old_row["rules"])
        embed.add_field(name="Nuevas reglas", value=f"{new_rules} (Peso: {new_weight})")
        embed.add_field(name="Puntos totales", value=str(new_points))
        embed.add_field(name="Estado de sanción", value=new_punishment)
        embed.add_field(name="Moderador", value=interaction.user.mention)
        await send_logs(guild, embed)

        await interaction.response.send_message(
            f"Warn `{self.warn_id}` editado. Puntos actuales: **{new_points}**. Estado: **{new_punishment}**.",
            ephemeral=True,
        )


class InputIDModal(discord.ui.Modal):
    def __init__(self, action: str):
        title = "Editar Warn" if action == "edit" else "Borrar Warn"
        super().__init__(title=title, timeout=180)
        self.action = action
        self.warn_id = discord.ui.TextInput(
            label="Warn ID (16 caracteres hex)",
            placeholder="Ej.: a1b2c3d4e5f60708",
            min_length=16,
            max_length=16,
            required=True,
        )
        self.add_item(self.warn_id)

    async def on_submit(self, interaction: discord.Interaction):
        if not isinstance(interaction.user, discord.Member) or not has_mod_role(interaction.user):
            return await interaction.response.send_message("No tienes permisos para esta acción.", ephemeral=True)

        wid = self.warn_id.value.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{16}", wid):
            return await interaction.response.send_message("El ID debe tener exactamente 16 caracteres hexadecimales.", ephemeral=True)

        async with db_connect() as db:
            async with db.execute("SELECT * FROM warns WHERE warn_id = ?", (wid,)) as cursor:
                row = await cursor.fetchone()

        if not row:
            return await interaction.response.send_message("Warn no encontrado.", ephemeral=True)

        if self.action == "edit":
            return await interaction.response.send_modal(WarnModal(wid, row["rules"]))

        deleted = await delete_warn(wid)
        if not deleted:
            return await interaction.response.send_message("Warn no encontrado.", ephemeral=True)

        guild = interaction.guild
        if guild:
            points = await get_user_points(guild.id, deleted["user_id"])
            state = await reconcile_user_sanction(guild, deleted["user_id"])

            embed = discord.Embed(title="Warn eliminado", color=discord.Color.red())
            embed.add_field(name="ID eliminado", value=f"`{wid}`")
            embed.add_field(name="Usuario", value=f"<@{deleted['user_id']}>")
            embed.add_field(name="Reglas", value=deleted["rules"])
            embed.add_field(name="Peso", value=str(deleted["weight"]))
            embed.add_field(name="Puntos restantes", value=str(points))
            embed.add_field(name="Estado de sanción", value=state)
            embed.add_field(name="Moderador", value=interaction.user.mention)
            await send_logs(guild, embed)

        await interaction.response.send_message(f"Warn `{wid}` eliminado.", ephemeral=True)


class WarnPaginationView(discord.ui.View):
    def __init__(self, data: list[aiosqlite.Row], is_global: bool, user: Optional[discord.Member], page: int = 1):
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

        prev_button = discord.ui.Button(label="Anterior", style=discord.ButtonStyle.secondary, disabled=self.page <= 1)
        next_button = discord.ui.Button(label="Siguiente", style=discord.ButtonStyle.secondary, disabled=self.page >= self.total_pages)
        edit_button = discord.ui.Button(label="Editar Warn", style=discord.ButtonStyle.primary)
        delete_button = discord.ui.Button(label="Borrar Warn", style=discord.ButtonStyle.danger)

        prev_button.callback = self.prev_page
        next_button.callback = self.next_page
        edit_button.callback = self.edit_warn
        delete_button.callback = self.delete_warn

        self.add_item(prev_button)
        self.add_item(next_button)
        self.add_item(edit_button)
        self.add_item(delete_button)

    def generate_embed(self) -> discord.Embed:
        start = (self.page - 1) * self.per_page
        page_data = self.data[start:start + self.per_page]

        title = "Lista global de warns" if self.is_global else f"Warns de {self.user.display_name if self.user else 'usuario'}"
        total_points = sum(int(row["weight"]) for row in self.data)

        embed = discord.Embed(
            title=title,
            color=discord.Color.orange(),
            description=(
                f"**Puntos acumulados:** {total_points}\n"
                f"**Registros de warn:** {len(self.data)}"
            ),
        )
        embed.set_footer(text=f"Página {self.page} de {self.total_pages} | Total de registros: {len(self.data)}")

        for row in page_data:
            source = "Automático pHash" if row["source"] == "phash" else "Manual"
            embed.add_field(
                name=f"ID: `{row['warn_id']}`",
                value=(
                    f"**Usuario:** <@{row['user_id']}>\n"
                    f"**Mod:** <@{row['mod_id']}>\n"
                    f"**Reglas:** {row['rules']} (Peso: {row['weight']})\n"
                    f"**Origen:** {source}\n"
                    f"**Fecha:** {discord_timestamp(row['timestamp'])}"
                ),
                inline=False,
            )
        return embed

    async def check_mod(self, interaction: discord.Interaction) -> bool:
        if not isinstance(interaction.user, discord.Member) or not has_mod_role(interaction.user):
            await interaction.response.send_message("No tienes permisos para esta acción.", ephemeral=True)
            return False
        return True

    async def prev_page(self, interaction: discord.Interaction):
        if not await self.check_mod_navigation(interaction):
            return
        if self.page > 1:
            self.page -= 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.generate_embed(), view=self)

    async def next_page(self, interaction: discord.Interaction):
        if not await self.check_mod_navigation(interaction):
            return
        if self.page < self.total_pages:
            self.page += 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.generate_embed(), view=self)

    async def check_mod_navigation(self, interaction: discord.Interaction) -> bool:
        if not isinstance(interaction.user, discord.Member):
            await interaction.response.send_message("Solo miembros del servidor pueden usar este botón.", ephemeral=True)
            return False
        if not interaction.user.guild_permissions.manage_messages and not has_mod_role(interaction.user):
            await interaction.response.send_message("No tienes permisos para esta acción.", ephemeral=True)
            return False
        return True

    async def edit_warn(self, interaction: discord.Interaction):
        if not await self.check_mod(interaction):
            return
        await interaction.response.send_modal(InputIDModal("edit"))

    async def delete_warn(self, interaction: discord.Interaction):
        if not await self.check_mod(interaction):
            return
        await interaction.response.send_modal(InputIDModal("delete"))


class PHashPaginationView(discord.ui.View):
    def __init__(self, data: list[aiosqlite.Row], page: int = 1):
        super().__init__(timeout=300)
        self.data = data
        self.page = page
        self.per_page = 10
        self.total_pages = max(1, (len(data) + self.per_page - 1) // self.per_page)
        self.update_buttons()

    def update_buttons(self):
        self.clear_items()
        prev_button = discord.ui.Button(label="Anterior", style=discord.ButtonStyle.secondary, disabled=self.page <= 1)
        next_button = discord.ui.Button(label="Siguiente", style=discord.ButtonStyle.secondary, disabled=self.page >= self.total_pages)
        prev_button.callback = self.prev_page
        next_button.callback = self.next_page
        self.add_item(prev_button)
        self.add_item(next_button)

    def generate_embed(self) -> discord.Embed:
        start = (self.page - 1) * self.per_page
        page_data = self.data[start:start + self.per_page]

        embed = discord.Embed(
            title="Lista de pHash registrados",
            color=discord.Color.purple(),
            description=f"**Total de hashes:** {len(self.data)}",
        )
        embed.set_footer(text=f"Página {self.page} de {self.total_pages} | Total: {len(self.data)} hashes")

        for row in page_data:
            embed.add_field(
                name=f"`{row['hash']}`",
                value=(
                    f"**Algoritmo:** {row['hash_algo']} ({row['hash_bits']} bits)\n"
                    f"**Reglas:** {row['rules']}\n"
                    f"**Mod:** <@{row['added_by']}>\n"
                    f"**Fecha:** {discord_timestamp(row['timestamp'])}"
                ),
                inline=False,
            )
        return embed

    async def check_viewer(self, interaction: discord.Interaction) -> bool:
        if not isinstance(interaction.user, discord.Member):
            return False
        if not interaction.user.guild_permissions.manage_messages and not has_mod_role(interaction.user):
            await interaction.response.send_message("No tienes permisos para esta acción.", ephemeral=True)
            return False
        return True

    async def prev_page(self, interaction: discord.Interaction):
        if not await self.check_viewer(interaction):
            return
        if self.page > 1:
            self.page -= 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.generate_embed(), view=self)

    async def next_page(self, interaction: discord.Interaction):
        if not await self.check_viewer(interaction):
            return
        if self.page < self.total_pages:
            self.page += 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.generate_embed(), view=self)


# ============================================================
# IMAGE / PHASH
# ============================================================
async def download_image_from_message(ctx: commands.Context, message_ref: str) -> tuple[Optional[discord.Message], Optional[bytes]]:
    target_msg = None

    if ctx.message.reference and ctx.message.reference.message_id:
        try:
            target_msg = await ctx.channel.fetch_message(ctx.message.reference.message_id)
        except discord.HTTPException:
            return None, None

    elif message_ref.lower().startswith("http"):
        match = re.search(r"channels/(\d+)/(\d+)", message_ref)
        if match:
            channel_id = int(match.group(1))
            message_id = int(match.group(2))
            channel = bot.get_channel(channel_id)
            if not channel:
                try:
                    channel = await bot.fetch_channel(channel_id)
                except discord.HTTPException:
                    return None, None
            try:
                target_msg = await channel.fetch_message(message_id)
            except (discord.NotFound, discord.HTTPException):
                return None, None
        else:
            return None, None

    elif message_ref.isdigit():
        try:
            target_msg = await ctx.channel.fetch_message(int(message_ref))
        except (discord.NotFound, discord.HTTPException):
            return None, None

    if not target_msg or not target_msg.attachments:
        return target_msg, None

    attachment = next(
        (
            a for a in target_msg.attachments
            if (a.content_type and a.content_type.startswith("image/")) or
               a.filename.lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"))
        ),
        None,
    )
    if not attachment:
        return target_msg, None

    if attachment.size > MAX_IMAGE_BYTES:
        return target_msg, None

    timeout = aiohttp.ClientTimeout(total=20)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(attachment.url) as resp:
                if resp.status != 200:
                    return target_msg, None
                data = await resp.read()
                if len(data) > MAX_IMAGE_BYTES:
                    return target_msg, None
                return target_msg, data
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return target_msg, None


async def make_phash(image_bytes: bytes) -> tuple[str, int]:
    def _hash() -> tuple[str, int]:
        try:
            with Image.open(io.BytesIO(image_bytes)) as image:
                image.load()
                h = imagehash.phash(image, hash_size=PHASH_HASH_SIZE)
                return str(h), PHASH_HASH_SIZE * PHASH_HASH_SIZE
        except (UnidentifiedImageError, OSError) as exc:
            raise ValueError("El archivo no es una imagen válida.") from exc

    return await asyncio.to_thread(_hash)


def hamming_distance(hex_a: str, hex_b: str) -> int:
    try:
        return (int(hex_a, 16) ^ int(hex_b, 16)).bit_count()
    except ValueError:
        return 10**9


async def find_matching_phash(guild_id: int, current_hash: str) -> Optional[aiosqlite.Row]:
    async with db_connect() as db:
        async with db.execute(
            "SELECT * FROM phashes WHERE guild_id = ? ORDER BY timestamp DESC",
            (guild_id,),
        ) as cursor:
            rows = await cursor.fetchall()

    best = None
    best_distance = None
    for row in rows:
        distance = hamming_distance(current_hash, row["hash"])
        if distance <= PHASH_MAX_DISTANCE and (best_distance is None or distance < best_distance):
            best = row
            best_distance = distance
    return best


# ============================================================
# EVENTS
# ============================================================
@bot.event
async def on_ready():
    await init_db()
    await restore_active_sanctions()
    print(f"Bot conectado como {bot.user} | pHash={PHASH_HASH_SIZE * PHASH_HASH_SIZE} bits | distancia={PHASH_MAX_DISTANCE}")


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        await bot.process_commands(message)
        return

    if message.attachments:
        image_attachment = next(
            (
                a for a in message.attachments
                if (a.content_type and a.content_type.startswith("image/")) or
                   a.filename.lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"))
            ),
            None,
        )
        if image_attachment and image_attachment.size <= MAX_IMAGE_BYTES:
            async with phash_scan_lock:
                try:
                    timeout = aiohttp.ClientTimeout(total=20)
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.get(image_attachment.url) as resp:
                            if resp.status == 200:
                                blob = await resp.read()
                                if len(blob) <= MAX_IMAGE_BYTES:
                                    current_hash, _ = await make_phash(blob)
                                    match = await find_matching_phash(message.guild.id, current_hash)
                                    if match:
                                        warn_id, points, desired = await create_warn(
                                            message.guild,
                                            message.author,
                                            bot.user,
                                            match["rules"],
                                            source="phash",
                                        )
                                        action = await apply_or_update_punishment(
                                            message.guild,
                                            message.author,
                                            desired,
                                            reason=f"Coincidencia pHash {match['hash']} | Warn {warn_id}",
                                        )

                                        embed = discord.Embed(
                                            title="Coincidencia pHash detectada",
                                            color=discord.Color.red(),
                                        )
                                        embed.add_field(name="Usuario", value=f"{message.author.mention} ({message.author.id})")
                                        embed.add_field(name="pHash detectado", value=f"`{current_hash}`")
                                        embed.add_field(name="Hash registrado", value=f"`{match['hash']}`")
                                        embed.add_field(name="Distancia", value=str(hamming_distance(current_hash, match["hash"])))
                                        embed.add_field(name="Reglas", value=match["rules"])
                                        embed.add_field(name="Warn ID", value=f"`{warn_id}`")
                                        embed.add_field(name="Puntos acumulados", value=str(points))
                                        embed.add_field(name="Acción", value=action)
                                        await send_logs(message.guild, embed)
                except Exception as exc:
                    print(f"[pHash scan] {message.guild.id}/{message.id}: {exc}")

    await bot.process_commands(message)


# ============================================================
# COMMANDS
# ============================================================
@bot.command(name="warn")
@commands.has_permissions(manage_messages=True)
async def warn_command(ctx: commands.Context, user_query: str, *, rules: str):
    try:
        if not ctx.guild:
            return await ctx.send("Este comando solo funciona en un servidor.")

        user = await resolve_member(ctx.guild, user_query)
        if not user:
            return await ctx.send("No pude encontrar ese usuario. Usa ID, mención o nombre de usuario.")

        warn_id, points, desired = await create_warn(ctx.guild, user, ctx.author, rules)

        action = await apply_or_update_punishment(
            ctx.guild,
            user,
            desired,
            reason=f"Warn {warn_id} | Regla(s): {rules}",
        )

        warn_count = await get_user_warn_count(ctx.guild.id, user.id)

        embed = discord.Embed(title="Usuario advertido", color=discord.Color.red())
        embed.add_field(name="Usuario", value=f"{user.mention} ({user.id})")
        embed.add_field(name="Moderador", value=ctx.author.mention)
        embed.add_field(name="Regla(s)", value=rules_to_text(rules))
        embed.add_field(name="ID del Warn", value=f"`{warn_id}`")
        embed.add_field(name="Peso de este Warn", value=str(calculate_warn_weight(rules)[0]))
        embed.add_field(name="Warns registrados", value=str(warn_count))
        embed.add_field(name="Puntos acumulados", value=str(points))
        embed.add_field(name="Acción tomada", value=action)
        await send_logs(ctx.guild, embed)

        await ctx.send(
            f"⚠️ {user.mention} ha recibido un warn. "
            f"ID: `{warn_id}` | Puntos: **{points}** | Acción: **{action}**"
        )
    except Exception as e:
        await ctx.send(f"Error al aplicar warn: `{e}`")
        print(f"[warn error] {e}")


@bot.command(name="warns")
@commands.has_permissions(manage_messages=True)
async def warns_command(ctx: commands.Context, subcommand: str = "", *, user_query: str = ""):
    try:
        if not ctx.guild:
            return await ctx.send("Este comando solo funciona en un servidor.")

        if subcommand.casefold() != "list":
            return await ctx.send("Uso: `.n warns list` o `.n warns list <usuario>`")

        user = None
        if user_query.strip():
            user = await resolve_member(ctx.guild, user_query.strip())
            if not user:
                return await ctx.send("No pude encontrar ese usuario. Usa ID, mención o nombre de usuario.")

        async with db_connect() as db:
            if user:
                async with db.execute(
                    "SELECT * FROM warns WHERE guild_id = ? AND user_id = ? ORDER BY timestamp DESC",
                    (ctx.guild.id, user.id),
                ) as cursor:
                    data = await cursor.fetchall()
            else:
                async with db.execute(
                    "SELECT * FROM warns WHERE guild_id = ? ORDER BY timestamp DESC",
                    (ctx.guild.id,),
                ) as cursor:
                    data = await cursor.fetchall()

        if not data:
            return await ctx.send(
                "No hay warns registrados en el servidor."
                if not user else f"El usuario {user.display_name} no tiene warns."
            )

        view = WarnPaginationView(data, is_global=user is None, user=user)
        await ctx.send(embed=view.generate_embed(), view=view)
    except Exception as e:
        await ctx.send(f"Error al listar warns: `{e}`")
        print(f"[warns error] {e}")


@bot.command(name="pHash")
@commands.has_permissions(manage_messages=True)
async def phash_command(ctx: commands.Context, target: str, *, rules: str = ""):
    try:
        if not ctx.guild:
            return await ctx.send("Este comando solo funciona en un servidor.")

        if target.casefold() == "list":
            async with db_connect() as db:
                async with db.execute(
                    "SELECT * FROM phashes WHERE guild_id = ? ORDER BY timestamp DESC",
                    (ctx.guild.id,),
                ) as cursor:
                    data = await cursor.fetchall()

            if not data:
                return await ctx.send("La base de datos de hashes está vacía.")

            view = PHashPaginationView(data)
            return await ctx.send(embed=view.generate_embed(), view=view)

        if not rules:
            return await ctx.send("Uso: `.n pHash <mensaje|ID|link|respuesta> <reglas>`")

        target_msg, image_bytes = await download_image_from_message(ctx, target)
        if not image_bytes:
            return await ctx.send(
                "No se pudo obtener una imagen. Responde a un mensaje con imagen, usa el ID del mensaje "
                "o un link de Discord válido que contenga una imagen."
            )

        img_hash, bits = await make_phash(image_bytes)

        rules = rules_to_text(rules)
        async with db_connect() as db:
            try:
                await db.execute(
                    """
                    INSERT INTO phashes
                        (hash, hash_algo, hash_bits, rules, added_by, guild_id, timestamp, image_blob)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (img_hash, "phash", bits, rules, ctx.author.id, ctx.guild.id, now_ts(), image_bytes),
                )
                await db.commit()
            except aiosqlite.IntegrityError:
                return await ctx.send(f"⚠️ El hash `{img_hash}` ya existe en la base de datos.")

        embed = discord.Embed(title="pHash registrado", color=discord.Color.green())
        embed.add_field(name="Hash", value=f"`{img_hash}`")
        embed.add_field(name="Precisión", value=f"{bits} bits ({PHASH_HASH_SIZE}×{PHASH_HASH_SIZE})")
        embed.add_field(name="Reglas asociadas", value=rules)
        embed.add_field(name="Registrado por", value=ctx.author.mention)
        if target_msg:
            embed.add_field(name="Mensaje origen", value=str(target_msg.id))
        await send_logs(ctx.guild, embed)

        await ctx.send(
            f"✅ Imagen registrada con pHash `{img_hash}` ({bits} bits). "
            f"Reglas asociadas: `{rules}`. El BLOB de la imagen quedó guardado en la base de datos."
        )
    except Exception as e:
        await ctx.send(f"Error en pHash: `{e}`")
        print(f"[pHash error] {e}")


# ============================================================
# ERROR HANDLING
# ============================================================
@bot.event
async def on_command_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.CommandNotFound):
        return
    if isinstance(error, commands.MissingPermissions):
        return await ctx.send("No tienes el permiso `Gestionar mensajes` para usar este comando.")
    if isinstance(error, commands.MissingRequiredArgument):
        return await ctx.send("Faltan argumentos. Revisa la sintaxis del comando.")
    if isinstance(error, commands.BadArgument):
        return await ctx.send("Uno de los argumentos no es válido.")

    await ctx.send(f"Ocurrió un error inesperado: `{error}`")
    print(f"[command error] {ctx.command}: {error}")


# ============================================================
# START
# ============================================================
keep_alive()
TOKEN = os.getenv("DISCORD_TOKEN")
if not TOKEN:
    raise RuntimeError("Falta la variable de entorno DISCORD_TOKEN")

bot.run(TOKEN)
