import discord
from discord.ext import commands, tasks
import sqlite3
import time
import io
import requests
import os
from PIL import Image, ImageOps
import imagehash
from datetime import datetime, timedelta, timezone

# --- CONFIGURACIÓN DE PARÁMETROS ---
PREFIX = ".n"
ROLE_MUTE_1H_ID = 1483621610819948635
CHANNEL_LOGS_ID = 1541275389450649680
HAMMING_THRESHOLD = 8  # Umbral de similitud para pHash (0 = idéntica, <10 = casi idéntica/modificada)

intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix=PREFIX, intents=intents)

# Base de Datos SQLite local
conn = sqlite3.connect("bot_database.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS warns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    mod_id INTEGER,
    rules TEXT,
    amount INTEGER,
    timestamp REAL
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS phash_sanctions (
    phash_raw BLOB PRIMARY KEY,
    rules TEXT
)
""")
conn.commit()

# --- FUNCIONES DE PHASH INVARIANTE A INVERSIÓN/ESPEJO ---

def compute_canonical_phash(image: Image.Image) -> imagehash.ImageHash:
    """
    Calcula el pHash canónico probando transformaciones básicas (normal, espejo horizontal,
    espejo vertical, rotaciones) y devolviendo el valor mínimo como firma representativa.
    Esto permite que la imagen sea detectada aunque el usuario la invierta.
    """
    img_gray = image.convert('L')
    hashes = [
        imagehash.phash(img_gray),
        imagehash.phash(ImageOps.mirror(img_gray)),
        imagehash.phash(ImageOps.flip(img_gray)),
        imagehash.phash(img_gray.rotate(180))
    ]
    # Se devuelve el menor lexicográficamente como hash canónico invariable a inversión
    return min(hashes, key=lambda h: str(h))

def hash_to_bytes(hash_obj: imagehash.ImageHash) -> bytes:
    # Convierte el objeto ImageHash a 8 bytes crudos (64 bits)
    return int(str(hash_obj), 16).to_bytes(8, byteorder='big')

def bytes_to_hash(raw_bytes: bytes) -> imagehash.ImageHash:
    # Convierte 8 bytes crudos de vuelta a un ImageHash
    hex_str = raw_bytes.hex()
    return imagehash.hex_to_hash(hex_str)

# --- RESPALDO / SUBIDA DE ARCHIVOS A LOGS ---

async def backup_db_to_channel(guild: discord.Guild, reason_msg: str):
    """Sube el archivo de la base de datos / registro de pHash en bytes al canal de logs."""
    channel = guild.get_channel(CHANNEL_LOGS_ID)
    if channel:
        conn.commit()
        utc_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        with open("bot_database.db", "rb") as f:
            db_file = discord.File(f, filename=f"bot_database_{int(time.time())}.db")
            await channel.send(
                content=f"📦 **Respaldo Automático de Base de Datos / pHash Registros**\nMotivo: {reason_msg}\nFecha: `{utc_now}`",
                file=db_file
            )

# --- MANEJO DE WARNS Y SANCIONES ---

def get_total_warns(user_id: int) -> int:
    now = time.time()
    two_months_ago = now - (60 * 86400)
    cursor.execute("SELECT SUM(amount) FROM warns WHERE user_id = ? AND timestamp > ?", (user_id, two_months_ago))
    res = cursor.fetchone()[0]
    return res if res else 0

async def apply_sanctions(guild: discord.Guild, member: discord.Member, total_warns: int, reason: str):
    if total_warns >= 13:
        await guild.ban(member, reason=f"Acumulación de {total_warns} warns (Ban Perm)", delete_message_days=0)
    elif total_warns >= 10:
        await guild.ban(member, reason=f"Acumulación de {total_warns} warns (Ban 30d)", delete_message_days=0)
    elif total_warns >= 7:
        await guild.ban(member, reason=f"Acumulación de {total_warns} warns (Ban 1d)", delete_message_days=0)
    elif total_warns >= 5:
        await guild.kick(member, reason=f"Acumulación de {total_warns} warns")
    elif total_warns >= 4:
        await member.timeout(timedelta(days=1), reason=f"Acumulación de {total_warns} warns")
    elif total_warns >= 3:
        role = guild.get_role(ROLE_MUTE_1H_ID)
        if role:
            await member.add_roles(role, reason="Mute 1h por 3 warns")
        await member.timeout(timedelta(hours=1), reason="Mute 1h por 3 warns")

async def log_admin_action(guild: discord.Guild, title: str, description: str, admin: discord.User):
    channel = guild.get_channel(CHANNEL_LOGS_ID)
    if channel:
        utc_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        embed = discord.Embed(title=title, description=description, color=discord.Color.orange())
        embed.add_field(name="Administrador", value=admin.mention, inline=True)
        embed.add_field(name="Fecha (UTC 0)", value=f"`{utc_now}`", inline=True)
        await channel.send(embed=embed)

# --- MONITOREO DE MENSAJES CON IMÁGENES ---

@bot.event
async def on_message(message):
    if message.author.bot or not message.guild:
        return

    # Escanear imágenes adjuntas para comprobar contra la BD de pHash
    if message.attachments:
        for attachment in message.attachments:
            if any(attachment.filename.lower().endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.webp']):
                try:
                    resp = requests.get(attachment.url, timeout=5)
                    img = Image.open(io.BytesIO(resp.content))
                    
                    img_hash = compute_canonical_phash(img)
                    
                    # Buscar coincidencias en la BD
                    cursor.execute("SELECT phash_raw, rules FROM phash_sanctions")
                    rows = cursor.fetchall()
                    
                    matched_rules = []
                    for raw_b, rules in rows:
                        db_hash = bytes_to_hash(raw_b)
                        # Comprobar distancia de Hamming entre firmas
                        if (img_hash - db_hash) <= HAMMING_THRESHOLD:
                            matched_rules.append(rules)

                    if matched_rules:
                        rules_str = ", ".join(matched_rules)
                        await message.delete()
                        
                        # Registrar warn automático por imagen prohibida
                        cursor.execute(
                            "INSERT INTO warns (user_id, mod_id, rules, amount, timestamp) VALUES (?, ?, ?, ?, ?)",
                            (message.author.id, bot.user.id, f"Imagen sancionada (Reglas: {rules_str})", 2, time.time())
                        )
                        conn.commit()
                        
                        total = get_total_warns(message.author.id)
                        await message.channel.send(
                            f"⚠️ {message.author.mention}, la imagen enviada infringe la(s) regla(s): **{rules_str}**. Se te han aplicado 2 warns.",
                            delete_after=10
                        )
                        await apply_sanctions(message.guild, message.author, total, f"Imagen prohibida (Reglas: {rules_str})")
                        await backup_db_to_channel(message.guild, f"Sanción automática por imagen pHash enviada por {message.author}")
                        break
                except Exception as e:
                    print(f"Error procesando imagen pHash: {e}")

    await bot.process_commands(message)

# --- COMANDOS ---

@bot.command(name="addphash")
@commands.has_permissions(administrator=True)
async def add_phash(ctx, *, reglas: str):
    """Agrega una imagen adjunta al mensaje a la lista de sancionadas pHash."""
    if not ctx.message.attachments:
        return await ctx.send("Debes adjuntar la imagen que deseas registrar en el sistema pHash.")

    attachment = ctx.message.attachments[0]
    try:
        resp = requests.get(attachment.url, timeout=5)
        img = Image.open(io.BytesIO(resp.content))
        
        canonical_hash = compute_canonical_phash(img)
        raw_bytes = hash_to_bytes(canonical_hash)

        cursor.execute("INSERT OR REPLACE INTO phash_sanctions (phash_raw, rules) VALUES (?, ?)", 
                       (sqlite3.Binary(raw_bytes), reglas))
        conn.commit()

        await ctx.send(f"✅ Imagen registrada exitosamente.\n**pHash (Hex):** `{canonical_hash}`\n**Bytes crudos:** `{len(raw_bytes)} bytes`\n**Reglas:** {reglas}")
        await backup_db_to_channel(ctx.guild, f"Nuevo pHash registrado por {ctx.author}")

    except Exception as e:
        await ctx.send(f"Error al procesar la imagen: {e}")

@bot.command(name="sancionar")
@commands.has_permissions(administrator=True)
async def sancionar(ctx, member: discord.Member, regla: int):
    if regla == 1:
        cursor.execute("INSERT INTO warns (user_id, mod_id, rules, amount, timestamp) VALUES (?, ?, ?, ?, ?)",
                       (member.id, ctx.author.id, "1", 2, time.time()))
        conn.commit()
        total = get_total_warns(member.id)
        await apply_sanctions(ctx.guild, member, total, "Violación de Regla 1")
        await ctx.send(f"Aplicados 2 warns a {member.mention} por Regla 1. Total activo: {total}")

    elif regla == 3:
        await ctx.guild.ban(member, reason="Violación de Regla 3 (Ban 3 días)", delete_message_days=0)
        await ctx.send(f"{member.mention} ha sido baneado por 3 días por Regla 3 (sin borrar mensajes).")

    elif regla == 5:
        cursor.execute("INSERT INTO warns (user_id, mod_id, rules, amount, timestamp) VALUES (?, ?, ?, ?, ?)",
                       (member.id, ctx.author.id, "5", 2, time.time()))
        conn.commit()
        total = get_total_warns(member.id)
        await apply_sanctions(ctx.guild, member, total, "Violación de Regla 5")
        await ctx.send(f"Aplicados 2 warns a {member.mention} por Regla 5. Total activo: {total}")

@bot.command(name="warns")
async def list_warns(ctx, member: discord.Member = None, page: int = 1):
    target = member or ctx.author
    cursor.execute("SELECT id, rules, amount, timestamp FROM warns WHERE user_id = ? ORDER BY id ASC", (target.id,))
    rows = cursor.fetchall()

    if not rows:
        return await ctx.send(f"{target.mention} no tiene advertencias registradas.")

    per_page = 5
    total_pages = (len(rows) + per_page - 1) // per_page
    page = max(1, min(page, total_pages))

    start_idx = (page - 1) * per_page
    page_rows = rows[start_idx:start_idx + per_page]

    embed = discord.Embed(title=f"Warns de {target.display_name} (Página {page}/{total_pages})", color=discord.Color.red())
    
    for wid, rules, amount, ts in page_rows:
        hex_id = f"0x{wid:016X}"  # Contador Hexadecimal de 8 bytes (16 caracteres)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        status = "Activo" if (time.time() - ts) < (60 * 86400) else "Expirado"
        embed.add_field(
            name=f"ID Hex: `{hex_id}` | Cantidad: {amount}",
            value=f"**Reglas:** {rules}\n**Fecha:** `{dt}`\n**Estado:** {status}",
            inline=False
        )

    await ctx.send(embed=embed)

@bot.command(name="delwarn")
@commands.has_permissions(administrator=True)
async def del_warn(ctx, hex_id: str):
    try:
        wid = int(hex_id, 16)
    except ValueError:
        return await ctx.send("ID Hexadecimal inválido.")

    cursor.execute("SELECT user_id, amount, rules FROM warns WHERE id = ?", (wid,))
    row = cursor.fetchone()
    if not row:
        return await ctx.send("No se encontró ningún warn con ese ID Hexadecimal.")

    user_id, amount, rules = row
    cursor.execute("DELETE FROM warns WHERE id = ?", (wid,))
    conn.commit()

    await ctx.send(f"Warn `{hex_id}` eliminado.")
    await log_admin_action(
        ctx.guild, 
        "Warn Eliminado", 
        f"**ID Hex:** `{hex_id}`\n**Usuario Afectado:** <@{user_id}>\n**Valor:** {amount} warn(s)\n**Regla(s):** {rules}", 
        ctx.author
    )
    await backup_db_to_channel(ctx.guild, f"Borrado de warn {hex_id} por {ctx.author}")

@bot.command(name="editwarn")
@commands.has_permissions(administrator=True)
async def edit_warn(ctx, hex_id: str, new_amount: int):
    try:
        wid = int(hex_id, 16)
    except ValueError:
        return await ctx.send("ID Hexadecimal inválido.")

    cursor.execute("SELECT user_id, amount FROM warns WHERE id = ?", (wid,))
    row = cursor.fetchone()
    if not row:
        return await ctx.send("No se encontró el warn.")

    old_amount = row[1]
    cursor.execute("UPDATE warns SET amount = ? WHERE id = ?", (new_amount, wid))
    conn.commit()

    await ctx.send(f"Warn `{hex_id}` actualizado de {old_amount} a {new_amount}.")
    await log_admin_action(
        ctx.guild, 
        "Warn Editado", 
        f"**ID Hex:** `{hex_id}`\n**Usuario:** <@{row[0]}>\n**Cantidad previa:** {old_amount}\n**Nueva cantidad:** {new_amount}", 
        ctx.author
    )
    await backup_db_to_channel(ctx.guild, f"Edición de warn {hex_id} por {ctx.author}")

@bot.command(name="exportdb")
@commands.has_permissions(administrator=True)
async def export_db(ctx):
    """Comando manual para pedir el archivo .db con los pHash y warns directamente en el chat de logs."""
    await backup_db_to_channel(ctx.guild, f"Exportación manual solicitada por {ctx.author}")
    await ctx.send("Base de datos enviada al canal de logs.")

# Leer el token desde la variable de entorno del sistema/servidor
TOKEN = os.getenv("DISCORD_TOKEN")

if not TOKEN:
    raise ValueError("Error: La variable de entorno 'DISCORD_TOKEN' no está configurada.")

bot.run(TOKEN)
