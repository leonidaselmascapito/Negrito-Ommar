import discord
from discord.ext import commands
import aiosqlite
import secrets
import time
import asyncio
from PIL import Image
import imagehash
import io
import aiohttp
import re
from datetime import timedelta

# --- CONFIGURACIÓN Y CONSTANTES ---
TOKEN = "TU_TOKEN_AQUI"
PREFIX = ".n "

MUTE_ROLE_ID = 1483621610819948635
LOG_CHANNELS = [1541275389450649680, 1483728856962826240]
MOD_ROLES = [1483621610975002771, 1483621610975002772]

intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix=PREFIX, intents=intents, help_command=None)

# --- BASE DE DATOS ---
async def init_db():
    async with aiosqlite.connect("moderation.db") as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS warns (
                warn_id TEXT PRIMARY KEY,
                user_id INTEGER,
                mod_id INTEGER,
                rules TEXT,
                timestamp REAL,
                weight INTEGER
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS phashes (
                hash TEXT PRIMARY KEY,
                rules TEXT,
                added_by INTEGER,
                timestamp REAL
            )
        """)
        await db.commit()

# --- FUNCIONES AUXILIARES ---
async def send_logs(guild, embed):
    for channel_id in LOG_CHANNELS:
        channel = guild.get_channel(channel_id)
        if channel:
            try:
                await channel.send(embed=embed)
            except discord.Forbidden:
                pass

def calculate_warn_weight(rules_str):
    rules = [r.strip() for r in rules_str.split(",")]
    weight = 0
    direct_punishment = None
    
    for rule in rules:
        if rule == "1" or rule == "5":
            weight += 2
        elif rule == "3":
            direct_punishment = "ban_3d"
        else:
            weight += 1 # Valor por defecto por regla rota
            
    return weight, direct_punishment

async def apply_punishment(member, total_warns, direct_punishment, guild):
    action_taken = "Ninguna (Solo Advertencia)"
    
    # Priorizar castigo directo de la regla 3
    if direct_punishment == "ban_3d":
        await guild.ban(member, reason="Regla 3: Ban automático de 3 días")
        bot.loop.create_task(unban_after(guild, member.id, 86400 * 3))
        return "Baneo de 3 días (Regla 3)"

    # Escala de castigos por acumulación
    if total_warns >= 13:
        await guild.ban(member, reason=f"Acumulación de {total_warns} warns")
        action_taken = "Baneo Permanente"
    elif total_warns >= 10:
        await guild.ban(member, reason=f"Acumulación de {total_warns} warns")
        bot.loop.create_task(unban_after(guild, member.id, 86400 * 31))
        action_taken = "Baneo de 31 días"
    elif total_warns >= 7:
        await guild.ban(member, reason=f"Acumulación de {total_warns} warns")
        bot.loop.create_task(unban_after(guild, member.id, 86400 * 1))
        action_taken = "Baneo de 1 día"
    elif total_warns >= 5:
        await guild.kick(member, reason=f"Acumulación de {total_warns} warns")
        action_taken = "Kick"
    elif total_warns >= 4:
        mute_role = guild.get_role(MUTE_ROLE_ID)
        if mute_role:
            await member.add_roles(mute_role, reason=f"Acumulación de {total_warns} warns")
            bot.loop.create_task(unmute_after(member, mute_role, 86400 * 1))
            action_taken = "Mute de 1 día"
    elif total_warns >= 3:
        mute_role = guild.get_role(MUTE_ROLE_ID)
        if mute_role:
            await member.add_roles(mute_role, reason=f"Acumulación de {total_warns} warns")
            bot.loop.create_task(unmute_after(member, mute_role, 3600))
            action_taken = "Mute de 1 hora"
            
    return action_taken

async def unmute_after(member, role, seconds):
    await asyncio.sleep(seconds)
    try:
        await member.remove_roles(role, reason="Tiempo de mute expirado")
    except:
        pass

async def unban_after(guild, user_id, seconds):
    await asyncio.sleep(seconds)
    try:
        user = await bot.fetch_user(user_id)
        await guild.unban(user, reason="Tiempo de baneo expirado")
    except:
        pass

async def get_image_from_message(ctx, message_ref):
    target_msg = None
    if ctx.message.reference:
        target_msg = await ctx.channel.fetch_message(ctx.message.reference.message_id)
    elif "http" in message_ref:
        # Extraer ID del link de discord
        match = re.search(r"channels/\d+/(\d+)/(\d+)", message_ref)
        if match:
            channel = bot.get_channel(int(match.group(1)))
            target_msg = await channel.fetch_message(int(match.group(2)))
    elif message_ref.isdigit():
        target_msg = await ctx.channel.fetch_message(int(message_ref))

    if not target_msg or not target_msg.attachments:
        return None

    attachment = target_msg.attachments[0]
    if not attachment.content_type.startswith("image/"):
        return None

    async with aiohttp.ClientSession() as session:
        async with session.get(attachment.url) as resp:
            if resp.status == 200:
                data = await resp.read()
                return Image.open(io.BytesIO(data))
    return None

# --- UI COMPONENTS ---
class WarnModal(discord.ui.Modal, title='Editar Warn'):
    def __init__(self, warn_id, current_rules):
        super().__init__()
        self.warn_id = warn_id
        self.rules = discord.ui.TextInput(
            label='Nuevas Reglas',
            default=current_rules,
            required=True
        )
        self.add_item(self.rules)

    async def on_submit(self, interaction: discord.Interaction):
        new_weight, _ = calculate_warn_weight(self.rules.value)
        async with aiosqlite.connect("moderation.db") as db:
            await db.execute("UPDATE warns SET rules = ?, weight = ? WHERE warn_id = ?", 
                             (self.rules.value, new_weight, self.warn_id))
            await db.commit()
            
        embed = discord.Embed(title="Warn Editado", color=discord.Color.blue())
        embed.add_field(name="ID", value=self.warn_id)
        embed.add_field(name="Nuevas Reglas", value=self.rules.value)
        embed.add_field(name="Moderador", value=interaction.user.mention)
        await send_logs(interaction.guild, embed)
        
        await interaction.response.send_message(f"Warn `{self.warn_id}` editado exitosamente.", ephemeral=True)

class WarnPaginationView(discord.ui.View):
    def __init__(self, data, is_global, user, page=1):
        super().__init__(timeout=180)
        self.data = data
        self.is_global = is_global
        self.user = user
        self.page = page
        self.per_page = 5
        self.total_pages = max(1, (len(data) + self.per_page - 1) // self.per_page)
        self.update_buttons()

    def update_buttons(self):
        self.clear_items()
        
        btn_prev = discord.ui.Button(label="Anterior", style=discord.ButtonStyle.secondary, disabled=(self.page == 1))
        btn_prev.callback = self.prev_page
        self.add_item(btn_prev)
        
        btn_next = discord.ui.Button(label="Siguiente", style=discord.ButtonStyle.secondary, disabled=(self.page == self.total_pages))
        btn_next.callback = self.next_page
        self.add_item(btn_next)

        # Botones de moderación (Edit/Delete) - Requiere permiso y roles específicos
        btn_edit = discord.ui.Button(label="Editar Warn", style=discord.ButtonStyle.primary)
        btn_edit.callback = self.edit_warn
        self.add_item(btn_edit)

        btn_delete = discord.ui.Button(label="Borrar Warn", style=discord.ButtonStyle.danger)
        btn_delete.callback = self.delete_warn
        self.add_item(btn_delete)

    def generate_embed(self):
        start = (self.page - 1) * self.per_page
        end = start + self.per_page
        page_data = self.data[start:end]

        title = "Lista Global de Warns" if self.is_global else f"Warns de {self.user.name}"
        total_warns_weight = sum(row[5] for row in self.data) # row[5] es el weight

        embed = discord.Embed(title=title, color=discord.Color.orange(), description=f"Total acumulado: **{total_warns_weight} warns**")
        embed.set_footer(text=f"Página {self.page} de {self.total_pages} | Registros totales: {len(self.data)}")

        for row in page_data:
            warn_id, u_id, m_id, rules, ts, weight = row
            fecha = f"<t:{int(ts)}:f>"
            embed.add_field(
                name=f"ID: `{warn_id}`",
                value=f"**Usuario:** <@{u_id}>\n**Mod:** <@{m_id}>\n**Reglas:** {rules} (Peso: {weight})\n**Fecha:** {fecha}",
                inline=False
            )
        return embed

    async def check_mod_roles(self, interaction):
        if not any(role.id in MOD_ROLES for role in interaction.user.roles):
            await interaction.response.send_message("No tienes permisos para esta acción.", ephemeral=True)
            return False
        return True

    async def prev_page(self, interaction: discord.Interaction):
        self.page -= 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.generate_embed(), view=self)

    async def next_page(self, interaction: discord.Interaction):
        self.page += 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.generate_embed(), view=self)

    async def edit_warn(self, interaction: discord.Interaction):
        if not await self.check_mod_roles(interaction): return
        # Para simplificar en UI directa, creamos un mini-modal pidiendo el ID
        await interaction.response.send_modal(InputIDModal(action="edit"))

    async def delete_warn(self, interaction: discord.Interaction):
        if not await self.check_mod_roles(interaction): return
        await interaction.response.send_modal(InputIDModal(action="delete"))

class InputIDModal(discord.ui.Modal, title='Introduce el ID del Warn'):
    warn_id = discord.ui.TextInput(label='Warn ID (16 carácteres)', min_length=16, max_length=16, required=True)

    def __init__(self, action):
        super().__init__()
        self.action = action

    async def on_submit(self, interaction: discord.Interaction):
        wid = self.warn_id.value
        async with aiosqlite.connect("moderation.db") as db:
            async with db.execute("SELECT rules FROM warns WHERE warn_id = ?", (wid,)) as cursor:
                row = await cursor.fetchone()
                
            if not row:
                return await interaction.response.send_message("Warn no encontrado.", ephemeral=True)

            if self.action == "delete":
                await db.execute("DELETE FROM warns WHERE warn_id = ?", (wid,))
                await db.commit()
                
                embed = discord.Embed(title="Warn Eliminado", color=discord.Color.red())
                embed.add_field(name="ID Eliminado", value=wid)
                embed.add_field(name="Moderador", value=interaction.user.mention)
                await send_logs(interaction.guild, embed)
                
                await interaction.response.send_message(f"Warn `{wid}` eliminado.", ephemeral=True)
            
            elif self.action == "edit":
                # Abrir el modal de edición pasándole las reglas actuales
                await interaction.response.send_modal(WarnModal(wid, row[0]))

class PHashPaginationView(discord.ui.View):
    # Similar a WarnPaginationView, simplificada para phashes
    def __init__(self, data, page=1):
        super().__init__(timeout=180)
        self.data = data
        self.page = page
        self.per_page = 10
        self.total_pages = max(1, (len(data) + self.per_page - 1) // self.per_page)
        self.update_buttons()

    def update_buttons(self):
        self.clear_items()
        btn_prev = discord.ui.Button(label="Anterior", disabled=(self.page == 1))
        btn_prev.callback = self.prev_page
        self.add_item(btn_prev)
        btn_next = discord.ui.Button(label="Siguiente", disabled=(self.page == self.total_pages))
        btn_next.callback = self.next_page
        self.add_item(btn_next)

    def generate_embed(self):
        start = (self.page - 1) * self.per_page
        end = start + self.per_page
        page_data = self.data[start:end]

        embed = discord.Embed(title="Lista de pHashes Registrados", color=discord.Color.purple())
        embed.set_footer(text=f"Página {self.page} de {self.total_pages} | Total: {len(self.data)} hashes")

        for row in page_data:
            h, rules, added, ts = row
            embed.add_field(
                name=f"`{h}`",
                value=f"**Reglas:** {rules}\n**Mod:** <@{added}>\n**Fecha:** <t:{int(ts)}:f>",
                inline=False
            )
        return embed

    async def prev_page(self, interaction: discord.Interaction):
        self.page -= 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.generate_embed(), view=self)

    async def next_page(self, interaction: discord.Interaction):
        self.page += 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.generate_embed(), view=self)

# --- COMANDOS ---
@bot.event
async def on_ready():
    await init_db()
    print(f"Bot conectado como {bot.user}")

@bot.command(name="warn")
@commands.has_permissions(manage_messages=True)
async def warn(ctx, user: discord.Member, *, rules: str):
    warn_id = secrets.token_hex(8) # 8 bytes = 16 hex chars
    weight, direct_punishment = calculate_warn_weight(rules)
    timestamp = time.time()

    async with aiosqlite.connect("moderation.db") as db:
        await db.execute(
            "INSERT INTO warns (warn_id, user_id, mod_id, rules, timestamp, weight) VALUES (?, ?, ?, ?, ?, ?)",
            (warn_id, user.id, ctx.author.id, rules, timestamp, weight)
        )
        await db.commit()

        # Calcular totales
        async with db.execute("SELECT SUM(weight) FROM warns WHERE user_id = ?", (user.id,)) as cursor:
            row = await cursor.fetchone()
            total_warns = row[0] if row[0] else 0

    action = await apply_punishment(user, total_warns, direct_punishment, ctx.guild)

    # Log Embed
    embed = discord.Embed(title="Usuario Advertido", color=discord.Color.red())
    embed.add_field(name="Usuario", value=f"{user.mention} ({user.id})")
    embed.add_field(name="Moderador", value=ctx.author.mention)
    embed.add_field(name="Regla(s)", value=rules)
    embed.add_field(name="ID del Warn", value=f"`{warn_id}`")
    embed.add_field(name="Acción Tomada", value=action)
    embed.add_field(name="Total Warns", value=str(total_warns))
    
    await send_logs(ctx.guild, embed)
    await ctx.send(f"⚠️ {user.mention} ha sido advertido. ID: `{warn_id}`. Acción: **{action}**")

@bot.command(name="warns")
@commands.has_permissions(manage_messages=True)
async def warns_list(ctx, param: str = None, user: discord.Member = None):
    # .n warns list [@user] o .n warns list
    if param != "list":
        return await ctx.send("Uso correcto: `.n warns list` o `.n warns list <usuario>`")

    async with aiosqlite.connect("moderation.db") as db:
        if user:
            async with db.execute("SELECT * FROM warns WHERE user_id = ? ORDER BY timestamp DESC", (user.id,)) as cursor:
                data = await cursor.fetchall()
            is_global = False
        else:
            async with db.execute("SELECT * FROM warns ORDER BY timestamp DESC") as cursor:
                data = await cursor.fetchall()
            is_global = True

    if not data:
        return await ctx.send("No hay warns registrados." if is_global else f"El usuario {user.name} no tiene warns.")

    view = WarnPaginationView(data, is_global, user)
    await ctx.send(embed=view.generate_embed(), view=view)

@bot.command(name="pHash")
@commands.has_permissions(manage_messages=True)
async def phash_cmd(ctx, target: str, *, rules: str = None):
    if target == "list":
        async with aiosqlite.connect("moderation.db") as db:
            async with db.execute("SELECT * FROM phashes ORDER BY timestamp DESC") as cursor:
                data = await cursor.fetchall()
        if not data:
            return await ctx.send("La base de datos de hashes está vacía.")
        
        view = PHashPaginationView(data)
        return await ctx.send(embed=view.generate_embed(), view=view)

    if not rules:
        return await ctx.send("Debes especificar las reglas asociadas. Uso: `.n pHash <mensaje> <reglas>`")

    img = await get_image_from_message(ctx, target)
    if not img:
        return await ctx.send("No se pudo obtener la imagen. Asegúrate de responder al mensaje o proporcionar un ID/Link válido que contenga una imagen.")

    # Genera pHash (hash_size=8 -> 8 bits por fila/col = 64 bits = 16 hex chars)
    img_hash = str(imagehash.phash(img, hash_size=8))
    
    async with aiosqlite.connect("moderation.db") as db:
        try:
            await db.execute("INSERT INTO phashes (hash, rules, added_by, timestamp) VALUES (?, ?, ?, ?)",
                             (img_hash, rules, ctx.author.id, time.time()))
            await db.commit()
            
            embed = discord.Embed(title="pHash Registrado", color=discord.Color.green())
            embed.add_field(name="Hash", value=f"`{img_hash}`")
            embed.add_field(name="Reglas Asociadas", value=rules)
            await send_logs(ctx.guild, embed)
            await ctx.send(f"✅ Imagen registrada con pHash `{img_hash}` y reglas `{rules}`.")
            
        except aiosqlite.IntegrityError:
            await ctx.send(f"⚠️ Este hash `{img_hash}` ya existe en la base de datos.")

bot.run(TOKEN)
