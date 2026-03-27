from __future__ import annotations

import asyncio
import base64
import logging
import time
import urllib.parse
from collections import deque
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable, List, Tuple, TypedDict

import aiohttp
import discord
from redbot.core import Config, commands, checks, modlog

from .constants import *

# --------------------------------------------------------------------------- #
# ---------------------------- CONSTANTS & HELPERS -------------------------- #
# --------------------------------------------------------------------------- #

log = logging.getLogger("red.OnyxAzryn-Cogs.LinkGuardian")
log.setLevel(logging.DEBUG)   # The cog can be toggled via the `debug` config

# --------------------------------------------------------------------------- #
# --------------------------- ENUMS & TYPED DICTS -------------------------- #
# --------------------------------------------------------------------------- #


class PunishAction(str, Enum):
    """Allowed punishment actions – used for config validation."""
    WARN = "warn"
    BAN = "ban"
    PUNISH = "punish"


class GuildConfig(TypedDict):
    """Typed representation of the per‑guild configuration."""
    enabled: bool
    excluded_roles: List[int]
    report_channel: int | None
    punishment_action: PunishAction
    punishment_role: int | None
    punishment_channel: int | None
    threshold: int
    debug: bool
    dmuser: bool
    modlog_channel: int | None


# --------------------------------------------------------------------------- #
# ------------------------------- COG CLASS --------------------------------- #
# --------------------------------------------------------------------------- #


class LinkGuardian(commands.Cog):
    """Check links for malicious content using VirusTotal."""

    __author__ = "OnyxAzryn"
    __version__ = "2.0.0"

    # ------------------------------------------------------------------- #
    # --------------------------- INITIALISATION ------------------------ #
    # ------------------------------------------------------------------- #

    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self._session: aiohttp.ClientSession | None = None

        # ---- Config ---------------------------------------------------- #
        self.config = Config.get_conf(
            self,
            identifier=923480957876572539,
            force_registration=True,
        )
        default_guild = {
            "enabled": False,
            "excluded_roles": [],
            "report_channel": None,
            "punishment_action": PunishAction.WARN,
            "punishment_role": None,
            "punishment_channel": None,
            "threshold": 5,
            "debug": False,
            "dmuser": True,
            "modlog_channel": None,
        }
        self.config.register_guild(**default_guild)

        # ---- Rate‑limit tracking (per‑guild) --------------------------- #
        self._rl: dict[int, deque[float]] = {}

        # ---- API‑key caching ------------------------------------------- #
        self._api_key: str | None = None
        self._api_key_expiry: float = 0.0

        log.info("LinkGuardian cog loaded.")

    # ------------------------------------------------------------------- #
    # -------------------------- LIFECYCLE HOOKS ----------------------- #
    # ------------------------------------------------------------------- #

    async def cog_load(self) -> None:
        """Create the shared aiohttp session when the cog is loaded."""
        self._session = aiohttp.ClientSession()
        log.debug("aiohttp.ClientSession created for LinkGuardian.")

    async def cog_unload(self) -> None:
        """Close the aiohttp session when the cog is unloaded."""
        if self._session and not self._session.closed:
            await self._session.close()
            log.debug("aiohttp.ClientSession closed for LinkGuardian.")

    # ------------------------------------------------------------------- #
    # -------------------------- CONFIG HELPERS ------------------------ #
    # ------------------------------------------------------------------- #

    async def _get_guild_cfg(self, guild: discord.Guild) -> GuildConfig:
        """Return the whole guild config as a typed dict."""
        return await self.config.guild(guild).all()

    async def _get_api_key(self) -> str | None:
        """
        Return the VirusTotal API key, cached for 30 seconds.
        Red’s shared‑API store is queried only when the cache expires.
        """
        now = time.time()
        if self._api_key and now < self._api_key_expiry:
            return self._api_key

        shared = await self.bot.get_shared_api_tokens("virustotal")
        self._api_key = shared.get("api_key")
        self._api_key_expiry = now + 30   # 30 s TTL – cheap, safe, easy to invalidate
        return self._api_key

    # ------------------------------------------------------------------- #
    # ---------------------------- RATE LIMIT --------------------------- #
    # ------------------------------------------------------------------- #

    def _clean_rl(self, guild_id: int) -> None:
        """Drop timestamps older than TIME_WINDOW from the deque for a guild."""
        now = time.time()
        dq = self._rl.setdefault(guild_id, deque())
        while dq and dq[0] < now - TIME_WINDOW:
            dq.popleft()

    async def _rate_limited(self, guild: discord.Guild) -> bool:
        """
        Return ``True`` if the guild has exhausted its request quota.
        The function also updates the deque with the new request timestamp.
        """
        self._clean_rl(guild.id)
        dq = self._rl[guild.id]

        if len(dq) < RATE_LIMIT:
            dq.append(time.time())
            cfg = await self.config.guild(guild).debug()
            if cfg:
                log.debug(f"[Rate] {guild.name}: {len(dq)}/{RATE_LIMIT} used.")
            return False
        return True

    # ------------------------------------------------------------------- #
    # ---------------------------- UTILITIES --------------------------- #
    # ------------------------------------------------------------------- #

    async def _safe_send(
        self,
        destination: discord.abc.Messageable,
        *,
        embed: discord.Embed | None = None,
        content: str | None = None,
    ) -> None:
        """Wrap ``await destination.send`` with unified error handling."""
        try:
            await destination.send(content=content, embed=embed)
        except discord.Forbidden:
            log.warning(f"Missing permissions to send to {destination!r}.")
        except discord.HTTPException as exc:
            log.warning(f"Failed to send message to {destination!r}: {exc}")

    async def _safe_delete(self, message: discord.Message) -> None:
        """Attempt to delete a message, logging only on genuine failures."""
        try:
            await message.delete()
        except discord.NotFound:
            # Already deleted – nothing to do.
            pass
        except discord.Forbidden:
            log.warning(
                f"Missing permission to delete message {message.id} from {message.author}."
            )
        except discord.HTTPException as exc:
            log.warning(f"Failed to delete message {message.id}: {exc}")

    async def _safe_role_change(
        self,
        member: discord.Member,
        *,
        add: Iterable[discord.Role] = (),
        remove: Iterable[discord.Role] = (),
    ) -> None:
        """Add / remove roles from a member, handling permission errors."""
        try:
            await member.add_roles(*add, reason="LinkGuardian punishment")
            await member.remove_roles(*remove, reason="LinkGuardian punishment")
        except discord.Forbidden:
            log.warning(f"Missing permission to modify roles for {member}.")
        except discord.HTTPException as exc:
            log.warning(f"Failed role change for {member}: {exc}")

    # ------------------------------------------------------------------- #
    # ------------------------- EMBED BUILDERS ------------------------ #
    # ------------------------------------------------------------------- #

    @staticmethod
    def _title_and_desc(
        malicious: int, suspicious: int, total: int
    ) -> Tuple[str, str]:
        """
        Compute the embed title and description based on the scan results.
        Returns ``(title, description)``.
        """
        # ---- Title ---------------------------------------------------- #
        if malicious:
            title = "Malicious "
            if suspicious:
                title += "and Suspicious "
        elif suspicious:
            title = "Suspicious "
        else:
            title = "Link "

        title += "Found"

        # ---- Description ---------------------------------------------- #
        parts: List[str] = []
        if malicious:
            parts.append(
                f"Found **Malicious** by: {malicious} / {total} scanners"
            )
            if suspicious:
                parts.append(
                    f"Found **Suspicious** by: {suspicious} / {total} scanners"
                )
        elif suspicious:
            parts.append(
                f"Found **Suspicious** by: {suspicious} / {total} scanners"
            )
        description = "\n".join(parts) or "No detections"

        return title, description

    # ------------------------------------------------------------------- #
    # -------------------------- PUNISHMENT LOGIC ---------------------- #
    # ------------------------------------------------------------------- #

    async def _punish_warn(
        self,
        guild: discord.Guild,
        member: discord.Member,
        embed: discord.Embed,
        message: discord.Message,
    ) -> None:
        """Warn‑only mode – delete the offending message and log."""
        # Delete only if the user is **not** excluded.
        cfg = await self.config.guild(guild).all()
        if not any(r.id in cfg["excluded_roles"] for r in member.roles):
            await self._safe_delete(message)

        await self._safe_send(member, embed=embed)          # DM
        await self._send_to_reports(guild, embed)          # Report channel

    async def _punish_ban(
        self,
        guild: discord.Guild,
        member: discord.Member,
        embed: discord.Embed,
        message: discord.Message,
    ) -> None:
        """Ban the user and create a Modlog case (if the Modlog cog is loaded)."""
        # 1️⃣  Modlog entry (soft‑fail if the cog isn’t present)
        try:
            await modlog.create_case(
                self.bot,
                guild,
                message.created_at,
                user=member,
                moderator=guild.me,
                reason="Malicious link detected",
                action_type="ban",
            )
            log.info(f"Modlog case created for ban of {member}.")
        except Exception as exc:   # Broad on purpose – we don’t want to block the ban.
            log.debug(f"Modlog case creation failed (non‑fatal): {exc}")

        # 2️⃣  Ban the user.
        try:
            await guild.ban(member, reason="Malicious link detected")
            log.info(f"Banned {member} for posting a malicious link.")
        except discord.Forbidden:
            log.error(f"Missing permission to ban {member}.")
        except discord.HTTPException as exc:
            log.error(f"Failed to ban {member}: {exc}")

        # 3️⃣  Delete the message (unless the role is excluded)
        cfg = await self.config.guild(guild).all()
        if not any(r.id in cfg["excluded_roles"] for r in member.roles):
            await self._safe_delete(message)

        await self._safe_send(member, embed=embed)          # DM
        await self._send_to_reports(guild, embed)          # Report channel

    async def _punish_role(
        self,
        guild: discord.Guild,
        member: discord.Member,
        embed: discord.Embed,
        message: discord.Message,
    ) -> None:
        """Assign a punishment role (and strip all others) then log."""
        cfg = await self.config.guild(guild).all()
        role_id = cfg["punishment_role"]
        channel_id = cfg["punishment_channel"]
        punishment_role = guild.get_role(role_id) if role_id else None
        punishment_channel = guild.get_channel(channel_id) if channel_id else None

        if not punishment_role:
            log.warning("Punish action configured but no role set – falling back to warn.")
            await self._punish_warn(guild, member, embed, message)
            return

        # 1️⃣  Modlog case (soft‑fail)
        try:
            await modlog.create_case(
                self.bot,
                guild,
                message.created_at,
                user=member,
                moderator=guild.me,
                reason="Malicious link detected",
                action_type="softban",
            )
            log.info(f"Modlog case created for role‑punish of {member}.")
        except Exception as exc:
            log.debug(f"Modlog case creation failed (non‑fatal): {exc}")

        # 2️⃣  Strip *all* roles except @everyone.
        roles_to_remove = [r for r in member.roles if r != guild.default_role]
        await self._safe_role_change(
            member,
            add=[punishment_role],
            remove=roles_to_remove,
        )

        # 3️⃣  Delete the original message if the user isn’t excluded.
        if not any(r.id in cfg["excluded_roles"] for r in member.roles):
            await self._safe_delete(message)

        # 4️⃣  Inform the user (DM) – the embed already contains the warning.
        await self._safe_send(member, embed=embed)

        # 5️⃣  Optional “jail” channel notice.
        if punishment_channel:
            notice = (
                f"You have been placed in **{punishment_channel.mention}**. "
                "If you believe this is a mistake, you may appeal there."
            )
            await self._safe_send(member, content=notice)

        # 6️⃣  Report channel.
        await self._send_to_reports(guild, embed)

    async def _send_to_reports(self, guild: discord.Guild, embed: discord.Embed) -> None:
        """Post an embed to the configured reports channel (if any)."""
        channel_id = await self.config.guild(guild).report_channel()
        if not channel_id:
            log.info("Report channel not set – skipping report embed.")
            return
        channel = guild.get_channel(channel_id)
        if not channel:
            log.warning("Configured report channel could not be resolved.")
            return
        await self._safe_send(channel, embed=embed)

    # ------------------------------------------------------------------- #
    # --------------------------- MAIN LOGIC --------------------------- #
    # ------------------------------------------------------------------- #

    async def _handle_detection(
        self,
        guild: discord.Guild,
        message: discord.Message,
        *,
        malicious: int,
        suspicious: int,
        total: int,
        link: str,
        malicious_engines: List[str],
        suspicious_engines: List[str],
    ) -> None:
        """
        Central dispatcher that builds the embed and calls the appropriate
        punishment routine based on the guild configuration.
        """
        cfg = await self.config.guild(guild).all()

        # Build the embed (title/description already computed)
        title, description = self._title_and_desc(malicious, suspicious, total)
        embed = discord.Embed(
            title=title,
            description=description,
            color=discord.Color.red(),
            timestamp=datetime.now(tz=timezone.utc),
        )
        embed.add_field(name="User", value=f"{message.author} ({message.author.id})", inline=False)
        embed.add_field(name="Link", value=link, inline=False)
        embed.add_field(
            name="Malicious Engines",
            value=", ".join(malicious_engines) or "None",
            inline=False,
        )
        embed.add_field(
            name="Suspicious Engines",
            value=", ".join(suspicious_engines) or "None",
            inline=False,
        )
        embed.set_footer(text=f"Total scanners: {total}")

        # ------------------------------------------------------------------- #
        # Decide which punishment to apply.
        # ------------------------------------------------------------------- #
        action = PunishAction(cfg["punishment_action"])
        if action is PunishAction.BAN:
            await self._punish_ban(guild, message.author, embed, message)
        elif action is PunishAction.PUNISH:
            await self._punish_role(guild, message.author, embed, message)
        else:  # WARN (default)
            await self._punish_warn(guild, message.author, embed, message)

    async def _scan_address(
        self,
        session: aiohttp.ClientSession,
        address: str,
        headers: dict[str, str],
        debug: bool,
    ) -> Tuple[bool, dict] | Tuple[bool, None]:
        """
        Perform a single VirusTotal request (URL or IP).  Returns a tuple:

        ``(True, json)``  – request succeeded and JSON is returned.  
        ``(False, None)`` – request failed (non‑200) or raised an exception.
        """
        # Detect IP vs URL -------------------------------------------------
        parsed = urllib.parse.urlparse(address)
        host = parsed.hostname or address
        if IPV4_REGEX.fullmatch(host) or IPV6_REGEX.fullmatch(host):
            api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{host}"
        else:
            # VirusTotal expects the URL base64‑url‑safe without padding.
            encoded = base64.urlsafe_b64encode(address.encode()).decode().rstrip("=")
            api_url = f"https://www.virustotal.com/api/v3/urls/{encoded}"

        if debug:
            log.debug(f"[VT] GET {api_url}")

        try:
            async with session.get(api_url, headers=headers, timeout=12) as resp:
                if resp.status != 200:
                    log.warning(f"VT request failed ({resp.status}) for {address}")
                    return False, None
                data = await resp.json()
                return True, data
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            log.warning(f"VT request exception for {address}: {exc}")
            return False, None

    async def _process_message(self, message: discord.Message) -> None:
        """Core entry‑point – called from the listeners."""
        if not message.guild or message.author.bot:
            return  # Ignore DMs and our own messages.

        cfg = await self._get_guild_cfg(message.guild)
        if not cfg["enabled"]:
            return

        # Early‑exit if the author has an excluded role.
        if any(r.id in cfg["excluded_roles"] for r in message.author.roles):
            return

        # ------------------------------------------------------------------- #
        # 1️⃣  Gather every possible address from the message.
        # ------------------------------------------------------------------- #
        urls = URL_REGEX.findall(message.content)
        ipv4 = IPV4_REGEX.findall(message.content)
        ipv6 = IPV6_REGEX.findall(message.content)
        addresses = set(urls + ipv4 + ipv6)

        if not addresses:
            return  # Nothing to scan.

        # ------------------------------------------------------------------- #
        # 2️⃣  Rate‑limit check – per guild.
        # ------------------------------------------------------------------- #
        if await self._rate_limited(message.guild):
            log.info(f"Rate‑limit hit for guild {message.guild.name}; skipping VT checks.")
            return

        # ------------------------------------------------------------------- #
        # 3️⃣  Prepare the HTTP request (single session, shared headers).
        # ------------------------------------------------------------------- #
        api_key = await self._get_api_key()
        if not api_key:
            log.error("VirusTotal API key missing – aborting link check.")
            return
        headers = {"x-apikey": api_key}

        # ------------------------------------------------------------------- #
        # 4️⃣  Scan each address – stop early if a detection meets the threshold.
        # ------------------------------------------------------------------- #
        session = self._session
        if session is None:
            log.error("aiohttp session not initialised – aborting.")
            return

        for address in addresses:
            success, data = await self._scan_address(session, address, headers, cfg["debug"])
            if not success or not data:
                continue

            # Extract the analysis results.
            analysis = (
                data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_results", {})
            )
            # Drop the ignored engines.
            for bad in EXCLUDED_ANALYZERS:
                analysis.pop(bad, None)

            malicious = [
                name for name, r in analysis.items() if r.get("category") == "malicious"
            ]
            suspicious = [
                name for name, r in analysis.items() if r.get("category") == "suspicious"
            ]

            mal_cnt = len(malicious)
            sus_cnt = len(suspicious)
            total = len(analysis)

            if cfg["debug"]:
                log.debug(
                    f"[VT] {address} → Mal={mal_cnt} Sus={sus_cnt} Total={total} "
                    f"Threshold={cfg['threshold']}"
                )

            # Threshold logic – **any** malicious or >= configured suspicious count.
            if mal_cnt >= 1 or sus_cnt >= cfg["threshold"]:
                # Resolve the display‑ready link (for URLs the API returns the original URL)
                if "url" in data.get("data", {}).get("attributes", {}):
                    display_link = data["data"]["attributes"]["url"]
                else:
                    display_link = address

                await self._handle_detection(
                    message.guild,
                    message,
                    malicious=mal_cnt,
                    suspicious=sus_cnt,
                    total=total,
                    link=display_link,
                    malicious_engines=malicious,
                    suspicious_engines=suspicious,
                )
                # We *could* break here to avoid scanning the remaining addresses,
                # but scanning them gives a richer report.  If you want the fast
                # path, uncomment the next line:
                # break

    # ------------------------------------------------------------------- #
    # --------------------------- LISTENERS ----------------------------- #
    # ------------------------------------------------------------------- #

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        """Listener for new messages."""
        await self._process_message(message)

    @commands.Cog.listener()
    async def on_message_edit(
        self, before: discord.Message, after: discord.Message
    ) -> None:
        """Listener for edited messages – only run when the content actually changed."""
        if before.content == after.content:
            return
        await self._process_message(after)

    # ------------------------------------------------------------------- #
    # -------------------------- ADMIN COMMANDS ------------------------ #
    # ------------------------------------------------------------------- #

    @commands.group(name="linkguardian", aliases=["lg"])
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def linkguardian(self, ctx: commands.Context) -> None:
        """Base command – sub‑commands manage the cog."""
        if ctx.invoked_subcommand is None:
            await ctx.send_help(ctx.command)

    # ------------------------------------------------------------------- #
    # ── ENABLE / DISABLE ------------------------------------------------ #
    # ------------------------------------------------------------------- #

    @linkguardian.command(name="enable")
    @checks.admin_or_permissions(manage_guild=True)
    async def enable(self, ctx: commands.Context) -> None:
        """Toggle the cog on/off for the current guild."""
        api_key = await self._get_api_key()
        if not api_key:
            await ctx.send(
                "VirusTotal API key missing. Use `[p]set api virustotal` → `api_key <your_key>`."
            )
            return

        cur = await self.config.guild(ctx.guild).enabled()
        await self.config.guild(ctx.guild).enabled.set(not cur)
        await ctx.send(f"LinkGuardian is now {'enabled' if not cur else 'disabled'}.")

    # ------------------------------------------------------------------- #
    # ── STATUS ---------------------------------------------------------- #
    # ------------------------------------------------------------------- #

    @linkguardian.command(name="status")
    async def status(self, ctx: commands.Context) -> None:
        """Show a nicely formatted embed with the current guild configuration."""
        cfg = await self._get_guild_cfg(ctx.guild)
        api_key = await self._get_api_key()
        embed = discord.Embed(title="LinkGuardian Status", colour=discord.Color.blue())
        embed.add_field(
            name="Enabled", value="✅" if cfg["enabled"] else "❌", inline=False
        )
        embed.add_field(
            name="API key",
            value="✅ Set" if api_key else "❌ Not set",
            inline=False,
        )
        embed.add_field(
            name="Action on detection",
            value=cfg["punishment_action"].capitalize(),
            inline=False,
        )
        embed.add_field(
            name="Threshold (suspicious)",
            value=str(cfg["threshold"]),
            inline=False,
        )
        embed.add_field(
            name="Debug logging",
            value="✅ Enabled" if cfg["debug"] else "❌ Disabled",
            inline=False,
        )
        embed.add_field(
            name="DM users",
            value="✅ Enabled" if cfg["dmuser"] else "❌ Disabled",
            inline=False,
        )
        # Channels
        report = (
            ctx.guild.get_channel(cfg["report_channel"]).mention
            if cfg["report_channel"]
            else "Not set"
        )
        modlog = (
            ctx.guild.get_channel(cfg["modlog_channel"]).mention
            if cfg["modlog_channel"]
            else "Not set"
        )
        embed.add_field(name="Report channel", value=report, inline=False)
        embed.add_field(name="Modlog channel", value=modlog, inline=False)

        # Excluded roles
        if cfg["excluded_roles"]:
            role_names = [
                ctx.guild.get_role(r).mention for r in cfg["excluded_roles"]
            ]
            embed.add_field(
                name="Excluded roles", value=", ".join(role_names), inline=False
            )
        else:
            embed.add_field(name="Excluded roles", value="None", inline=False)

        await ctx.send(embed=embed)

    # ------------------------------------------------------------------- #
    # ── SETTINGS SUB‑GROUP --------------------------------------------- #
    # ------------------------------------------------------------------- #

    @linkguardian.group(name="set")
    async def _set(self, ctx: commands.Context) -> None:
        """Sub‑commands that change the configuration."""
        if ctx.invoked_subcommand is None:
            await ctx.send_help(ctx.command)

    @_set.command(name="debug")
    async def set_debug(self, ctx: commands.Context) -> None:
        """Toggle the debug flag."""
        cur = await self.config.guild(ctx.guild).debug()
        await self.config.guild(ctx.guild).debug.set(not cur)
        await ctx.send(f"Debug logging {'enabled' if not cur else 'disabled'}.")

    @_set.command(name="dmuser")
    async def set_dmuser(self, ctx: commands.Context) -> None:
        """Toggle whether the bot DMs the offender."""
        cur = await self.config.guild(ctx.guild).dmuser()
        await self.config.guild(ctx.guild).dmuser.set(not cur)
        await ctx.send(f"User DM {'enabled' if not cur else 'disabled'}.")

    @_set.command(name="exclude")
    async def set_excluded(self, ctx: commands.Context, *roles: discord.Role) -> None:
        """Add/remove roles from the exclusion list (toggle)."""
        cfg = await self.config.guild(ctx.guild).excluded_roles()
        for role in roles:
            if role.id in cfg:
                cfg.remove(role.id)
            else:
                cfg.append(role.id)
        await self.config.guild(ctx.guild).excluded_roles.set(cfg)

        if cfg:
            names = ", ".join(r.mention for r in [ctx.guild.get_role(i) for i in cfg])
            await ctx.send(f"Excluded roles: {names}")
        else:
            await ctx.send("No roles are currently excluded.")

    @_set.command(name="reports")
    async def set_reports(self, ctx: commands.Context, channel: discord.TextChannel) -> None:
        """Set the channel where detection reports are posted."""
        await self.config.guild(ctx.guild).report_channel.set(channel.id)
        await ctx.send(f"Report channel set to {channel.mention}")

    @_set.command(name="modlog")
    async def set_modlog(self, ctx: commands.Context, channel: discord.TextChannel) -> None:
        """Set the Modlog channel (used by the Modlog cog)."""
        await self.config.guild(ctx.guild).modlog_channel.set(channel.id)
        await ctx.send(f"Modlog channel set to {channel.mention}")

    @_set.command(name="punish")
    async def set_punishment(
        self,
        ctx: commands.Context,
        action: str,
        role: discord.Role | None = None,
        channel: discord.TextChannel | None = None,
    ) -> None:
        """
        Configure the punishment. ``action`` must be one of:
        ``warn`` (default), ``ban`` or ``punish`` (role‑jail).

        * ``warn`` – only delete the message and DM the user.  
        * ``ban`` – ban the user and log the case.  
        * ``punish`` – give the user a role and optionally point them to a “jail” channel.
        """
        action = action.lower()
        if action not in {a.value for a in PunishAction}:
            await ctx.send(
                "Invalid action. Choose **warn**, **ban** or **punish**."
            )
            return

        # ``punish`` requires a role (and optionally a channel).
        if action == PunishAction.PUNISH.value and role is None:
            await ctx.send("When using **punish** you must specify a role.")
            return

        await self.config.guild(ctx.guild).punishment_action.set(action)
        await self.config.guild(ctx.guild).punishment_role.set(role.id if role else None)
        await self.config.guild(ctx.guild).punishment_channel.set(
            channel.id if channel else None
        )

        await ctx.send(
            f"Punishment set to **{action}**"
            + (f" with role **{role.name}**" if role else "")
            + (f" and channel **{channel.name}**" if channel else "")
            + "."
        )

    @_set.command(name="threshold")
    async def set_threshold(self, ctx: commands.Context, value: int) -> None:
        """Set the number of *suspicious* detections that triggers an action."""
        if value <= 0:
            await ctx.send("Threshold must be a positive integer.")
            return
        await self.config.guild(ctx.guild).threshold.set(value)
        await ctx.send(f"Threshold set to **{value}** suspicious detections.")

    @_set.command(name="reset")
    async def reset(self, ctx: commands.Context) -> None:
        """Reset the whole configuration to defaults."""
        await self.config.guild(ctx.guild).clear()
        await ctx.send("LinkGuardian settings have been reset to defaults.")

    # ------------------------------------------------------------------- #
    # -------------------------- END OF COG ----------------------------- #
    # ------------------------------------------------------------------- #
