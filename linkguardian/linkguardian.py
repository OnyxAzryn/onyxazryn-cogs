from __future__ import annotations

import base64
import datetime
import json
import logging
import re
import time
import urllib.parse
from collections import deque, defaultdict
from typing import Any, Dict, List, Optional, Tuple, Union

import aiohttp
import discord
from redbot.core import Config, checks, commands, data_manager, modlog

# --------------------------------------------------------------------
#  Local imports – keep them at the top for static analysis tools.
# --------------------------------------------------------------------
from .constants import (
    EXCLUDED_ANALYZERS,
    IPV4_REGEX,
    IPV6_REGEX,
    RATE_LIMIT,
    TIME_WINDOW,
    URL_REGEX,
)
from .utils import read_hosts_file_domains

# --------------------------------------------------------------------
#  Logging
# --------------------------------------------------------------------
log = logging.getLogger("red.OnyxAzryn-Cogs.LinkGuardian")
log.setLevel(logging.DEBUG)   # Debug entries are emitted; admins can toggle via config.

# --------------------------------------------------------------------
#  Helper types
# --------------------------------------------------------------------
JSONDict = Dict[str, Any]
Embedable = Union[str, discord.Embed]

# --------------------------------------------------------------------
#  Cog definition
# --------------------------------------------------------------------
class LinkGuardian(commands.Cog):
    """
    Check links for malicious content using VirusTotal and an allow/deny list.

    All public commands and configuration options are preserved from the
    original implementation. The internals have been refactored for
    readability, type‑safety and a small performance gain.
    """

    # ----------------------------------------------------------------
    #  Constructor & lifecycle helpers
    # ----------------------------------------------------------------
    def __init__(self, bot: commands.Bot):
        self.bot = bot

        # -------------------------- Config -------------------------
        self.config: Config = Config.get_conf(
            self,
            identifier=923480957876572539,
            force_registration=True,
        )
        default_guild_settings: JSONDict = {
            "enabled": False,
            "excluded_roles": [],
            "report_channel": None,
            "punishment_action": "Warn",
            "punishment_role": None,
            "punishment_channel": None,
            "threshold": 5,
            "debug": False,
            "dmuser": True,
            "modlog_channel": None,
        }
        self.config.register_guild(**default_guild_settings)

        # --------------------- Runtime caches --------------------
        self._rate_tracker: defaultdict[int, deque[float]] = defaultdict(deque)
        self.seen_links: Dict[str, bool] = {}
        self.trusted_domains: List[str] = []
        self.blocked_domains: List[str] = []

        # ----------------------- HTTP client ---------------------
        self._http: aiohttp.ClientSession = aiohttp.ClientSession()

        # ----------------------- Load data -----------------------
        self._load_trust_lists()

        # Dedupe from lists, send everything to a dictionary, and log
        self.blocked_domains = list(set(self.blocked_domains))
        for i in self.trusted_domains:
            self.seen_links[i] = False
        for i in self.blocked_domains:
            self.seen_links[i] = True
        log.info(f"Loaded {len(self.trusted_domains)} trusted domains and {len(self.blocked_domains)} blocked domains!")

        # Clear the lists for memory reduction
        self.trusted_domains = []
        self.blocked_domains = []

        log.info("LinkGuardian Cog has loaded.")

    def _load_trust_lists(self) -> None:
        """Load the bundled JSON/hosts files that contain trusted and blocked domains."""
        bundled_path = data_manager.bundled_data_path(self)

        # Trusted domains (JSON)
        try:
            with open(str(bundled_path / "trusted_domains.json"), "r", encoding="utf-8") as f:
                self.trusted_domains = json.load(f).get("trusted_domains", [])
        except Exception as exc:   # pragma: no cover – defensive
            log.exception("Failed to load trusted_domains.json: %s", exc)
            self.trusted_domains = []

        # Blocked domains (hosts style file) https://github.com/hagezi/dns-blocklists
        # Threat Intelligence Feeds (hosts style file) https://github.com/hagezi/dns-blocklists
        # Steven Black Hosts (hosts style file) https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts
        hosts_files = ["ultimate.txt", "tif.txt", "hosts.txt"]

        # Blocked domains (hosts style file)
        for i in hosts_files:
            try:
                with open(str(bundled_path / i), "r", encoding="utf-8") as f:
                    self.blocked_domains += read_hosts_file_domains(f)
            except Exception as exc:   # pragma: no cover – defensive
                log.exception(f"Failed to load blocklist {i}: %s", exc)

    async def cog_unload(self) -> None:
        """Close the aiohttp session when the cog is unloaded."""
        await self._http.close()

    # ----------------------------------------------------------------
    #  Utility helpers
    # ----------------------------------------------------------------
    @staticmethod
    async def ensure_api_key(ctx: commands.Context) -> bool:
        """
        Verify that a VirusTotal API key is stored in the shared API token
        storage.  Returns ``True`` if the key exists, otherwise informs the
        user and returns ``False``.
        """
        api = await ctx.bot.get_shared_api_tokens("virustotal")
        if not api or not api.get("api_key"):
            await ctx.send(
                "VirusTotal API Missing.\n\n"
                "Use `[p]set api virustotal` and type `api_key <your_api_key>` "
                "in the pop‑out box to set the API key."
            )
            return False
        return True

    async def _debug(self, guild: discord.Guild, message: str) -> None:
        """Log a debug message only when the guild has ``debug`` enabled."""
        if await self.config.guild(guild).debug():
            log.debug(message)

    async def _rate_limited(self, guild: discord.Guild) -> bool:
        """
        Check if the guild is currently over the global VT request limit.
        The underlying algorithm is unchanged – a sliding window of
        ``TIME_WINDOW`` seconds that allows up to ``RATE_LIMIT`` calls.
        """
        now = time.time()
        timestamps = self._rate_tracker[guild.id]

        # Remove stale entries
        while timestamps and timestamps[0] < now - TIME_WINDOW:
            timestamps.popleft()

        if len(timestamps) < RATE_LIMIT:
            timestamps.append(now)
            await self._debug(guild, f"Current Rate for guild {guild.id}: {len(timestamps)}")
            return False  # Not rate‑limited
        return True

    @staticmethod
    def _extract_addresses(content: str) -> set[str]:
        """
        Pull URLs, IPv4 and IPv6 addresses from a message string.
        Returns a ``set`` of raw matches (duplicates removed).
        """
        urls = re.findall(URL_REGEX, content)
        ipv4 = re.findall(IPV4_REGEX, content)
        ipv6 = re.findall(IPV6_REGEX, content)
        return set(urls + ipv4 + ipv6)

    async def _log_to_modlog(
        self,
        guild: discord.Guild,
        member: discord.Member,
        reason: str,
        action_type: str = "ban",
    ) -> None:
        """
        Helper that creates a Modlog case and also sends a nice embed to the
        optional ``modlog_channel`` configured by the user.
        """
        try:
            await modlog.create_case(
                self.bot,
                guild,
                datetime.datetime.utcnow(),
                user=member,
                moderator=guild.me,
                reason=reason,
                action_type=action_type,
            )
            log.info(
                "Modlog case created for %s (%s) – action: %s",
                member,
                member.id,
                action_type,
            )
        except Exception as exc:   # pragma: no cover – defensive
            log.debug("Modlog creation failed (non‑critical): %s", exc)

        # Also push a simple embed to the dedicated modlog channel, if set.
        modlog_channel_id = await self.config.guild(guild).modlog_channel()
        if modlog_channel_id:
            channel = guild.get_channel(modlog_channel_id)
            if channel:
                embed = discord.Embed(
                    title="User Moderation",
                    description=f"**User:** {member} ({member.id})\n**Reason:** {reason}",
                    color=discord.Color.red(),
                    timestamp=datetime.datetime.utcnow(),
                )
                embed.set_footer(text=f"Guild: {guild.name}")
                try:
                    await channel.send(embed=embed)
                except discord.Forbidden:
                    log.warning(
                        "Missing permissions to send to configured modlog channel %s", channel.id
                    )
                except discord.HTTPException:
                    log.warning("Failed to send embed to modlog channel %s", channel.id)

    # ----------------------------------------------------------------
    #  Configuration commands
    # ----------------------------------------------------------------
    @commands.group(aliases=["lg"])
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def linkguardian(self, ctx: commands.Context) -> None:
        """Manage LinkGuardian link checking."""
        pass

    @linkguardian.command(name="enable")
    @checks.admin_or_permissions(manage_guild=True)
    async def linkguardian_toggle(self, ctx: commands.Context) -> None:
        """Toggle link checking."""
        if not await self.ensure_api_key(ctx):
            return

        enabled = await self.config.guild(ctx.guild).enabled()
        await self.config.guild(ctx.guild).enabled.set(not enabled)
        await ctx.send(
            f"LinkGuardian is now {'enabled' if not enabled else 'disabled'}."
        )
        log.info(
            "LinkGuardian toggled to %s for guild %s", "enabled" if not enabled else "disabled", ctx.guild.id
        )

    @linkguardian.command(name="reset")
    @checks.admin_or_permissions(manage_guild=True)
    async def reset_settings(self, ctx: commands.Context) -> None:
        """Reset LinkGuardian settings to default."""
        await self.config.guild(ctx.guild).clear()
        await ctx.send("LinkGuardian settings have been reset to default.")

    @linkguardian.command(name="status")
    @checks.admin_or_permissions(manage_guild=True)
    async def linkguardian_status(self, ctx: commands.Context) -> None:
        """Show the current status of LinkGuardian settings."""
        embed = await self._get_status_embed(ctx.guild)
        await ctx.send(embed=embed)

    @linkguardian.group(name="set")
    @checks.admin_or_permissions(manage_guild=True)
    async def linkguardian_setgroup(self, ctx: commands.Context) -> None:
        """Set various configurations for LinkGuardian."""
        pass

    @linkguardian_setgroup.command(name="debug")
    @checks.admin_or_permissions(manage_guild=True)
    async def linkguardian_debug(self, ctx: commands.Context) -> None:
        """Toggle debugging logs."""
        debug = await self.config.guild(ctx.guild).debug()
        await self.config.guild(ctx.guild).debug.set(not debug)
        await ctx.send(
            f"LinkGuardian debug logging is now {'enabled' if not debug else 'disabled'}."
        )

    @linkguardian_setgroup.command(name="dmuser")
    @checks.admin_or_permissions(manage_guild=True)
    async def linkguardian_dmuser(self, ctx: commands.Context) -> None:
        """Enable/Disable Sending DM Notifications to the User."""
        dmuser = await self.config.guild(ctx.guild).dmuser()
        await self.config.guild(ctx.guild).dmuser.set(not dmuser)
        await ctx.send(
            f"LinkGuardian {'will' if not dmuser else 'will not'} send a DM to the user when triggered."
        )

    @linkguardian_setgroup.command(name="exclude")
    @checks.admin_or_permissions(manage_guild=True)
    async def exclude_roles(self, ctx: commands.Context, *roles: discord.Role) -> None:
        """Exclude or include the given roles from link checking."""
        excluded = await self.config.guild(ctx.guild).excluded_roles()
        for role in roles:
            if role.id in excluded:
                excluded.remove(role.id)
            else:
                excluded.append(role.id)
        await self.config.guild(ctx.guild).excluded_roles.set(excluded)

        if excluded:
            role_list = "\n".join(f"- {ctx.guild.get_role(r).name}" for r in excluded)
        else:
            role_list = "None"
        await ctx.send(f"The following roles have been excluded from LinkGuardian:\n{role_list}")

    @linkguardian_setgroup.command(name="modlog")
    @checks.admin_or_permissions(manage_guild=True)
    async def set_modlog_channel(self, ctx: commands.Context, channel: discord.TextChannel) -> None:
        """Set the modlog channel where moderation actions like bans will be logged."""
        await self.config.guild(ctx.guild).modlog_channel.set(channel.id)
        await ctx.send(f"Modlog channel set to: {channel.mention}")

    @linkguardian_setgroup.command(name="punishment")
    @checks.admin_or_permissions(manage_guild=True)
    async def set_punishment(
        self,
        ctx: commands.Context,
        action: str,
        role: Optional[discord.Role] = None,
        channel: Optional[discord.TextChannel] = None,
    ) -> None:
        """
        Set punishment for sending malicious links.

        ``action`` can be ``warn``, ``ban`` or ``punish``.  ``punish`` requires
        both a role and a channel (the “jail” channel).
        """
        act = action.lower()
        if act not in {"warn", "ban", "punish"}:
            await ctx.send("Invalid action. Please choose 'warn', 'ban', or 'punish'.")
            return

        if act == "punish" and (role is None or channel is None):
            await ctx.send(
                "Please specify the role and channel to set for punishment.\r"
                "Remember! You will NEED to set up the channel to be an appropriate Jail!"
            )
            return

        await self.config.guild(ctx.guild).punishment_action.set(act)
        await self.config.guild(ctx.guild).punishment_role.set(role.id if role else None)
        await self.config.guild(ctx.guild).punishment_channel.set(channel.id if channel else None)

        if act == "ban":
            await ctx.send("Senders of malicious links will be banned.")
            await self.config.guild(ctx.guild).punishment_role.set(None)
        elif act == "punish":
            await ctx.send(
                f"Senders of malicious links will be punished with the role: {role.name} "
                f"and limited to {channel.name}.\r"
                "Remember! You will NEED to set up the channel to be an appropriate Jail!"
            )
        else:
            await ctx.send("Senders of malicious links will be informed only.")
            await self.config.guild(ctx.guild).punishment_role.set(None)

    @linkguardian_setgroup.command(name="reportschannel")
    @checks.admin_or_permissions(manage_guild=True)
    async def set_reports_channel(self, ctx: commands.Context, channel: discord.TextChannel) -> None:
        """Set the channel where reports will be sent."""
        await self.config.guild(ctx.guild).report_channel.set(channel.id)
        await ctx.send(f"Reports channel set to: {channel.mention}")

    @linkguardian_setgroup.command(name="threshold")
    @checks.admin_or_permissions(manage_guild=True)
    async def set_threshold(self, ctx: commands.Context, threshold: int) -> None:
        """Set the threshold of number of malicious returns before taking action."""
        if threshold <= 0:
            await ctx.send("Please provide a non‑negative number value for the threshold.")
            return

        try:
            await self.config.guild(ctx.guild).threshold.set(threshold)
            await ctx.send(f"VirusTotal threshold set to {threshold} positive returns")
        except Exception:   # pragma: no cover – defensive
            await ctx.send("Failed to set the threshold – an unexpected error occurred.")

    # ----------------------------------------------------------------
    #  Status embed builder (private)
    # ----------------------------------------------------------------
    async def _get_status_embed(self, guild: discord.Guild) -> discord.Embed:
        """Collect configuration and runtime data and return a nicely formatted embed."""
        api_tokens = await self.bot.get_shared_api_tokens("virustotal")
        cfg = await self.config.guild(guild).all()

        # Basic fields -------------------------------------------------
        embed = discord.Embed(title="LinkGuardian Status", color=discord.Color.blue())
        embed.add_field(name="Link checking", value="✅ Enabled" if cfg["enabled"] else "❌ Disabled", inline=False)
        embed.add_field(
            name="VirusTotal API key",
            value="✅ Set" if api_tokens.get("api_key") else "❌ Not set",
            inline=False,
        )

        # Punishment ---------------------------------------------------
        punishment_action = cfg["punishment_action"]
        punishment_role_id = cfg["punishment_role"]
        punishment_role = guild.get_role(punishment_role_id) if punishment_role_id else None
        punishment_channel_id = cfg["punishment_channel"]
        punishment_channel = guild.get_channel(punishment_channel_id) if punishment_channel_id else None

        if punishment_action == "punish" and punishment_role and punishment_channel:
            embed.add_field(
                name="Action upon detection",
                value=f"Punish them to `{punishment_role.name}` in `{punishment_channel.name}`",
                inline=False,
            )
        else:
            embed.add_field(
                name="Action upon detection",
                value="Warn" if punishment_action == "warn" else "Ban",
                inline=False,
            )

        # Channels ------------------------------------------------------
        report_chan = guild.get_channel(cfg["report_channel"])
        embed.add_field(name="Reports channel", value=report_chan.name if report_chan else "Not set", inline=False)

        modlog_chan = guild.get_channel(cfg["modlog_channel"])
        embed.add_field(name="Modlog channel", value=modlog_chan.name if modlog_chan else "Not set", inline=False)

        # Misc ---------------------------------------------------------
        embed.add_field(name="Threshold", value=f"{cfg['threshold']} virus scanning vendors", inline=False)
        embed.add_field(name="Debug Logging", value="✅ Enabled" if cfg["debug"] else "❌ Disabled", inline=False)
        embed.add_field(name="DM User", value="✅ Enabled" if cfg["dmuser"] else "❌ Disabled", inline=False)

        if cfg["excluded_roles"]:
            role_names = ", ".join(
                guild.get_role(r).name for r in cfg["excluded_roles"] if guild.get_role(r) is not None
            )
            embed.add_field(name="Excluded roles from link checking", value=role_names, inline=False)
        else:
            embed.add_field(name="Excluded roles from link checking", value="None", inline=False)

        return embed

    # ----------------------------------------------------------------
    #  Messaging helpers (DM & report channel)
    # ----------------------------------------------------------------
    async def _send_dm_to_user(self, member: discord.Member, embed: discord.Embed) -> None:
        """Send a DM to ``member`` if the guild configuration permits it."""
        if not await self.config.guild(member.guild).dmuser():
            return

        try:
            await member.send(embed=embed)
        except discord.Forbidden:
            log.warning("Cannot DM user %s (%s) – blocked or privacy settings.", member, member.id)
        except discord.HTTPException as exc:
            log.warning("Failed to DM user %s (%s): %s", member, member.id, exc)

    async def _send_to_reports_channel(self, guild: discord.Guild, embed: discord.Embed) -> None:
        """Post the embed in the configured reports channel, if any."""
        channel_id = await self.config.guild(guild).report_channel()
        if not channel_id:
            log.debug("Reports channel not configured for guild %s", guild.id)
            return

        channel = guild.get_channel(channel_id)
        if not channel:
            log.warning("Configured reports channel %s not found in guild %s", channel_id, guild.id)
            return

        try:
            await channel.send(embed=embed)
        except discord.Forbidden:
            log.warning("Missing permissions to send to reports channel %s", channel_id)
        except discord.HTTPException as exc:
            log.warning("Failed to send report embed to channel %s: %s", channel_id, exc)

    # ----------------------------------------------------------------
    #  Core link‑checking logic
    # ----------------------------------------------------------------
    async def check_links(self, message: discord.Message) -> None:
        """Entry point – scans a message for URLs / IPs and reacts if needed."""
        # ----------------------------------------------------------------
        #  Guard clauses – ignore DMs, bots and disabled guilds
        # ----------------------------------------------------------------
        if not message.guild or message.author.bot:
            return

        guild = message.guild
        cfg = await self.config.guild(guild).all()
        if not cfg["enabled"]:
            return

        # ----------------------------------------------------------------
        #  Pull the VirusTotal API key (must exist – already validated on toggle)
        # ----------------------------------------------------------------
        api_tokens = await self.bot.get_shared_api_tokens("virustotal")
        api_key = api_tokens.get("api_key")
        if not api_key:
            log.error("VirusTotal API key missing – aborting link scan.")
            return

        # ----------------------------------------------------------------
        #  Extract all possible addresses from the message content
        # ----------------------------------------------------------------
        addresses = self._extract_addresses(message.content)
        if not addresses:
            return

        await self._debug(guild, f"Addresses found: {addresses}")

        headers = {"x-apikey": api_key}

        # ----------------------------------------------------------------
        #  Process each address – allowlist / denylist / VT lookup
        # ----------------------------------------------------------------
        for raw in addresses:
            await self._debug(guild, f"Checking address: {raw}")

            parsed = urllib.parse.urlparse(raw)
            host = parsed.hostname or raw  # ``hostname`` is None for raw IP strings

            # ----- Allow/Deny list checks -------------------------------------------------
            if host in self.seen_links:
                if self.seen_links[host]:  # previously flagged as bad
                    log.info(f"{host} is known to be bad, blocking...")
                    await self.handle_bad_link(
                        guild,
                        message,
                        num_malicious=1,
                        num_suspicious=0,
                        total_scanners=1,
                        link=host,
                        malicious_engines=["Denylist"],
                        suspicious_engines=[],
                    )
                else:
                    log.info(f"{host} is known to be good, allowing...")
                continue

            # ----- Rate‑limit check -------------------------------------------------------
            if await self._rate_limited(guild):
                log.warning("API rate limit exceeded for guild %s – skipping further VT checks.", guild.id)
                return

            # ----- Build the VT endpoint ---------------------------------------------------
            if re.fullmatch(IPV4_REGEX, host) or re.fullmatch(IPV6_REGEX, host):
                vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{host}"
                scan_type = "ip"
            else:
                # VT expects a base64‑url‑safe representation without padding
                encoded = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
                vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded}"
                scan_type = "url"

            await self._debug(guild, f"VT request URL: {vt_url} (type={scan_type})")

            # ----- Perform the request ----------------------------------------------------
            async with self._http.get(vt_url, headers=headers) as resp:
                if resp.status != 200:
                    log.error("VT request failed with status %s (url=%s)", resp.status, vt_url)
                    continue

                data = await resp.json()
                analysis = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_results", {})
                )

                # Remove any vendors the author explicitly excluded
                for exc in EXCLUDED_ANALYZERS:
                    analysis.pop(exc, None)

                malicious_engines = [
                    eng for eng, res in analysis.items() if res.get("category") == "malicious"
                ]
                suspicious_engines = [
                    eng for eng, res in analysis.items() if res.get("category") == "suspicious"
                ]

                malicious = len(malicious_engines)
                suspicious = len(suspicious_engines)
                total_scanners = len(analysis)

                await self._debug(
                    guild,
                    f"VT results – Malicious={malicious}, Suspicious={suspicious}, "
                    f"Scanners={total_scanners}, Threshold={cfg['threshold']}",
                )

                # ----- Decide whether the link is bad -----------------------------------
                is_bad = malicious >= 1 or suspicious >= cfg["threshold"]
                if is_bad:
                    log.info(f"{host} is malicious, blocking...")
                    link_display = (
                        raw
                        if scan_type == "ip"
                        else data["data"]["attributes"].get("url", raw)
                    )
                    await self.handle_bad_link(
                        guild,
                        message,
                        malicious,
                        suspicious,
                        total_scanners,
                        link_display,
                        malicious_engines,
                        suspicious_engines,
                    )
                else:
                    log.info(f"{host} passed all checks, allowing...")

                # ----- Cache the result for future messages ---------------------------
                self.seen_links[host] = is_bad

    # ----------------------------------------------------------------
    #  Helper – build title/description for the embed
    # ----------------------------------------------------------------
    async def determine_mal_sus(
        self, malicious: int, suspicious: int, total_scanners: int
    ) -> Tuple[str, str]:
        """Return a title and description based on the scan outcome."""
        # Title -------------------------------------------------------
        title_parts = []
        if malicious:
            title_parts.append("Malicious")
        if suspicious:
            title_parts.append("Suspicious")
        title = " and ".join(title_parts) + " Link Found" if title_parts else "Link Found"

        # Description -------------------------------------------------
        if malicious:
            desc = f"Found Malicious by: {malicious} of {total_scanners} virus scanners"
            if suspicious:
                desc += f"\nFound Suspicious by: {suspicious} of {total_scanners} virus scanners"
        elif suspicious:
            desc = f"Found Suspicious by: {suspicious} of {total_scanners} virus scanners"
        else:
            desc = "No malicious or suspicious detections."

        return title, desc

    # ----------------------------------------------------------------
    #  Main handler – called when a link is deemed “bad”
    # ----------------------------------------------------------------
    async def handle_bad_link(
        self,
        guild: discord.Guild,
        message: discord.Message,
        num_malicious: int,
        num_suspicious: int,
        total_scanners: int,
        link: str,
        malicious_engines: List[str],
        suspicious_engines: List[str],
    ) -> None:
        """Create embeds, apply punishment and log the incident."""
        member = message.author
        cfg = await self.config.guild(guild).all()
        excluded_roles = cfg["excluded_roles"]
        punishment = cfg["punishment_action"]

        # --------------------------------------------------------------
        #  Build the embed that will be used for DM and report channel
        # --------------------------------------------------------------
        title, description = await self.determine_mal_sus(
            num_malicious, num_suspicious, total_scanners
        )

        embed = discord.Embed(
            title=title,
            description=description,
            color=discord.Color.red(),
            timestamp=datetime.datetime.utcnow(),
        )
        embed.add_field(name="User", value=f"{member} ({member.id})", inline=False)
        embed.add_field(name="Link", value=link, inline=False)
        embed.add_field(
            name="Malicious Engines",
            value=", ".join(malicious_engines) if malicious_engines else "None",
            inline=False,
        )
        embed.add_field(
            name="Suspicious Engines",
            value=", ".join(suspicious_engines) if suspicious_engines else "None",
            inline=False,
        )
        embed.set_footer(text=f"Total Scanners: {total_scanners}")

        # --------------------------------
        #  Apply the configured punishment
        # --------------------------------
        if num_malicious >= 1 or num_suspicious > cfg["threshold"]:
            if punishment == "ban":
                # --- Ban path ------------------------------------------------
                await self._log_to_modlog(
                    guild,
                    member,
                    reason="Malicious link detected",
                    action_type="ban",
                )
                try:
                    await guild.ban(member, reason="Malicious link detected")
                except discord.Forbidden:
                    log.error("Missing permissions to ban %s (%s)", member, member.id)
                except discord.HTTPException as exc:
                    log.error("Ban failed for %s (%s): %s", member, member.id, exc)

            elif punishment == "punish":
                # --- Role‑jail path ----------------------------------------
                punishment_channel_id = cfg["punishment_channel"]
                punishment_role_id = cfg["punishment_role"]
                punishment_channel = guild.get_channel(punishment_channel_id) if punishment_channel_id else None
                punishment_role = guild.get_role(punishment_role_id) if punishment_role_id else None

                embed.add_field(
                    name="Alert!",
                    value=(
                        f"You have sent a link that is considered malicious and have been "
                        f"disabled from sending further messages.\n"
                        f"You can appeal this status in `{punishment_channel.name if punishment_channel else '???'}` channel."
                    ),
                    inline=False,
                )

                # Log to Modlog as a “softban” (the role‑jail case)
                await self._log_to_modlog(
                    guild,
                    member,
                    reason="Malicious link detected",
                    action_type="softban",
                )

                # Apply the role jail
                try:
                    # Strip all roles except @everyone
                    roles_to_remove = [r for r in member.roles if r != guild.default_role]
                    await member.remove_roles(*roles_to_remove)

                    if punishment_role:
                        await member.add_roles(punishment_role)
                except discord.Forbidden:
                    log.warning("Missing permissions to modify roles for %s (%s)", member, member.id)
                except discord.HTTPException as exc:
                    log.warning("Role modification failed for %s (%s): %s", member, member.id, exc)

            # ----------------------------------------------------------
            #  Delete the offending message (unless the user is excluded)
            # ----------------------------------------------------------
            if not any(r.id in excluded_roles for r in member.roles):
                try:
                    await message.delete()
                except discord.NotFound:
                    log.debug("Message already deleted.")
                except discord.Forbidden:
                    log.warning("Missing permissions to delete message from %s (%s).", member, member.id)
                except discord.HTTPException as exc:
                    log.warning("Failed to delete message from %s (%s): %s", member, member.id, exc)

        # --------------------------------------------------------------
        #  Finally – DM the user (if enabled) and post to the reports channel
        # --------------------------------------------------------------
        await self._send_dm_to_user(member, embed)
        await self._send_to_reports_channel(guild, embed)

    # ----------------------------------------------------------------
    #  Event listeners
    # ----------------------------------------------------------------
    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        await self.check_links(message)

    @commands.Cog.listener()
    async def on_message_edit(self, before: discord.Message, after: discord.Message) -> None:
        # ``before`` is ignored – we only care about the new content.
        await self.check_links(after)