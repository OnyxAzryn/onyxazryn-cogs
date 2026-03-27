# Logic adapted from https://github.com/Grommish/Grommish-Cogs/blob/main/virustotal/virustotal.py

from redbot.core import commands, Config, checks, modlog
from collections import deque
import time
import aiohttp
import discord
import datetime
import logging
import base64 # Used by API to encode URL for submission
import re
import urllib.parse

log = logging.getLogger("red.OnyxAzryn-Cogs.LinkGuardian")
log.setLevel(logging.DEBUG)  # Enable Debug level entries to goto the log

RATE_LIMIT = 4  # VirusTotal Free Tier: 4 requests per minute
TIME_WINDOW = 60  # Time window in seconds (1 minute)

class LinkGuardian(commands.Cog):
    """Check links for malicious content using VirusTotal."""
    # Set some static strings

    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=736848614378176543, force_registration=True)
        default_guild_settings = {
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
        self.request_times = deque()  # Track timestamps of API requests
        log.info("LinkGuardian Cog has loaded.")

    async def rate_limited(self, guild) -> bool:
        """Check if the rate limit has been exceeded for a specific guild."""
        debug = await self.config.guild(guild).debug()
        now = time.time()

        # Remove timestamps older than the time window
        while self.request_times and self.request_times[0] < now - TIME_WINDOW:
            self.request_times.popleft()

        # Check if we're within the rate limit
        if len(self.request_times) < RATE_LIMIT:
            self.request_times.append(now)
            if debug:
                log.debug(f"Current Rate is: {len(self.request_times)}")
            return False  # Not rate limited
        return True  # Rate limited

    # Use Standarized Calls to handle Secret Token/API
    async def get_api_key(self):
        # First, try to get the API key from shared API tokens
        shared_api_key = await self.bot.get_shared_api_tokens("virustotal")
        # Return api_key as the API token or None if it isn't set
        return shared_api_key.get("api_key", None)

    async def ensure_api_key(ctx):
        api = await ctx.bot.get_shared_api_tokens("virustotal")
        if not api or not api.get("api_key"):
            await ctx.send("VirusTotal API Missing.\n\nUse `[p]set api virustotal` and type `api_key <your_api_key>` in the popout box to set the API key")
            return False
        return True

    @commands.group(aliases=["lg"])
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def linkguardian(self, ctx):
        """Manage VirusTotal link checking."""
        pass

    @linkguardian.command(name="enable")
    @checks.admin_or_permissions(manage_guild=True)
    async def virustotal_toggle(self, ctx):
        """Toggle link checking."""
        enabled = await self.config.guild(ctx.guild).enabled()

        if not await self.ensure_api_key():
            # No API key is set
            return

        # Flip the current status
        await self.config.guild(ctx.guild).enabled.set(not enabled)
        await ctx.send(f"VirusTotal link checking is now {'enabled' if not enabled else 'disabled'}.")
        log.info(f"VirusTotal link checking is now {'enabled' if not enabled else 'disabled'}.")

    @linkguardian.command(name="reset")
    @checks.admin_or_permissions(manage_guild=True)
    async def reset_settings(self, ctx):
        """Reset VirusTotal settings to default."""
        await self.config.guild(ctx.guild).clear()
        await ctx.send("VirusTotal settings have been reset to default.")

    @linkguardian.command(name="status")
    @checks.admin_or_permissions(manage_guild=True)
    async def virustotal_status(self, ctx):
        """Show the current status of VirusTotal settings."""
        guild = ctx.guild
        embed = await self.get_status(guild)
        await ctx.send(embed=embed)

    @linkguardian.group(name="set")
    @checks.admin_or_permissions(manage_guild=True)
    async def linkguardian_setgroup(self, ctx):
        """Set various configurations for VirusTotal."""

    @linkguardian_setgroup.command(name="debug")
    @checks.admin_or_permissions(manage_guild=True)
    async def virustotal_debug(self, ctx):
        """Toggle debugging logs."""
        debug = await self.config.guild(ctx.guild).debug()
        await self.config.guild(ctx.guild).debug.set(not debug)
        await ctx.send(f"VirusTotal debug logging is now {'enabled' if not debug else 'disabled'}.")

    @linkguardian_setgroup.command(name="dmuser")
    @checks.admin_or_permissions(manage_guild=True)
    async def virustotal_dmuser(self, ctx):
        '''Enable/Disable Sending DM Notifications to the User'''
        dmuser = await self.config.guild(ctx.guild).dmuser()
        await self.config.guild(ctx.guild).dmuser.set(not dmuser)
        await ctx.send(f"VirusTotal {'will' if not dmuser else 'will not'} send a DM to the user when triggered.")

    @linkguardian_setgroup.command(name="exclude")
    @checks.admin_or_permissions(manage_guild=True)
    async def exclude_roles(self, ctx, *roles: discord.Role):
        """Exclude specified roles from link checking."""
        guild = ctx.guild
        excluded_roles = await self.config.guild(guild).excluded_roles()

        for role in roles:
            if role.id in excluded_roles:
                # Role already excluded, remove it from the list
                excluded_roles.remove(role.id)
            else:
                # Role not excluded, add it to the list
                excluded_roles.append(role.id)

        await self.config.guild(guild).excluded_roles.set(excluded_roles)

        # Build a formatted string listing the excluded roles
        if excluded_roles:
            excluded_roles_str = "\n".join([f"- {guild.get_role(role_id).name}" for role_id in excluded_roles])
        else:
            excluded_roles_str = "None"
        await ctx.send(f"The following roles have been excluded from VirusTotal link checking:\n{excluded_roles_str}")

    @linkguardian_setgroup.command(name="modlog")
    @checks.admin_or_permissions(manage_guild=True)
    async def set_modlog_channel(self, ctx, channel: discord.TextChannel):
        """Set the modlog channel where moderation actions like bans will be logged."""
        await self.config.guild(ctx.guild).modlog_channel.set(channel.id)
        await ctx.send(f"Modlog channel set to: {channel.mention}")

    @linkguardian_setgroup.command(name="punishment")
    @checks.admin_or_permissions(manage_guild=True)
    async def set_punishment(self, ctx, action: str, role: discord.Role = None, channel: discord.TextChannel = None):
        """Set punishment for sending malicious links."""
        action_type = action.lower()

        if action_type not in ["warn", "ban", "punish"]:
            return await ctx.send("Invalid action. Please choose 'warn', 'ban', or 'punish'.")

        # Punish action requires both a Role and a TextChannel to send them to.
        if action_type == "punish" and (not role or not channel):
            return await ctx.send("Please specify the role and channel to set for punishment.\r"
                                "Remember! You will NEED to set up the channel to be an appropriate Jail!")

        # Set the Action, Role, and Channel to Config
        await self.config.guild(ctx.guild).punishment_action.set(action_type)
        await self.config.guild(ctx.guild).punishment_role.set(role.id if role else None)
        await self.config.guild(ctx.guild).punishment_channel.set(channel.id if channel else None)

        if action_type == "ban": # Ban them!
            await ctx.send("Senders of malicious links will be banned.")
            await self.config.guild(ctx.guild).punishment_role.set(None)
        elif action_type == "punish": # Punish them!
            await ctx.send(f"Senders of malicious links will be punished with the role: {role.name} and limited to {channel.name}.\r"
                           "Remember! You will NEED to set up the channel to be an appropriate Jail!")
        else: # Defaults to Warn.
            await ctx.send("Senders of malicious links will be informed only.")
            await self.config.guild(ctx.guild).punishment_role.set(None)

    @linkguardian_setgroup.command(name="reportschannel")
    @checks.admin_or_permissions(manage_guild=True)
    async def set_reports_channel(self, ctx, channel: discord.TextChannel):
        """Set the channel where reports will be sent."""
        await self.config.guild(ctx.guild).report_channel.set(channel.id)
        await ctx.send(f"Reports channel set to: {channel.mention}")

    @linkguardian_setgroup.command(name="threshold")
    @checks.admin_or_permissions(manage_guild=True)
    async def set_threshold(self, ctx, threshold: int):
        """Set the threshold of number of malicious returns before taking action."""
        if threshold <= 0:
            await ctx.send("Please provide a non-negative number value for the threshold.")
            return

        try:
            # Attempt to set the threshold
            await self.config.guild(ctx.guild).threshold.set(threshold)
            await ctx.send(f"VirusTotal threshold set to {threshold} positive returns")
        except ValueError:
            # If the threshold provided is not an integer, notify the user
            await ctx.send("Please provide an number value for the threshold.")

    async def get_status(self, guild):
        """Get the current status of the VirusTotal cog."""
        api_key = await self.bot.get_shared_api_tokens("virustotal")  # Use the built in API Token handler

        # Load the Guild configuration information
        config = await self.config.guild(guild).all()

        debug = config["debug"]
        if debug:
            # !!SECURITY WARNING!!  This WILL display your API Token in plaintext in the logs
            log.debug(f"get_shared_api_tokens: {api_key}")

        # Get Cog Status
        enabled = config["enabled"]
        excluded_roles = config["excluded_roles"]

        punishment = config["punishment_action"]
        punishment_role_id = config["punishment_role"]
        punishment_role = guild.get_role(punishment_role_id) if punishment_role_id else None
        punishment_channel_id = await self.config.guild(guild).punishment_channel()
        punishment_channel = guild.get_channel(punishment_channel_id) if punishment_channel_id else None

        report_channel_id = config["report_channel"]
        report_channel = guild.get_channel(report_channel_id) if report_channel_id else None
        report_channel_name = report_channel.name if report_channel else "Not set"

        modlog_channel_id = config["modlog_channel"]  # New modlog channel configuration
        modlog_channel = guild.get_channel(modlog_channel_id) if modlog_channel_id else None  # Get modlog channel
        modlog_channel_name = modlog_channel.name if modlog_channel else "Not set"  # Determine modlog channel name

        threshold = config["threshold"]
        dmuser = config["dmuser"]

        # Create the Embed that will be returned with the above status
        embed = discord.Embed(title="VirusTotal Status", color=discord.Color.blue())
        embed.add_field(name="Link checking", value="✅ Enabled" if enabled else "❌ Disabled", inline=False)
        embed.add_field(name="VirusTotal API key", value="✅ Set" if api_key.get("api_key") is not None else "❌ Not set", inline=False)
        if punishment_role:
            embed.add_field(name="Action upon detection",
                            value = f"Punish them to `{punishment_role.name}` in `{punishment_channel.name}`\n",
                            inline=False)
        else:
            embed.add_field(name="Action upon detection",
                            value=f"{'Warn' if punishment == 'warn' else 'Ban'}",
                            inline=False)
        embed.add_field(name="Reports channel", value=report_channel_name, inline=False)
        embed.add_field(name="Modlog channel", value=modlog_channel_name, inline=False)
        embed.add_field(name="Threshold", value=str(threshold) + ' virus scanning vendors', inline=False)
        embed.add_field(name="Debug Logging", value="✅ Enabled" if debug else "❌ Disabled", inline=False)
        embed.add_field(name="DM User", value="✅ Enabled" if dmuser else "❌ Disabled", inline=False)

        if excluded_roles:
            excluded_roles_names = ", ".join([guild.get_role(role_id).name for role_id in excluded_roles])
            embed.add_field(name="Excluded roles from link checking", value=excluded_roles_names, inline=False)
        else:
            embed.add_field(name="Excluded roles from link checking", value="None", inline=False)

        return embed

    async def send_dm_to_user(self, member, embed):
        dmuser = await self.config.guild(member.guild).dmuser()

        # Is sending to DMs to user enabled?
        if not dmuser:
            log.error("send_dm_to_user: No User?")
            return
        else:
            try:
                await member.send(embed=embed)
            except discord.errors.Forbidden:
                log.warning("You do not have permissions to send a direct message to the user.")
            except discord.errors.HTTPException:
                log.warning("Sending a direct message to the user failed.")

    async def send_to_reports_channel(self, guild, embed):
        reports_channel_id = await self.config.guild(guild).report_channel()
        reports_channel = guild.get_channel(reports_channel_id)

        if not reports_channel:
            log.error("No Reports Channel has been defined!")
            return

        if reports_channel:
            try:
                await reports_channel.send(embed=embed)
            except discord.errors.Forbidden:
                log.warning("You do not have permissions to send messages to the reports channel.")
            except discord.errors.HTTPException:
                log.warning("Sending a message to the reports channel failed.")

    async def determine_mal_sus(self, num_malicious, num_suspicious, total_scanners):

        # Format the Title
        if num_malicious >= 1: # Malicious Link
            mal_sus = "Malicious "
            if num_suspicious >= 1:
                mal_sus += "and Suspicious "
        elif num_suspicious >= 1:
            mal_sus = "Suspicious "

        mal_sus += "Link Found"

        # Format the Description
        if num_malicious >= 1: # Malicious Link
            message_content = f"Found Malicious by: {num_malicious} of {total_scanners} virus scanners"
            if num_suspicious >= 1:
                message_content += f"\nFound Suspicious by: {num_suspicious} of {total_scanners} virus scanners"
        elif num_suspicious >= 1:
            message_content = f"Found Suspicious by: {num_suspicious} of {total_scanners} virus scanners"

        # Send back the results
        return mal_sus, message_content # Title and Description

    async def check_links(self, message):
        """Async Task for Link checking"""
        # Ignore messages from DMs or the bot itself
        if not message.guild or message.author.bot:
            return  # Ignore if message is not from a guild or the author is the bot

        author = message.author
        guild = author.guild

        # Load the Guild configuration information
        config = await self.config.guild(guild).all()

        debug = config["debug"]
        threshold = config["threshold"]
        api_key = await self.bot.get_shared_api_tokens("virustotal")

        # Extract the API key
        api_key_value = api_key.get("api_key", None)
        if not api_key_value:
            log.error("VirusTotal API key is missing!")
            return  # Handle missing API key gracefully

        headers = {"x-apikey": api_key_value}

        # Improved regular expressions
        url_regex = r'https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?:[/?#][^\s]*)?'
        ipv4_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ipv6_regex = r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'

        # Combine all address matches
        urls = re.findall(url_regex, message.content)
        ipv4_addresses = re.findall(ipv4_regex, message.content)
        ipv6_addresses = re.findall(ipv6_regex, message.content)

        all_addresses = set(urls + ipv4_addresses + ipv6_addresses)
        # If all_addresses is empty, there is no point processing the rest.
        if not all_addresses:
            return

        if await self.rate_limited(guild):
            log.warning("API Rate limit exceeded! Skipping VirusTotal checks.")
            return  # Skip API calls if rate limit is exceeded

        if debug:
            log.debug(f"Addresses found: {all_addresses}")

        async with aiohttp.ClientSession() as session:
            for address in all_addresses:
                log.debug(f"Checking address: {address}")

                # Determine if the address is an IP or a URL
                parsed_address = urllib.parse.urlparse(address)
                host_address = parsed_address.hostname or address  # Use the hostname if URL, else the raw address

                if re.match(ipv4_regex, host_address) or re.match(ipv6_regex, host_address):
                    url = f"https://www.virustotal.com/api/v3/ip_addresses/{host_address}"
                    scan_type = "ip"
                else:
                    encoded_url = base64.urlsafe_b64encode(address.encode()).decode().strip("=")
                    url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
                    scan_type = "url"

                if debug:
                    log.debug(f"API URL: {url} (Type: {scan_type})")

                # Perform the API request
                async with session.get(url, headers=headers) as response:
                    if response.status != 200:
                        log.error(f"[ERROR] VirusTotal API request failed with status code {response.status}")
                        continue

                    json_response = await response.json()
                    analysis_results = json_response.get("data", {}).get("attributes", {}).get("last_analysis_results", {})

                    # Exclude Quttera engine due to false positives, and calculate totals
                    analysis_results.pop("Quttera", None)
                    # Exclude CRDF, who returns 0.0.0.0 as Malicious
                    analysis_results.pop("CRDF", None)

                    malicious_engines = [engine for engine, result in analysis_results.items() if result['category'] == 'malicious']
                    suspicious_engines = [engine for engine, result in analysis_results.items() if result['category'] == 'suspicious']

                    malicious = len(malicious_engines)
                    suspicious = len(suspicious_engines)
                    total_scanners = len(analysis_results)

                    if debug:
                        log.debug(f"Results: Malicious={malicious}, Suspicious={suspicious}, Scanners={total_scanners}, Threshold={threshold}")
                        log.debug(f"Malicious Engines: {malicious_engines}")
                        log.debug(f"Suspicious Engines: {suspicious_engines}")

                    # Trigger handling logic if threshold is breached
                    if (malicious >= 1) or (suspicious >= threshold):

                        link = address if scan_type == "ip" else json_response["data"]["attributes"].get("url", address)
                        await self.handle_bad_link(
                            guild, message, malicious, suspicious, total_scanners, link, malicious_engines, suspicious_engines
                        )

    async def handle_bad_link(self, guild, message, num_malicious: int, num_suspicious: int, total_scanners: int, link, malicious_engines: list, suspicious_engines: list):
        member = message.author

        # Load the Guild configuration information
        config = await self.config.guild(guild).all()
        debug = config["debug"]

        # Excluded Role IDs

        excluded_roles = config["excluded_roles"]
        punishment = config["punishment_action"]
        punishment_channel_id = config["punishment_channel"]
        punishment_channel = guild.get_channel(int(punishment_channel_id)) if punishment_channel_id else None

        if debug:
            log.debug(f"PUNISH: {punishment}")

        # Build out Embed Title and Description
        title, description = await self.determine_mal_sus(num_malicious, num_suspicious, total_scanners)

        # Build engine details
        malicious_engines_str = ', '.join(malicious_engines) if malicious_engines else 'None'
        suspicious_engines_str = ', '.join(suspicious_engines) if suspicious_engines else 'None'
        member_info = f"{member.name} ({member.id})"

        # Create the embed
        embed = discord.Embed(title=title, description=description, color=discord.Color.red())
        embed.add_field(name="User", value=member_info, inline=False)
        embed.add_field(name="Link", value=link, inline=False)
        embed.add_field(name="Malicious Engines", value=malicious_engines_str, inline=False)
        embed.add_field(name="Suspicious Engines", value=suspicious_engines_str, inline=False)
        embed.set_footer(text=f"Total Scanners: {total_scanners}")

        # The Link is Malicious
        if num_malicious >= 1:
            if punishment == "ban":  # Ban the Sender
                try:
                    # Log the ban to the modlog using the Modlog cog API
                    await modlog.create_case(
                        self.bot,
                        guild,
                        message.created_at,
                        user=member,
                        moderator=guild.me,
                        reason="Malicious link detected",
                        action_type="ban"
                    )

                    log.info(f"Modlog case created for banning user {member.name} ({member.id}) due to malicious link.")
                except RuntimeError:  # modlog channel isn't set
                    pass
                except discord.Forbidden:
                    log.warning(f"Modlog failed regarding modlog case creation for {member.name} ({member.id}) due to missing permissions.")
                except Exception as e:
                    log.exception(f"Modlog failed to create case for {member.name} ({member.id}) due to an unexpected error: {e}.")

                try:
                    await message.guild.ban(member, reason="Malicious link detected")
                except discord.errors.Forbidden:
                    log.error(f"Bot does not have proper permissions to ban the user {member.name} ({member.id})")

            elif punishment == "punish":  # This is when it's set to Punish
                embed.add_field(
                    name="Alert!",
                    value=f"You have sent a link that is considered malicious and have been disabled from sending further messages.\nYou can appeal this status in `{punishment_channel.name}` channel.",
                    inline=False
                )

                # Modlog - Open the case
                try:
                    if debug:
                        log.debug("Entering Punishment Modlog")

                    await modlog.create_case(
                        self.bot,
                        guild,
                        message.created_at,
                        user=member,
                        moderator=guild.me,
                        reason="Malicious link detected",
                        action_type="softban"
                    )

                    log.info(f"Modlog case created for punishing user {member} due to malicious link.")
                except TypeError as e:
                    log.error(f"TypeError while creating a modlog case: {e}")
                except discord.Forbidden as e:
                    log.error(f"Insufficient permissions to create a modlog case: {e}")
                except discord.HTTPException as e:
                    log.error(f"HTTPException occurred while creating a modlog case: {e}")
                except ValueError as e:
                    log.error(f"ValueError while creating a modlog case: {e}")
                except RuntimeError as e:
                    log.error(f"RuntimeError in modlog case creation: {e}")
                except Exception as e:  # Catch-all for any other exceptions
                    log.error(f"An unexpected error occurred while creating a modlog case: {e}")

                # Do the Punishing
                try:
                    # Remove all roles from the user except @everyone
                    roles_to_remove = [role for role in member.roles if role != guild.default_role]
                    await member.remove_roles(*roles_to_remove)

                    # Assign the punishment role
                    punishment_role_id = await self.config.guild(message.guild).punishment_role()
                    if punishment_role_id:
                        punishment_role = message.guild.get_role(punishment_role_id)
                        await member.add_roles(punishment_role)

                except discord.errors.Forbidden:
                    log.warning(f"Bot does not have permissions to manage roles for {member.name} ({member.id}).")
                except discord.errors.HTTPException:
                    log.warning(f"Managing roles for {member.name} failed.")

            # Handle the Link in the Message
            try:
                if not any(role.id in excluded_roles for role in member.roles):
                    await message.delete()
            except discord.errors.NotFound:
                log.warning("Message not found or already deleted.")
            except discord.errors.Forbidden:
                log.warning(f"Bot does not have proper permissions to delete the message from {member.name} ({member.id})")
            except discord.errors.HTTPException:
                log.warning("Deleting the message failed.")

        if debug:
            log.debug(f"Link: {link}")

        # Send to the Reports channel
        await self.send_dm_to_user(member, embed)
        await self.send_to_reports_channel(guild, embed)

    async def log_to_modlog_channel(self, guild, member, reason):
        """Log moderation actions like bans to the configured modlog channel."""
        modlog_channel_id = await self.config.guild(guild).modlog_channel()
        modlog_channel = guild.get_channel(modlog_channel_id)

        if modlog_channel:
            embed = discord.Embed(
                title="User Banned",
                description=f"**User:** {member} ({member.id})\n**Reason:** {reason}",
                color=discord.Color.red(),
                timestamp=datetime.datetime.utcnow(),
            )
            embed.set_footer(text=f"Guild: {guild.name}")
            try:
                await modlog_channel.send(embed=embed)
            except discord.errors.Forbidden:
                log.warning("You do not have permissions to send messages to the modlog channel.")
            except discord.errors.HTTPException:
                log.warning("Sending a message to the modlog channel failed.")
        else:
            log.warning("Modlog channel is not set.")

    @commands.Cog.listener()
    async def on_message(self, message):
        await self.check_links(message)

    @commands.Cog.listener()
    async def on_message_edit(self, before, after):
        await self.check_links(after)
