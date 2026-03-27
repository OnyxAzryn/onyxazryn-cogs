from redbot.core.bot import Red

from .linkguardian import LinkGuardian

async def setup(bot: Red):
    await bot.add_cog(LinkGuardian(bot))
