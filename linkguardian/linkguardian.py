from redbot.core import commands

class LinkGuardian(commands.Cog):
    """Link Guardian Cog"""

    def __init__(self, bot):
        self.bot = bot

    @commands.is_owner()
    @commands.command()
    async def myCom(self, ctx):
        """This does stuff!"""
        # Your code will go here
        await ctx.send("I can do stuff!")