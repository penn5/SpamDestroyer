import telethon

from . import api_token, checkers

import logging
logging.basicConfig(level=logging.DEBUG)


def main():
    client = telethon.TelegramClient("SpamDestroyerBot", api_token.ID, api_token.HASH).start(bot_token=api_token.TOKEN)
    client.parse_mode = "HTML"
    client.loop.run_until_complete(amain(client))

async def amain(client):
    async with client:
        async with checkers.SpamChecker(client):
            await client.catch_up()
            await client.run_until_disconnected()

if __name__ == "__main__":
    main()
