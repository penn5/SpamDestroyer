import telethon

from . import api_token, checkers

import logging
logging.basicConfig(level=logging.DEBUG)


def main():
    client = telethon.TelegramClient("SpamDestroyerBot", api_token.ID, api_token.HASH).start(bot_token=api_token.TOKEN)
    client.parse_mode = "HTML"
    with client:
        checkers.SpamChecker(client)
        client.loop.run_until_complete(client.catch_up())
        client.run_until_disconnected()


if __name__ == "__main__":
    main()
