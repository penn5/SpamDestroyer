import telethon
from telethon.tl.custom.button import Button
from telethon.tl.functions.channels import EditBannedRequest
from telethon.tl.types import ChatBannedRights

from PIL import Image
import imagehash
import io

import aiohttp

import asyncio
import json
import re
import shutil
import unicodedata
import functools
import concurrent
import shlex

from gglsbl import SafeBrowsingList

from . import api_token

import logging
logging.basicConfig(level=logging.DEBUG)


def run_sync(executor, func, *args, **kwargs):
    return asyncio.get_event_loop().run_in_executor(executor, functools.partial(func, *args, **kwargs))


class GbanReason:
    id = -1
    subs = {}

    @staticmethod
    def sub(name, id):
        ret = type(name, (GbanReason,), {"id": id})
        GbanReason.subs[id] = ret
        return ret

    def __init__(self, severity, *args):
        self.severity = severity
        self.args = ",".join([repr(arg) for arg in args])
        self.chatid = None
        self.msgid = None

    def __repr__(self):
        return "{}/{}:{}({}:{})".format(self.chatid or "?", self.msgid or "?", type(self).__name__,
                                        self.args, self.severity)

    def __str__(self):
        return ",".join([str(self.id),
                         str(self.chatid) if self.chatid is not None else "?",
                         str(self.msgid) if self.chatid is not None else "?",
                         str(self.severity), self.args])

    @staticmethod
    def from_str(s):
        split = s.split(",", 4)
        if int(split[0]) == -2:
            return CompoundReason.from_str(s)
        s = split
        del split
        ret = GbanReason.subs.get(int(s[0]), GbanReason)(int(s[3]), s[4])
        try:
            ret.chatid = int(s[1])
        except ValueError:
            pass
        try:
            ret.msgid = int(s[2])
        except ValueError:
            pass
        return ret

    def __add__(self, other):
        return CompoundReason(self, other)

    def __radd__(self, other):
        if other is None:
            return self
        else:
            return NotImplemented

    def update_for_message(self, message):
        chat = message.to_id
        attrs = vars(chat)
        if len(attrs) != 1:
            chatid = "?"
        else:
            chatid = next(iter(attrs.values()))
        self.chatid = chatid
        self.msgid = message.id


class CompoundReason(GbanReason):
    id = -2

    def __init__(self, *reasons):
        super().__init__(sum([reason.severity for reason in reasons]))
        self.reasons = []
        for reason in reasons:
            if isinstance(reason, CompoundReason):
                self.reasons += reason.reasons
            else:
                self.reasons += [reason]

    def __repr__(self):
        return " + ".join([repr(reason) for reason in self.reasons])

    def __str__(self):
        return str(self.id) + "," + ("+".join([str(reason).replace("+", "++") for reason in self.reasons]))

    def __add__(self, other):
        if other is None:
            return self
        return type(self)(*(self.reasons + [other]))

    def __radd__(self, other):
        if other is None:
            return self
        return type(self)(*([other] + self.reasons))

    def update_for_message(self, *args, **kwargs):
        for reason in self.reasons:
            reason.update_for_message(*args, **kwargs)
        return super().update_for_message(*args, **kwargs)

    @staticmethod
    def from_str(s):
        s = s.split(",", 1)[1]
        # un-escape + signs
        # horribly inefficient but it works
        skip = False
        o = ""
        for i in range(len(s)):
            if skip:
                skip = False
                continue
            if s[i] == "+" and s[i+1:i+2] == "+":
                skip = True
            o += s[i]
        s = o.split("+")
        o = []
        for i in s:
            o += [GbanReason.from_str(i)]
        return CompoundReason(*o)


MessageEditedRecently = GbanReason.sub("MessageEditedRecently", 0x0)
MessageContainsPhoto = GbanReason.sub("MessageContainsPhoto", 0x1)
ImageHashBlackisted = GbanReason.sub("ImageHashBlackisted", 0x2)
MessageTextBlacklisted = GbanReason.sub("MessageTextBlacklisted", 0x3)
MessageContainsLink = GbanReason.sub("MessageContainsLink", 0x4)
UrlBlacklisted = GbanReason.sub("UrlBlacklisted", 0x5)
ForwardUserBlacklisted = GbanReason.sub("ForwardUserBlacklisted", 0x6)
BioTextBlacklisted = GbanReason.sub("BioTextBlacklisted", 0x7)
BioTextEmpty = GbanReason.sub("BioTextEmpty", 0x8)
NameTextBlacklisted = GbanReason.sub("NameTextBlacklisted", 0x9)
MessageContainsRtl = GbanReason.sub("MessageContainsRtl", 0xa)
MessageContainsMention = GbanReason.sub("MessageContainsMention", 0xb)
ManuallyBlacklisted = GbanReason.sub("ManuallyBlacklisted", 0xc)
AddedGbannedUser = GbanReason.sub("AddedGbannedUser", 0xd)


def eh(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class SpamBlocker:
    def __init__(self, tl):
        self.http_session = None
        self.tl_client = tl
        tl.add_event_handler(self.check, telethon.events.newmessage.NewMessage(incoming=True))
        tl.add_event_handler(self.check, telethon.events.messageedited.MessageEdited(incoming=True))
        tl.add_event_handler(self.userjoin, telethon.events.chataction.ChatAction())
        tl.add_event_handler(self.appealflow, telethon.events.callbackquery.CallbackQuery(data=b"human"))
        tl.add_event_handler(self.startcmd, telethon.events.newmessage.NewMessage(incoming=True,
                                                                                  pattern="/start(?: (.*))?"))
        tl.add_event_handler(self.gbancmd, telethon.events.newmessage.NewMessage(incoming=True, pattern="/gban (.+)"))
        tl.add_event_handler(self.statcmd, telethon.events.newmessage.NewMessage(incoming=True,
                                                                                 pattern="/stat(?: ([0-9]{1,9}))?"))
        self.storage = BlacklistStorage("blacklist.json")
        self.gsb = None

    async def statcmd(self, event):
        stat = self.storage.get_gban_stat(event.from_id)
        if stat is None:
            await event.reply("<code>" + str(event.pattern_match[1]) + "</code> is not banned")
        else:
            await event.reply("<code>" + str(event.pattern_match[1]) + "</code> is globally banned:\n"
                              + "\n<b>Severity<b>: <code>" + eh(str(stat["total_severity"]))
                              + "</code>\n<b>Reason</b>: <code>" + eh(repr(GbanReason.from_str(stat["raw_reason"])))
                              + "</code>")

    async def userjoin(self, event):
        if not (event.user_added or event.user_joined):
            return
        stat = self.storage.get_gban_stat(event.user_id)
        if stat is not None:
            if event.user_added:
                adder = (await event.get_added_by()).id
                adder_stat = self.storage.get_gban_stat(adder)
                if adder_stat is not None:
                    adder_stat = GbanReason.from_str(adder_stat["raw_reason"])
                adder_stat += AddedGbannedUser(stat["total_severity"], event.user_id, stat["raw_reason"])
                await self.storage.gban_user(adder, adder_stat)
                await event.client(EditBannedRequest(await event.get_input_chat(), await event.get_added_by(),
                                                     ChatBannedRights(until_date=None, view_messages=True)))
            await event.client(EditBannedRequest(await event.get_input_chat(), await event.get_input_user(),
                                                 ChatBannedRights(until_date=None, view_messages=True)))

    async def startcmd(self, event):
        if not isinstance(event.to_id, telethon.tl.types.PeerUser):
            return
        dat = ""
        if len(event.pattern_match.groups()) == 1:
            dat = event.pattern_match[1]
        if dat == "appeal":
            await event.respond("Click the button below to confirm you are human",
                                buttons=Button.inline("Click Me", "human"))
        else:
            await event.respond("Hello! Add me to a group to benefit from accurate automated gbans!")

    async def appealflow(self, event):
        stat = self.storage.get_gban_stat(event.sender_id)
        if stat is None:
            await event.answer("You aren't gbanned! Have fun!")
        elif stat["total_severity"] > 10:
            await event.answer("Unfortunately, your request requires manual review. Please wait for a response.",
                               alert=True)
            # TODO notify sudo user
        else:
            # TODO better system?
            print("UNGBAN " + str(event.sender_id))
            self.storage.gban_user(event.sender_id, None)
            await event.answer("Your account has been freed", alert=True)

    async def gbancmd(self, event):
        if not self.storage.is_user_sudo(event.from_id):
            return
        dat = shlex.split(event.pattern_match[1], " ")
        cmd = dat[0]
        args = dat[1:]
        message = await event.get_reply_message()
        if cmd == "img":
            if len(args) != 1:
                await event.edit("E: bad args")
                return
            if message.photo is None:
                await event.edit("E: no photo found")
                return
            self.storage.add_image_hash(await self.get_photo_hash(message), int(args[0]))
        elif cmd == "user":
            if len(args) != 1:
                await event.edit("E: bad args")
                return
            if args[0] == "fwd":
                if not message.fwd_from:
                    await event.edit("E: not a forward")
                    return
                if message.fwd_from.from_id is None:
                    await event.edit("E: forward privacy is on")
                    return
                uid = message.fwd_from.from_id
            elif args[0] == "user":
                uid = message.from_id
            else:
                try:
                    uid = int(args[0], 10)
                except ValueError:
                    await event.edit("E: unable to parse uid")
                    return
            self.storage.add_user_blacklist(uid)

    async def run_checks(self, message, *checks):
        final = None
        results = await asyncio.gather(*[check(message) for check in checks], return_exceptions=True)
        for result in results:
            if isinstance(result, GbanReason):
                final += result
            elif isinstance(result, Exception):
                logging.exception("Checker failed:", exc_info=result)
            else:
                logging.debug("Check passed")
        if final is not None:
            final.update_for_message(message)
        return final

    async def check(self, event):
        message = event.message
        cur_stat = self.storage.get_gban_stat(message.from_id)
        if cur_stat is not None:
            # Apply gban
            await message.delete()
            await message.client(EditBannedRequest(message.to_id, message.from_id,
                                                   ChatBannedRights(until_date=None, view_messages=True)))

        lastlvl = -1
        final = CompoundReason()
        acted = -1
        while final.severity > lastlvl:
            lastlvl = final.severity
            if final.severity > 6 and acted == 1:
                final += await self.run_checks(message, self.check_uid)
                acted = 6
            elif final.severity > 1 and acted == 0:
                final += await self.run_checks(message, self.check_image_2, self.check_entities_2)
                acted = 1
            elif acted == -1:
                final += await self.run_checks(message, self.check_text, self.check_entities,
                                               self.check_image, self.check_edit)
                acted = 0

            if final.severity > 8:
                print("BAN {} because {}!".format(message.from_id, repr(final)))
                await message.delete()
                m2 = await message.reply(("<b>⚠️ Gban Initated ⚠️</b>\n\n"
                                          + "<a href='tg://user?id={uid}'>Your account</a>"
                                          + " was detected as a spammer or scammer. "
                                          + "If you believe this was in error,  "
                                          + "<a href='https://t.me/{un}?start=appeal'>"
                                          + "click here </a></b>\n"
                                          + "If no action is taken, your account will be <b>banned</b>!\n\n"
                                          + "<i>This message will self-destruct soon</i>")
                                         .format(un=(await self.tl_client.get_me()).username,
                                                 uid=message.from_id))
                if "FORCE_GBAN" in message.message or not self.storage.is_user_sudo(message.from_id):
                    self.storage.gban_user(message.from_id, final)
                await asyncio.sleep(240)
                await m2.delete()
                return

    async def gban_user(self, uid, reason):
        self.storage.gban_user(uid, reason)

    async def check_edit(self, message):
        reason = None
        if message.edit_date:
            if message.date.timestamp() + 10 < message.edit_date:
                reason = MessageEditedRecently(2)
            elif message.date.timestamp() + 120 < message.edit_date:
                reason = MessageEditedRecently(0.5)
        return reason

    async def check_image(self, message):
        if message.photo is not None:
            return MessageContainsPhoto(1)

    async def check_image_2(self, message):
        if message.photo is None:
            return
        hash = await self.get_photo_hash(message)
        severity = self.storage.check_image_hash(hash)
        if severity > 0:
            return ImageHashBlackisted(severity, str(hash))

    async def get_photo_hash(self, message):
        image = io.BytesIO()
        try:
            await message.download_media(image)
            image.seek(0)
            img = Image.open(image)
        finally:
            del image
        try:
            return imagehash.phash(img, hash_size=16)
        finally:
            img.close()

    async def get_pfp_hash(self, userfull, client):
        image = io.BytesIO()
        try:
            await client.download_profile_photo(userfull, image)
            image.seek(0)
            img = Image.open(image)
        finally:
            del image
        try:
            return imagehash.phash(img, hash_size=16)
        finally:
            img.close()

    async def check_text(self, message):
        text = message.message
        result = self.storage.check_text(text)
        ret = None
        for txt, severity in result.items():
            ret += MessageTextBlacklisted(severity, txt)
        rtl = False
        for char in text:
            if unicodedata.bidirectional(char) == "AL":
                # Arabic Letter
                rtl = True
        if rtl:
            ret += MessageContainsRtl(3)
        return ret

    async def check_entities(self, message):
        text = message.message
        entities = message.entities
        if entities is None:
            return
        ret = None
        for entity in entities:
            if isinstance(entity, telethon.tl.types.MessageEntityUrl):
                ret += MessageContainsLink(1)
                severity = self.storage.check_url(text[entity.offset:entity.offset + entity.length])
                if severity > 0:
                    ret += UrlBlacklisted(severity,
                                          text[entity.offset:entity.offset + entity.length])
            if isinstance(entity, telethon.tl.types.MessageEntityMention):
                ret += MessageContainsMention(2)
        return ret

    async def check_entities_2(self, message):
        entities = message.entities
        if entities is None:
            return
        text = message.message
        if self.http_session is None or 1:
            self.http_session = aiohttp.ClientSession()
        ret = None
        async with self.http_session as session:
            for entity in entities:
                if isinstance(entity, telethon.tl.types.MessageEntityUrl):
                    check_gsb = False
                    url = text[entity.offset:entity.offset + entity.length]
                    severity = self.storage.check_url(text[entity.offset:entity.offset + entity.length])
                    if severity > 0:
                        continue  # Dealt with in check_entities
                    async with session.get(url, allow_redirects=False) as response:
                        if response.status in [301, 302]:  # It's quite simple and doesn't do JS
                            url = response.headers.get("Location", None)
                            if not url:
                                continue
                            severity = self.storage.check_url(url)
                            if severity > 0:
                                self.storage.add_url_blacklist(url, severity + 1)  # Cache it
                                ret += UrlBlacklisted(severity + 1, text, entity.offset, entity.length)
                            else:
                                check_gsb = True
                        else:
                            check_gsb = True
                    if check_gsb:
                        if self.gsb is None:
                            self.gsb_executor = concurrent.futures.ThreadPoolExecutor(1)
                            self.gsb = await run_sync(self.gsb_executor, SafeBrowsingList, api_token.GSB_KEY)
#                            await run_sync(self.gsb_executor, self.gsb.update_hash_prefix_cache)
                        threats = await run_sync(self.gsb_executor, self.gsb.lookup_url, url)
                        if threats:
                            ret += UrlBlacklisted(4, "GSB", threats)
        return ret

    async def check_fwd(self, message):
        fwd_header = message.fwd_from
        if not fwd_header:
            return None
        if self.storage.check_uid(fwd_header.from_id):
            return ForwardUserBlacklisted(4, fwd_header.from_id, fwd_header.from_name, fwd_header.channel_id)

    async def check_uid(self, message):
        uid = message.from_id
        ret = None
        full_user = await self.tl_client(telethon.functions.users.GetFullUserRequest(uid))
        if full_user.about:
            matches = self.storage.check_text(full_user.about)
            for txt, severity in matches.items():
                if severity > 0:
                    ret += BioTextBlacklisted(severity, txt)
        else:
            ret += BioTextEmpty(1)
        matches = self.storage.check_text(full_user.user.first_name)
        for txt, severity in matches.items():
            if severity > 0:
                ret += NameTextBlacklisted(severity, txt)
        if full_user.user.last_name:
            matches = self.storage.check_text(full_user.user.last_name)
            for txt, severity in matches.items():
                if severity > 0:
                    ret += NameTextBlacklisted(severity, txt)
        return ret

    async def check_manuals(self, message):
        full_user = await self.tl_client(telethon.functions.users.GetFullUserRequest(message.from_id))
        manuals = self.storage.manuals
        for manual in manuals:
            if message.from_id < manual["min_uid"]:
                continue
            if (message.photo is None) is (manual["photo"] is not False):
                continue
            if message.photo and await self.get_photo_hash(message) != manual["photo"]:
                continue
            present = True
            for keyword in manual["keywords"]:
                if not re.search(keyword, message.message, re.I):
                    present = False
                    break
            if not present:
                continue
            if (full_user.profile_photo is None) is (manual["pfp"] is not False):
                continue
            if full_user.profile_photo and await self.get_pfp_hash(full_user) != manual["photo"]:
                continue
            if manual["first_name"] and manual["first_name"] != full_user.first_name:
                continue
            if (full_user.last_name is None) is (manual["last_name"] is not False):
                continue
            if full_user.last_name and full_user.last_name != manual["last_name"]:
                continue
            return ManuallyBlacklisted(manual["severity"], manual["id"], *manual["reasonData"])


class BlacklistStorage:
    def __init__(self, filename):
        self._filename = filename
        with open(filename, "r") as f:
            self._data = json.load(f)
        end = r"(^|$|\W)"
        self._blacklist_text = [(re.compile(end + text + end, re.I), severity)
                                for text, severity in self._data["text"].items()]
        self._blacklist_images = self._data["imgs"]
        self._blacklist_urls = self._data["urls"]
        self._blacklist_uids = self._data["uids"]
        self._sudo_users = self._data["sudo"]

    def _save(self):
        shutil.move(self._filename, self._filename + ".bak")
        with open(self._filename, "w") as f:
            json.dump(self._data, f, indent=2)

    def check_text(self, text):
        ret = {}
        for regex, severity in self._blacklist_text:
            match = regex.search(text)
            if match:
                ret[match[0].strip()] = severity
        return ret

    def check_image_hash(self, hash):
        return self._blacklist_images.get(str(hash), 0)

    def check_url(self, url):
        for blacked, severity in self._blacklist_urls.items():
            if blacked in url:
                return severity
        return 0

    def is_user_sudo(self, uid):
        return isinstance(uid, int) and uid > 0 and uid in self._sudo_users

    def add_image_hash(self, hash, severity):
        self._blacklist_images[str(hash)] = severity
        self._save()

    def gban_user(self, uid, reason):
        if reason is None:
            del self._blacklist_uids[str(uid)]
        else:
            self._blacklist_uids[str(uid)] = {"total_severity": reason.severity, "raw_reason": str(reason)}
        self._save()

    def get_gban_stat(self, uid):
        return self._blacklist_uids.get(str(uid), None)


def main():
    client = telethon.TelegramClient("SpamDestroyerBot", api_token.ID, api_token.HASH).start(bot_token=api_token.TOKEN)
    client.parse_mode = "HTML"
    with client:
        SpamBlocker(client)
        client.loop.run_until_complete(client.catch_up())
        client.run_until_disconnected()


if __name__ == "__main__":
    main()
