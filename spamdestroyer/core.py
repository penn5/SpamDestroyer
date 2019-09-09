import telethon
import json
import re
import asyncio
import logging
import shutil
import functools
import shlex

from telethon.tl.custom.button import Button
from telethon.tl.functions.messages import DeleteChatUserRequest


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
ImageHashBlacklisted = GbanReason.sub("ImageHashBlackisted", 0x2)
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
ProfilePicHashBlacklisted = GbanReason.sub("ProfilePicHashBlacklisted", 0xe)
NoProfilePic = GbanReason.sub("NoProfilePic", 0xf)


def eh(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class SpamBlocker:
    checkers = {}

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
                logging.debug("Gbanning user for adding gbanned user")
                adder = event.action_message.action.inviter_id
                adder_stat = self.storage.get_gban_stat(adder)
                if adder_stat is not None:
                    adder_stat = GbanReason.from_str(adder_stat["raw_reason"])
                adder_stat += AddedGbannedUser(stat["total_severity"], event.user_id, stat["raw_reason"])
                await self.gban_triggered(event, adder_stat)
            await self.ban_user(await event.get_input_chat(), await event.get_input_user())

    async def ban_user(self, chat, user):
        try:
            try:
                await self.tl_client.edit_permissions(chat, user,
                                                      send_messages=False, change_info=False,
                                                      invite_users=False, pin_messages=False)
            except ValueError:
                await self.tl_client(DeleteChatUserRequest(chat, user))
        except telethon.errors.rpcerrorlist.ChatAdminRequiredError:
            await self.tl_client.send_message(chat,
                                              "<a href='tg://user?id={id}'>".format(id=getattr(user, "user_id", user))
                                              + "This user</a> is a spammer or scammer and should be banned.")

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
            await event.answer("Unfortunately, your request requires manual review. Please go to @SpamDestroyers.",
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

    async def run_checks(self, message, checks):
        final = None
        logging.debug(checks)
        # The functions aren't bound because they are evaluated at class init time, not instance
        results = await asyncio.gather(*[check(self, message) for check in checks], return_exceptions=True)
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
            await self.ban_user(message.to_id, message.from_id)

        lastlvl = -1
        final = CompoundReason()
        while True:
            if lastlvl < final.severity:
                lastlvl += 1
            else:
                return
            final += await self.run_checks(message, self.checkers.get(lastlvl, []))
            if final.severity > 8:
                return await self.gban_triggered(message, final)

    async def gban_triggered(self, message, final):
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

    async def gban_user(self, uid, reason):
        self.storage.gban_user(uid, reason)

    @classmethod
    def reg(self, level):
        def reg2(func):
            self.checkers.setdefault(level, []).append(func)
            return func
        return reg2


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
