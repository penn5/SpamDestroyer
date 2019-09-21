from . import api_token
from .core import SpamBlocker, MessageEditedRecently, MessageContainsPhoto, ImageHashBlacklisted
from .core import MessageTextBlacklisted, MessageContainsLink, UrlBlacklisted, ForwardUserBlacklisted
from .core import BioTextBlacklisted, BioTextEmpty, NameTextBlacklisted, MessageContainsRtl, MessageContainsMention
from .core import ManuallyBlacklisted, ProfilePicHashBlacklisted, NoProfilePic

import telethon

import asyncio
import functools

from PIL import Image
import imagehash

import unicodedata
import io

import aiohttp
from gglsbl import SafeBrowsingList
import concurrent

import re


def run_sync(executor, func, *args, **kwargs):
    return asyncio.get_event_loop().run_in_executor(executor, functools.partial(func, *args, **kwargs))


class SpamChecker(SpamBlocker):
    async def __aenter__(self):
        self.http_session = aiohttp.ClientSession()

    async def __aexit__(self):
        if self.http_session is not None:
            await self.http_session.close()

    @SpamBlocker.reg(0)
    async def check_edit(self, message):
        reason = None
        if message.edit_date:
            if message.date.timestamp() + 10 < message.edit_date.timestamp():
                reason = MessageEditedRecently(2)
            elif message.date.timestamp() + 120 < message.edit_date.timestamp():
                reason = MessageEditedRecently(0.5)
        return reason

    @SpamBlocker.reg(0)
    async def check_image(self, message):
        if message.photo is not None:
            return MessageContainsPhoto(1)

    @SpamBlocker.reg(1)
    async def check_image_2(self, message):
        if message.photo is None:
            return
        hash = await self.get_photo_hash(message)
        severity = self.storage.check_image_hash(hash)
        if severity > 0:
            return ImageHashBlacklisted(severity, str(hash))

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

    async def get_pfp_hash(self, userfull):
        image = io.BytesIO()
        try:
            await self.tl_client.download_profile_photo(userfull.user.id, image)
            image.seek(0)
            img = Image.open(image)
        finally:
            del image
        try:
            return imagehash.phash(img, hash_size=16)
        finally:
            img.close()

    @SpamBlocker.reg(0)
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

    @SpamBlocker.reg(0)
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

    @SpamBlocker.reg(1)
    async def check_entities_2(self, message):
        entities = message.entities
        if entities is None:
            return
        text = message.message
        ret = None
        for entity in entities:
            if isinstance(entity, telethon.tl.types.MessageEntityUrl):
                check_gsb = False
                url = text[entity.offset:entity.offset + entity.length]
                severity = self.storage.check_url(text[entity.offset:entity.offset + entity.length])
                if severity > 0:
                    continue  # Dealt with in check_entities
                response = self.http_session.get(url, allow_redirects=False)
                await response.release()
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
#                        await run_sync(self.gsb_executor, self.gsb.update_hash_prefix_cache)
                    threats = await run_sync(self.gsb_executor, self.gsb.lookup_url, url)
                    if threats:
                        ret += UrlBlacklisted(4, "GSB", threats)
        return ret

    @SpamBlocker.reg(0)
    async def check_fwd(self, message):
        fwd_header = message.fwd_from
        if not fwd_header:
            return None
        stat = self.storage.get_gban_stat(fwd_header.from_id)
        if stat is not None:
            return ForwardUserBlacklisted(4, fwd_header.from_id, fwd_header.from_name,
                                          fwd_header.channel_id, stat["raw_reason"])

    @SpamBlocker.reg(3)
    async def check_cas(self, message):
        uid = message.from_id
        if not uid:
            return
        request = self.http_session.get("https://combot.org/api/cas/check?user_id={}".format(str(uid)))
        async with request:
            resp = await request.json()
        if resp["ok"]:
            return CombotCasBan(result["offences"], *resp["result"]["messages"])

    @SpamBlocker.reg(6)
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
        if full_user.profile_photo is None:
            ret += NoProfilePic(1)
        else:
            hash = await self.get_pfp_hash(full_user)
            severity = self.storage.check_image_hash(hash)
            if severity > 0:
                return ProfilePicHashBlacklisted(severity, str(hash))
        return ret

    @SpamBlocker.reg(1)
    async def check_manuals(self, message):
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
            full_user = await self.tl_client(telethon.functions.users.GetFullUserRequest(message.from_id))
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
