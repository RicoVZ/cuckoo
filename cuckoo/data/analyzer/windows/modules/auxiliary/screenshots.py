# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import StringIO
import threading
import time

from lib.api.screenshot import Screenshot
from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile

log = logging.getLogger(__name__)

SHOT_DELAY = 1
MAX_RMS = 25

# Skip the following area when comparing screen shots.
# Example for 800x600 screen resolution.
# SKIP_AREA = ((735, 575), (790, 595))
SKIP_AREA = None

class Screenshots(threading.Thread, Auxiliary):
    """Take screenshots."""

    def __init__(self, options={}, analyzer=None):
        threading.Thread.__init__(self)
        Auxiliary.__init__(self, options, analyzer)
        self.do_run = True
        self.delay = SHOT_DELAY
        self.max_rms = MAX_RMS

    def init(self):
        delay = self.options.get("screenshot.delay", 0)
        if delay:
            try:
                delay = int(delay)
                self.delay = delay
            except ValueError:
                log.error("Invalid screenshot delay specified: %s", delay)

        max_rms = self.options.get("screenshot.max_rms", 0)
        if max_rms:
            try:
                max_rms = int(max_rms)
                self.max_rms = max_rms
            except ValueError:
                log.error("Invalid screenshot max rms specified: %s", max_rms)

    def stop(self):
        """Stop screenshotting."""
        self.do_run = False

    def run(self):
        """Run screenshotting.
        @return: operation status.
        """
        scr = Screenshot()

        # TODO We should also send the action "pillow" so that the Web
        # Interface can adequately inform the user about this missing library.
        if not scr.have_pil():
            log.info(
                "Python Image Library (either PIL or Pillow) is not "
                "installed, screenshots are disabled."
            )
            return False

        img_counter = 0
        img_last = None

        while self.do_run:
            time.sleep(SHOT_DELAY)

            try:
                img_current = scr.take()
            except IOError as e:
                log.error("Cannot take screenshot: %s", e)
                continue

            if img_last and scr.equal(
                    img_last, img_current, SKIP_AREA, self.max_rms
            ):
                continue

            img_counter += 1

            # workaround as PIL can't write to the socket file object :(
            tmpio = StringIO.StringIO()
            img_current.save(tmpio, format="JPEG")
            tmpio.seek(0)

            # now upload to host from the StringIO
            nf = NetlogFile()
            nf.init("shots/%04d.jpg" % img_counter)

            for chunk in tmpio:
                nf.sock.sendall(chunk)

            nf.close()

            img_last = img_current

        return True