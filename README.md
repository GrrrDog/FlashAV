# FlashAV
Remote detection of a user's AV via Flash

[Full information about this method is here](http://agrrrdog.blogspot.ru/2016/06/remote-detection-of-users-av-via-flash.html)

This is a PoC and code is pretty dirty.

sweet.py opens 843 port and gives flashpolicy.xml. Also it opens 8080 (by default) and receives encoded ssl certificates.
flashav.swf - sends a SSLv3 Client Hello request and resend response to sweet.py (8080)
swf_src - sources of swf. This is a project for FlashDevelop 5.
