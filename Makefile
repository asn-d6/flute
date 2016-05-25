.PHONY: install

install:
	cp weechat_flute.py $(HOME)/.weechat/python/
	cp -R flute $(HOME)/.weechat/python/

dev-install:
	ln -s $(CURDIR)/weechat_flute.py $(HOME)/.weechat/python/
	ln -s $(CURDIR)/flute $(HOME)/.weechat/python/

