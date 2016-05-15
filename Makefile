.PHONY: install

install:
	cp weechat_viola.py $(HOME)/.weechat/python/
	cp -R viola $(HOME)/.weechat/python/

dev-install:
	ln -s $(CURDIR)/weechat_viola.py $(HOME)/.weechat/python/
	ln -s $(CURDIR)/viola $(HOME)/.weechat/python/

