py=.venv/bin/python
user=guenthner
program-name=hash-directory

set_user:
	cp ~/.pypirc_$(user) ~/.pypirc

build: clean version
	$(py) -m build

version:
	vinc

clean:
	touch dist/fuck
	rm dist/*

upload: set_user build
	$(py) -m twine upload --repository pypi dist/* $(flags)

reload: upload
	pipx upgrade $(program-name)
	pipx upgrade $(program-name)
	$(program-name) --version .
