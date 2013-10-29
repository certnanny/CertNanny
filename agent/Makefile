
all: doc

DOC=README certnanny.1.gz
doc: $(DOC)

DONOTEDIT=[This file was automatically generated from certnanny. Do not edit!]

README: bin/certnanny
	echo '$(DONOTEDIT)' >README
	pod2text bin/certnanny >>README

certnanny.1.gz: bin/certnanny
	pod2man bin/certnanny | gzip -9  > certnanny.1.gz

clean:
	-rm -f $(DOC)
