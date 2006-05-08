
all: doc

DOC=README certnanny.1
doc: $(DOC)

DONOTEDIT=[This file was automatically generated from certnanny. Do not edit!]

README: bin/certnanny
	echo '$(DONOTEDIT)' >README
	pod2text bin/certnanny >>README

certnanny.1: bin/certnanny
	pod2man bin/certnanny certnanny.1

clean:
	-rm -f $(DOC)
