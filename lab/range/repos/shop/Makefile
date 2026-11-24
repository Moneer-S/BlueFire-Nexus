# The shop's build: packs its sources into shop.tar. The build server's
# ordinary activity runs it after each pull.
SOURCES = items.csv

shop.tar: $(SOURCES)
	tar -cf $@ $(SOURCES)

clean:
	rm -f shop.tar

.PHONY: clean
