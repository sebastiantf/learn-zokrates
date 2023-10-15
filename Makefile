# make program=root inputs="5 25"
# make program=root inputs="12 144"

all: compile setup compute-witness generate-proof export-verifier verify clean

compile:
	zokrates compile -i $(program)/$(program).zok

setup:
	zokrates setup

compute-witness:
	zokrates compute-witness -a $(inputs)

generate-proof:
	zokrates generate-proof

export-verifier:
	zokrates export-verifier

verify:
	zokrates verify

# Clean intermediate files
clean:
	rm -f *.json
	rm -f out*
	rm -f *.key
	rm -f verifier.sol
	rm -f witness

# Add a phony target for easy cleanup
.PHONY: clean
