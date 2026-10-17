# The public article, built twice and checked for layout and reference defects.
.PHONY: all english clean

all: english

english:
	python3 ../scripts/build_paper.py --source faces12-en.tex

clean:
	rm -f *.aux *.log *.out *.toc *.fls *.fdb_latexmk *.synctex.gz
