all: ps

ps:
	latex exemplu_teza
	latex exemplu_teza
	bibtex exemplu_teza
	latex exemplu_teza
	dvips -o exemplu_teza.ps exemplu_teza.dvi

pdf: ps
	ps2pdf exemplu_teza.ps

clean: 
	rm -f *.out *~ *.thm *.log *.bbl *.blg *.aux *.toc *.lot *.lof *.dvi exemplu_teza.ps 


