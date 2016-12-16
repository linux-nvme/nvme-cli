# Guard against environment variables
MAN1_TXT =
TECH_DOCS =
ARTICLES =
SP_ARTICLES =

MAN1_TXT += $(filter-out \
		$(addsuffix .txt, $(ARTICLES) $(SP_ARTICLES)), \
		$(wildcard nvme-*.txt))
MAN1_TXT += nvme.txt
MAN_TXT = $(MAN1_TXT)
MAN_XML = $(patsubst %.txt,%.xml,$(MAN_TXT))
MAN_HTML = $(patsubst %.txt,%.html,$(MAN_TXT))

DOC_HTML = $(MAN_HTML) $(OBSOLETE_HTML)

API_DOCS = 
SP_ARTICLES += $(API_DOCS)
SP_ARTICLES += $(TECH_DOCS)


DOC_MAN1 = $(patsubst %.txt,%.1,$(MAN1_TXT))

ASCIIDOC = asciidoc
ASCIIDOC_EXTRA =
ASCIIDOC_DOCBOOK = docbook
ASCIIDOC_COMMON = $(ASCIIDOC) $(ASCIIDOC_EXTRA)
TXT_TO_XML = $(ASCIIDOC_COMMON) -b $(ASCIIDOC_DOCBOOK)
MANPAGE_XSL = manpage-normal.xsl
XMLTO = xmlto
XMLTO_EXTRA =
INSTALL ?= install
RM ?= rm -f
MAN_REPO = ../../nvme-manpages

ASCIIDOC_HTML = xhtml11
ASCIIDOC_CONF = -f asciidoc.conf
ASCIIDOC_COMMON = $(ASCIIDOC) $(ASCIIDOC_EXTRA) $(ASCIIDOC_CONF)
TXT_TO_HTML = $(ASCIIDOC_COMMON) -b $(ASCIIDOC_HTML)

MAKEINFO = makeinfo
INSTALL_INFO = install-info
DOCBOOK2X_TEXI = docbook2x-texi
DBLATEX = dblatex
ASCIIDOC_DBLATEX_DIR = /etc/asciidoc/dblatex
ifndef PERL_PATH
	PERL_PATH = /usr/bin/perl
endif

ifdef DOCBOOK_XSL_172
MANPAGE_XSL = manpage-1.72.xsl
else
	ifndef ASCIIDOC_ROFF
	endif
endif
ifdef MAN_BOLD_LITERAL
XMLTO_EXTRA += -m manpage-bold-literal.xsl
endif
ifdef DOCBOOK_SUPPRESS_SP
XMLTO_EXTRA += -m manpage-suppress-sp.xsl
endif

ifndef MAN_BASE_URL
MAN_BASE_URL = file://$(htmldir)/
endif
XMLTO_EXTRA +=

ifdef GNU_ROFF
XMLTO_EXTRA +=
endif

SHELL_PATH ?= $(SHELL)
# Shell quote;
SHELL_PATH_SQ = $(subst ','\'',$(SHELL_PATH))

ifdef DEFAULT_PAGER
DEFAULT_PAGER_SQ = $(subst ','\'',$(DEFAULT_PAGER))
endif

ifdef DEFAULT_EDITOR
DEFAULT_EDITOR_SQ = $(subst ','\'',$(DEFAULT_EDITOR))
endif

QUIET_SUBDIR0  = +$(MAKE) -C # space to separate -C and subdir
QUIET_SUBDIR1  =

ifneq ($(findstring $(MAKEFLAGS),w),w)
PRINT_DIR = --no-print-directory
else # "make -w"
NO_SUBDIR = :
endif

DESTDIR =
PREFIX ?= /usr/local

all: man html

html: $(DOC_HTML)

man: man1
man1: $(DOC_MAN1)

install-no-build:
	$(INSTALL) -d -m 755 $(DESTDIR)$(PREFIX)/share/man/man1
	$(INSTALL) -m 644 $(DOC_MAN1) $(DESTDIR)$(PREFIX)/share/man/man1

install: install-man

install-man: man
	$(INSTALL) -d -m 755 $(DESTDIR)$(PREFIX)/share/man/man1
	$(INSTALL) -m 644 $(DOC_MAN1) $(DESTDIR)$(PREFIX)/share/man/man1

docdep_prereqs = \
	cmd-list.made $(cmds_txt)

doc.dep : $(docdep_prereqs) $(wildcard *.txt) build-docdep.perl
	$(QUIET_GEN)$(RM) $@+ $@ && \
	$(PERL_PATH) ./build-docdep.perl >$@+ $(QUIET_STDERR) && \
	mv $@+ $@

-include doc.dep

cmds_txt = cmds-ancillaryinterrogators.txt \
	cmds-ancillarymanipulators.txt \
	cmds-mainporcelain.txt \
	cmds-plumbinginterrogators.txt \
	cmds-plumbingmanipulators.txt \
	cmds-synchingrepositories.txt \
	cmds-synchelpers.txt \
	cmds-purehelpers.txt \
	cmds-foreignscminterface.txt

$(cmds_txt): cmd-list.made

cmd-list.made: cmd-list.perl ../command-list.txt $(MAN1_TXT)
	$(QUIET_GEN)$(RM) $@ && \
	$(PERL_PATH) ./cmd-list.perl ../command-list.txt $(QUIET_STDERR) && \
	date >$@

clean:
	$(RM) *.xml *.xml+ *.html+
	$(RM) *.texi *.texi+ *.texi++ nvme.info nvmeman.info
	$(RM) *.pdf
	$(RM) howto-index.txt howto/*.html doc.dep
	$(RM) technical/*.html technical/api-index.txt
	$(RM) $(cmds_txt) *.made
	$(RM) manpage-base-url.xsl
	$(RM) *~

clobber: clean
	$(RM) *.html *.1

%.1 : %.xml
	$(QUIET_XMLTO)$(RM) $@ && \
	$(XMLTO) -m $(MANPAGE_XSL) $(XMLTO_EXTRA) man $<

%.xml : %.txt 
	$(QUIET_ASCIIDOC)$(RM) $@+ $@ && \
	$(TXT_TO_XML) -d manpage -o $@+ $< && \
	mv $@+ $@

user-manual.xml: user-manual.txt user-manual.conf
	$(QUIET_ASCIIDOC)$(RM) $@+ $@ && \
	$(TXT_TO_XML) -d article -o $@+ $< && \
	mv $@+ $@

technical/api-index.txt: technical/api-index-skel.txt \
	technical/api-index.sh $(patsubst %,%.txt,$(API_DOCS))
	$(QUIET_GEN)cd technical && '$(SHELL_PATH_SQ)' ./api-index.sh

XSLT = docbook.xsl
XSLTOPTS = --xinclude --stringparam html.stylesheet docbook-xsl.css

nvme.info: user-manual.texi
	$(QUIET_MAKEINFO)$(MAKEINFO) --no-split -o $@ user-manual.texi

user-manual.texi: user-manual.xml
	$(QUIET_DB2TEXI)$(RM) $@+ $@ && \
	$(DOCBOOK2X_TEXI) user-manual.xml --encoding=UTF-8 --to-stdout >$@++ && \
	$(PERL_PATH) fix-texi.perl <$@++ >$@+ && \
	rm $@++ && \
	mv $@+ $@

user-manual.pdf: user-manual.xml
	$(QUIET_DBLATEX)$(RM) $@+ $@ && \
	$(DBLATEX) -o $@+ -p $(ASCIIDOC_DBLATEX_DIR)/asciidoc-dblatex.xsl -s $(ASCIIDOC_DBLATEX_DIR)/asciidoc-dblatex.sty $< && \
	mv $@+ $@

nvmeman.texi: $(MAN_XML) cat-texi.perl
	$(QUIET_DB2TEXI)$(RM) $@+ $@ && \
	($(foreach xml,$(MAN_XML),$(DOCBOOK2X_TEXI) --encoding=UTF-8 \
		--to-stdout $(xml) &&) true) > $@++ && \
	$(PERL_PATH) cat-texi.perl $@ <$@++ >$@+ && \
	rm $@++ && \
	mv $@+ $@

nvmeman.info: nvmeman.texi
	$(QUIET_MAKEINFO)$(MAKEINFO) --no-split --no-validate $*.texi

$(patsubst %.txt,%.texi,$(MAN_TXT)): %.texi : %.xml
	$(QUIET_DB2TEXI)$(RM) $@+ $@ && \
	$(DOCBOOK2X_TEXI) --to-stdout $*.xml >$@+ && \
	mv $@+ $@

howto-index.txt: howto-index.sh $(wildcard howto/*.txt)
	$(QUIET_GEN)$(RM) $@+ $@ && \
	'$(SHELL_PATH_SQ)' ./howto-index.sh $(sort $(wildcard howto/*.txt)) >$@+ && \
	mv $@+ $@

WEBDOC_DEST = /pub/software/scm/nvme/docs

$(MAN_HTML): %.html : %.txt
	$(QUIET_ASCIIDOC)$(RM) $@+ $@ && \
	$(TXT_TO_HTML) -d manpage -o $@+ $< && \
	mv $@+ $@

quick-install: quick-install-man

$(patsubst %,%.html,$(ARTICLES)) : %.html : %.txt
	$(QUIET_ASCIIDOC)$(TXT_TO_HTML) $*.txt

install-webdoc : html
	'$(SHELL_PATH_SQ)' ./install-webdoc.sh $(WEBDOC_DEST)

require-manrepo::
	@if test ! -d $(MAN_REPO); \
	then echo "nvme-manpages repository must exist at $(MAN_REPO)"; exit 1; fi

quick-install-man: require-manrepo
	'$(SHELL_PATH_SQ)' ./install-doc-quick.sh $(MAN_REPO) $(DESTDIR)$(mandir)

print-man1:
	@for i in $(MAN1_TXT); do echo $$i; done

.PHONY: FORCE
