/* Copyright 2013 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "fmap.h"
#include "futility.h"

#define PRESERVE "preserve"
#define NOT_PRESERVE "not-preserve"
#define IS_PRESERVE(flags)                                                     \
	((flags & FMAP_AREA_PRESERVE) ? PRESERVE : NOT_PRESERVE)

/*
 * FMT_NORMAL: This format contains info related to fmap and areas including
 * their name, offset and size in multiple lines per area
 * FMT_PARSER: This format is parsable by scripts, it contains info about areas
 * including their name, offset and size
 * FMT_FLASHROM: This format is understandable by 'flashrom', it contains info
 * about areas including their name, first and last offsets
 * FMT_HUMAN: This format is human reader friendly, it includes hierarchy based
 * indentation. It contains info about areas including their name, first and
 * last offsets and size
 * FMT_FLASH_EC: This format is understandable by 'flash_ec' script, it contains
 * info about areas including their name and preserve flag status
 */
typedef enum {
	FMT_NORMAL,
	FMT_PARSER,
	FMT_FLASHROM,
	FMT_HUMAN,
	FMT_FLASH_EC
} format_t;

/* Return 0 if successful */
static int normal_fmap(const FmapHeader *fmh,
	const void *base_of_rom, size_t size_of_rom,
	bool extract, format_t format,
	const char *const *names, size_t names_len)
{
	int retval = 0;
	char buf[80];		/* DWR: magic number */
	const FmapAreaHeader *ah = (const FmapAreaHeader *) (fmh + 1);
        /* Size must greater than 0, else behavior is undefined. */
	struct {
		char *outname;
		bool found;
	} sections[names_len >= 1 ? names_len : 1];

	memset(sections, 0, sizeof(sections));

	if (extract) {
		/* prepare the filenames to write areas to */
		for (int i = 0; i < names_len; i++) {
			const char *a = names[i];
			char *f = strchr(a, ':');
			if (!f)
				continue;
			if (a == f || *(f+1) == '\0') {
				ERROR("argument \"%s\" is bogus\n", a);
				retval = 1;
				continue;
			}
			*f++ = '\0';
			sections[i].outname = f;
		}
		if (retval)
			return retval;
	}

	if (FMT_NORMAL == format) {
		snprintf(buf, FMAP_SIGNATURE_SIZE + 1, "%s",
			 fmh->fmap_signature);
		printf("fmap_signature   %s\n", buf);
		printf("fmap_version:    %d.%d\n",
		       fmh->fmap_ver_major, fmh->fmap_ver_minor);
		printf("fmap_base:       0x%" PRIx64 "\n", fmh->fmap_base);
		printf("fmap_size:       0x%08x (%d)\n", fmh->fmap_size,
		       fmh->fmap_size);
		snprintf(buf, FMAP_NAMELEN + 1, "%s", fmh->fmap_name);
		printf("fmap_name:       %s\n", buf);
		printf("fmap_nareas:     %d\n", fmh->fmap_nareas);
	}

	for (uint16_t i = 0; i < fmh->fmap_nareas; i++, ah++) {
		snprintf(buf, FMAP_NAMELEN + 1, "%s", ah->area_name);
		char *outname = NULL;

		if (names_len) {
			bool found = false;
			for (int j = 0; j < names_len; j++)
				if (!strcmp(names[j], buf)) {
					found = true;
					sections[j].found = true;
					outname = sections[j].outname;
					break;
				}
			if (!found)
				continue;
		}

		switch (format) {
		case FMT_PARSER:
			printf("%s %d %d\n", buf, ah->area_offset,
			       ah->area_size);
			break;
		case FMT_FLASHROM:
			if (ah->area_size)
				printf("0x%08x:0x%08x %s\n", ah->area_offset,
				       ah->area_offset + ah->area_size - 1,
				       buf);
			break;
		case FMT_FLASH_EC:
			if (ah->area_size)
				printf("%s %d %d %s\n", buf, ah->area_offset, ah->area_size,
				       IS_PRESERVE(ah->area_flags));
			break;
		default:
			printf("area:            %d\n", i + 1);
			printf("area_offset:     0x%08x\n", ah->area_offset);
			printf("area_size:       0x%08x (%d)\n", ah->area_size,
			       ah->area_size);
			printf("area_name:       %s\n", buf);
		}

		if (extract) {
			if (!outname) {
				for (char *s = buf; *s; s++)
					if (*s == ' ')
						*s = '_';
				outname = buf;
			}
			FILE *fp = fopen(outname, "wb");
			if (!fp) {
				ERROR("can't open %s: %s\n",
				      outname, strerror(errno));
				retval = 1;
			} else if (!ah->area_size) {
				ERROR("section %s has zero size\n", buf);
				retval = 1;
			} else if (ah->area_offset + ah->area_size >
				   size_of_rom) {
				ERROR("section %s is larger than the image\n", buf);
				retval = 1;
			} else if (1 != fwrite(base_of_rom + ah->area_offset,
					       ah->area_size, 1, fp)) {
				ERROR("can't write %s: %s\n",
				      buf, strerror(errno));
				retval = 1;
			} else {
				if (FMT_NORMAL == format)
					printf("saved as \"%s\"\n", outname);
			}
			if (fp)
				fclose(fp);
		}
	}

	for (int j = 0; j < names_len; j++)
		if (!sections[j].found) {
			ERROR("FMAP section %s not found\n", names[j]);
			retval = 1;
		}

	return retval;
}

/****************************************************************************/
/* Stuff for human-readable form */

struct dup_s {
	char *name;
	struct dup_s *next;
};

struct node_s {
	char *name;
	uint32_t start;
	uint32_t size;
	uint32_t end;
	struct node_s *parent;
	int num_children;
	struct node_s **child;
	struct dup_s *alias;
};

static struct node_s *all_nodes;

static void sort_nodes(int num, struct node_s *ary[])
{
	/* bubble-sort is quick enough with only a few entries */
	for (unsigned int i = 0; i < num; i++) {
		for (unsigned int j = i + 1; j < num; j++) {
			if (ary[j]->start > ary[i]->start) {
				struct node_s *tmp = ary[i];
				ary[i] = ary[j];
				ary[j] = tmp;
			}
		}
	}
}

static void line(int indent, const char *name, uint32_t start, uint32_t end,
		 uint32_t size, const char *append)
{
	for (int i = 0; i < indent; i++)
		printf("  ");
	printf("%-25s  %08x    %08x    %08x%s\n", name, start, end, size,
	       append ? append : "");
}

static void empty(int indent, uint32_t start, uint32_t end, char *name, bool gaps, int *gapcount)
{
	char buf[80];
	if (gaps) {
		sprintf(buf, "  // gap in %s", name);
		line(indent + 1, "", start, end, end - start, buf);
	}
	(*gapcount)++;
}

static void show(struct node_s *p, int indent, int show_first, bool show_gaps, int *gapcount)
{
	struct dup_s *alias;
	if (show_first) {
		line(indent, p->name, p->start, p->end, p->size, 0);
		for (alias = p->alias; alias; alias = alias->next)
			line(indent, alias->name, p->start, p->end, p->size,
			     "  // DUPLICATE");
	}
	sort_nodes(p->num_children, p->child);
	for (unsigned int i = 0; i < p->num_children; i++) {
		if (i == 0 && p->end != p->child[i]->end)
			empty(indent, p->child[i]->end, p->end, p->name, show_gaps, gapcount);
		show(p->child[i], indent + show_first, 1, show_gaps, gapcount);
		if (i < p->num_children - 1
		    && p->child[i]->start != p->child[i + 1]->end)
			empty(indent, p->child[i + 1]->end, p->child[i]->start,
			      p->name, show_gaps, gapcount);
		if (i == p->num_children - 1 && p->child[i]->start != p->start)
			empty(indent, p->start, p->child[i]->start, p->name, show_gaps, gapcount);
	}
}

static int overlaps(int i, int j)
{
	struct node_s *a = all_nodes + i;
	struct node_s *b = all_nodes + j;

	return ((a->start < b->start) && (b->start < a->end) &&
		(b->start < a->end) && (a->end < b->end));
}

static int encloses(int i, int j)
{
	struct node_s *a = all_nodes + i;
	struct node_s *b = all_nodes + j;

	return ((a->start <= b->start) && (a->end >= b->end));
}

static int duplicates(int i, int j)
{
	struct node_s *a = all_nodes + i;
	struct node_s *b = all_nodes + j;

	return ((a->start == b->start) && (a->end == b->end));
}

static void add_dupe(int i, int j, int numnodes)
{
	struct dup_s *alias = (struct dup_s *) malloc(sizeof(struct dup_s));
	alias->name = all_nodes[j].name;
	alias->next = all_nodes[i].alias;
	all_nodes[i].alias = alias;
	for (int k = j; k < numnodes; k++)
		all_nodes[k] = all_nodes[k + 1];
}

static void add_child(struct node_s *p, int n)
{
	if (p->num_children && !p->child) {
		p->child =
		    (struct node_s **)calloc(p->num_children,
					     sizeof(struct node_s *));
		if (!p->child) {
			perror("calloc failed");
			exit(1);
		}
	}
	for (unsigned int i = 0; i < p->num_children; i++) {
		if (!p->child[i]) {
			p->child[i] = all_nodes + n;
			return;
		}
	}
}

static int human_fmap(const FmapHeader *fmh, bool gaps, int overlap)
{
	int errorcnt = 0;

	/* The challenge here is to generate a directed graph from the
	 * arbitrarily-ordered FMAP entries, and then to prune it until it's as
	 * simple (and deep) as possible. Overlapping regions are not allowed.
	 * Duplicate regions are okay, but may require special handling. */

	/* Convert the FMAP info into our format. */
	uint16_t numnodes = fmh->fmap_nareas;

	/* plus one for the all-enclosing "root" */
	all_nodes = (struct node_s *) calloc(numnodes + 1,
					     sizeof(struct node_s));
	if (!all_nodes) {
		perror("calloc failed");
		return 1;
	}
	for (uint16_t i = 0; i < numnodes; i++) {
		char buf[FMAP_NAMELEN + 1];
		const FmapAreaHeader *ah = (FmapAreaHeader *) (fmh + 1);

		strncpy(buf, ah[i].area_name, FMAP_NAMELEN);
		buf[FMAP_NAMELEN] = '\0';
		all_nodes[i].name = strdup(buf);
		if (!all_nodes[i].name) {
			perror("strdup failed");
			return 1;
		}
		all_nodes[i].start = ah[i].area_offset;
		all_nodes[i].size = ah[i].area_size;
		all_nodes[i].end = ah[i].area_offset + ah[i].area_size;
	}
	/* Now add the root node */
	all_nodes[numnodes].name = strdup("-entire flash-");
	all_nodes[numnodes].start = fmh->fmap_base;
	all_nodes[numnodes].size = fmh->fmap_size;
	all_nodes[numnodes].end = fmh->fmap_base + fmh->fmap_size;

	/* First, coalesce any duplicates */
	for (uint16_t i = 0; i < numnodes; i++) {
		for (uint16_t j = i + 1; j < numnodes; j++) {
			if (duplicates(i, j)) {
				add_dupe(i, j, numnodes);
				numnodes--;
			}
		}
	}

	/* Each node should have at most one parent, which is the smallest
	 * enclosing node. Duplicate nodes "enclose" each other, but if there's
	 * already a relationship in one direction, we won't create another.
	 */
	for (uint16_t i = 0; i < numnodes; i++) {
		/* Find the smallest parent, which might be the root node. */
		int k = numnodes;
		for (uint16_t j = 0; j < numnodes; j++) { /* full O(N^2) comparison */
			if (i == j)
				continue;
			if (overlaps(i, j)) {
				printf("ERROR: %s and %s overlap\n",
				       all_nodes[i].name, all_nodes[j].name);
				printf("  %s: %#x - %#x\n", all_nodes[i].name,
				       all_nodes[i].start, all_nodes[i].end);
				printf("  %s: %#x - %#x\n", all_nodes[j].name,
				       all_nodes[j].start, all_nodes[j].end);
				if (overlap < 2) {
					printf("Use more -h args to ignore"
					       " this error\n");
					errorcnt++;
				}
				continue;
			}
			if (encloses(j, i)
			    && all_nodes[j].size < all_nodes[k].size)
				k = j;
		}
		all_nodes[i].parent = all_nodes + k;
	}
	if (errorcnt)
		return 1;

	/* Force those deadbeat parents to recognize their children */
	for (uint16_t i = 0; i < numnodes; i++)	/* how many */
		if (all_nodes[i].parent)
			all_nodes[i].parent->num_children++;
	for (uint16_t i = 0; i < numnodes; i++)	/* here they are */
		if (all_nodes[i].parent)
			add_child(all_nodes[i].parent, i);

	/* Ready to go */
	printf("# name                     start       end         size\n");
	int gapcount = 0;
	show(all_nodes + numnodes, 0, gaps, gaps, &gapcount);

	if (gapcount && !gaps)
		printf("\nWARNING: unused regions found. Use -H to see them\n");

	return 0;
}

/* End of human-reable stuff */
/****************************************************************************/

static const char usage[] =
	"\nUsage:  " MYNAME " %s [OPTIONS] FLASHIMAGE [NAME...]\n\n"
	"Display (and extract) the FMAP components from a BIOS image.\n"
	"\n"
	"Options:\n"
	"  -x             Extract the named sections from the file\n"
	"  -h             Use a human-readable format\n"
	"  -H             With -h, display any gaps\n"
	"  -p             Use a format easy to parse by scripts\n"
	"  -F             Use the format expected by flashrom\n"
	"  -e             Use the format expected by flash_ec\n"
	"\n"
	"Specify one or more NAMEs to dump only those sections.\n"
	"\n";

static void print_help(int argc, char *argv[])
{
	printf(usage, argv[0]);
}

enum {
	OPT_HELP = 1000,
};
static const struct option long_opts[] = {
	{"help",     0, 0, OPT_HELP},
	{NULL, 0, 0, 0}
};
static int do_dump_fmap(int argc, char *argv[])
{
	int c;
	int errorcnt = 0;
	int retval = 1;
	bool opt_extract = false;
	int opt_overlap = 0;
	bool opt_gaps = false;
	format_t opt_format = FMT_NORMAL;

	opterr = 0;		/* quiet, you */
	while ((c = getopt_long(argc, argv, ":xpFhHe", long_opts, 0)) != -1) {
		switch (c) {
		case 'x':
			opt_extract = true;
			break;
		case 'p':
			opt_format = FMT_PARSER;
			break;
		case 'e':
			opt_format = FMT_FLASH_EC;
			break;
		case 'F':
			opt_format = FMT_FLASHROM;
			break;
		case 'H':
			opt_gaps = true;
			VBOOT_FALLTHROUGH;
		case 'h':
			opt_format = FMT_HUMAN;
			opt_overlap++;
			break;
		case OPT_HELP:
			print_help(argc, argv);
			return 0;
		case '?':
			ERROR("%s: unrecognized switch: -%c\n",
				argv[0], optopt);
			errorcnt++;
			break;
		case ':':
			ERROR("%s: missing argument to -%c\n",
				argv[0], optopt);
			errorcnt++;
			break;
		default:
			errorcnt++;
			break;
		}
	}

	if (errorcnt || optind >= argc) {
		print_help(argc, argv);
		return 1;
	}

	int fd = open(argv[optind], O_RDONLY);
	if (fd < 0) {
		ERROR("%s: can't open %s: %s\n",
			argv[0], argv[optind], strerror(errno));
		return 1;
	}

	struct stat sb;
	if (fstat(fd, &sb)) {
		ERROR("%s: can't stat %s: %s\n",
			argv[0], argv[optind], strerror(errno));
		close(fd);
		return 1;
	}

	void *base_of_rom = mmap(0, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (base_of_rom == MAP_FAILED) {
		ERROR("%s: can't mmap %s: %s\n",
			argv[0], argv[optind], strerror(errno));
		close(fd);
		return 1;
	}
	close(fd);		/* done with this now */

	const size_t size_of_rom = sb.st_size;

	const FmapHeader *fmap = fmap_find(base_of_rom, size_of_rom);
	if (fmap) {
		switch (opt_format) {
		case FMT_HUMAN:
			retval = human_fmap(fmap, opt_gaps, opt_overlap);
			break;
		case FMT_NORMAL:
			printf("hit at 0x%08x\n",
			       (uint32_t) ((char *)fmap - (char *)base_of_rom));
			VBOOT_FALLTHROUGH;
		default:
			retval = normal_fmap(fmap, base_of_rom, size_of_rom,
					     opt_extract, opt_format,
					     (const char **)(argv + optind + 1),
					     argc - optind - 1);
		}
	} else {
		ERROR("FMAP header not found in %s\n", argv[optind]);
	}

	if (munmap(base_of_rom, sb.st_size)) {
		ERROR("%s: can't munmap %s: %s\n",
			argv[0], argv[optind], strerror(errno));
		return 1;
	}

	return retval;
}

DECLARE_FUTIL_COMMAND(dump_fmap, do_dump_fmap, VBOOT_VERSION_ALL,
		      "Display FMAP contents from a firmware image");
