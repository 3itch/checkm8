/* Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Accessing updater resources from an archive.
 */

#include <assert.h>
#include <errno.h>
#if defined(__OpenBSD__)
#include <sys/types.h>
#endif
#include <fts.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef HAVE_LIBARCHIVE
#include <archive.h>
#include <archive_entry.h>
#endif

#ifdef HAVE_LIBZIP
#ifndef __clang__
/* If libzip headers were built for Clang but later get included with GCC you
   need this. This check should really be in libzip but apparently they think
   it's fine to ship compiler-specific system headers or something... */
#define _Nullable
#define _Nonnull
#endif
#include <zip.h>
#endif

#include "host_misc.h"
#include "updater.h"

/*
 * A firmware update package (archive) is a file packed by either shar(1) or
 * zip(1). See https://chromium.googlesource.com/chromiumos/platform/firmware/
 * for more information.
 */

struct u_archive {
	void *handle;

	void * (*open)(const char *name);
	int (*close)(void *handle);

	int (*walk)(void *handle, void *arg,
		    int (*callback)(const char *path, void *arg));
	int (*has_entry)(void *handle, const char *name);
	int (*read_file)(void *handle, const char *fname,
			 uint8_t **data, uint32_t *size, int64_t *mtime);
	int (*write_file)(void *handle, const char *fname,
			  uint8_t *data, uint32_t size, int64_t mtime);
};

/*
 * -- The fallback driver (using general file system). --
 */

/* Callback for archive_open on a general file system. */
static void *archive_fallback_open(const char *name)
{
	assert(name && *name);
	return strdup(name);
}

/* Callback for archive_close on a general file system. */
static int archive_fallback_close(void *handle)
{
	free(handle);
	return 0;
}

/* Callback for archive_walk on a general file system. */
static int archive_fallback_walk(
		void *handle, void *arg,
		int (*callback)(const char *path, void *arg))
{
	FTS *fts_handle;
	FTSENT *ent;
	char *fts_argv[2] = {};
	char default_path[] = ".";
	char *root = default_path;
	size_t root_len;

	if (handle)
		root = (char *)handle;
	root_len = strlen(root);
	fts_argv[0] = root;

	fts_handle = fts_open(fts_argv, FTS_NOCHDIR, NULL);
	if (!fts_handle)
		return -1;

	while ((ent = fts_read(fts_handle)) != NULL) {
		char *path = ent->fts_path + root_len;
		if (ent->fts_info != FTS_F && ent->fts_info != FTS_SL)
			continue;
		while (*path == '/')
			path++;
		if (!*path)
			continue;
		if (callback(path, arg))
			break;
	}
	return 0;
}

/* Callback for fallback drivers to get full path easily. */
static const char *archive_fallback_get_path(void *handle, const char *fname,
					     char **temp_path)
{
	if (handle && *fname != '/') {
		ASPRINTF(temp_path, "%s/%s", (char *)handle, fname);
		return *temp_path;
	}
	return fname;
}

/* Callback for archive_has_entry on a general file system. */
static int archive_fallback_has_entry(void *handle, const char *fname)
{
	int r;
	char *temp_path = NULL;
	const char *path = archive_fallback_get_path(handle, fname, &temp_path);

	VB2_DEBUG("Checking %s\n", path);
	r = access(path, R_OK);
	free(temp_path);
	return r == 0;
}

/* Callback for archive_read_file on a general file system. */
static int archive_fallback_read_file(void *handle, const char *fname,
				      uint8_t **data, uint32_t *size, int64_t *mtime)
{
	int r;
	char *temp_path = NULL;
	const char *path = archive_fallback_get_path(handle, fname, &temp_path);
	struct stat st;

	VB2_DEBUG("Reading %s\n", path);
	*data = NULL;
	*size = 0;
	/* vb2_read_file already has an extra '\0' in the end. */
	r = vb2_read_file(path, data, size) != VB2_SUCCESS;
	if (mtime) {
		if (stat(path, &st) == 0)
			*mtime = st.st_mtime;
		else
			WARN("Unable to stat %s: %s\n", path, strerror(errno));
	}
	free(temp_path);
	return r;
}

/* Callback for archive_write_file on a general file system. */
static int archive_fallback_write_file(void *handle, const char *fname,
				       uint8_t *data, uint32_t size, int64_t mtime)
{
	int r;
	char *temp_path = NULL;
	const char *path = archive_fallback_get_path(handle, fname, &temp_path);

	VB2_DEBUG("Writing %s\n", path);
	if (strchr(path, '/')) {
		char *dirname = strdup(path);
		*strrchr(dirname, '/') = '\0';
		/* TODO(hungte): call mkdir(2) instead of shell invocation. */
		if (access(dirname, W_OK) != 0) {
			char *command;
			ASPRINTF(&command, "mkdir -p %s", dirname);
			free(host_shell(command));
			free(command);
		}
		free(dirname);
	}
	r = vb2_write_file(path, data, size) != VB2_SUCCESS;
	if (mtime) {
		struct timeval times[2] = {
			{.tv_sec = mtime, .tv_usec = 0},
			{.tv_sec = mtime, .tv_usec = 0},
		};
		if (utimes(path, times) != 0)
			WARN("Unable to set times on %s: %s\n", path, strerror(errno));
	}
	free(temp_path);
	return r;
}

/*
 * -- The cache driver (used by other drivers). --
 */

#ifdef HAVE_LIBARCHIVE

/*
 * For stream-based archives (e.g., tar+gz) we want to create a cache for
 * storing the names and contents for later processing.
 */
struct archive_cache {
	char *name;
	uint8_t *data;
	int64_t mtime;
	size_t size;
	int has_data;
	struct archive_cache *next;
};

/* Add a new cache node to an existing cache list and return the new head. */
static struct archive_cache *archive_cache_new(struct archive_cache *cache,
					       const char *name)
{
	struct archive_cache *c;

	c = (struct archive_cache *)calloc(sizeof(*c), 1);
	if (!c)
		return NULL;

	c->name = strdup(name);
	if (!c->name) {
		free(c);
		return NULL;
	}

	c->next = cache;
	return c;
}

/* Find and return an entry (by name) from the cache. */
static struct archive_cache *archive_cache_find(struct archive_cache *c,
						const char *name)
{
	for (; c; c = c->next) {
		assert(c->name);
		if (!strcmp(c->name, name))
			return c;
	}
	return NULL;
}

/* Callback for archive_walk to process all entries in the cache. */
static int archive_cache_walk(
		struct archive_cache *c, void *arg,
		int (*callback)(const char *name, void *arg))
{
	for (; c; c = c->next) {
		assert(c->name);
		if (callback(c->name, arg))
			break;
	}
	return 0;
}

/* Delete all entries in the cache. */
static void *archive_cache_free(struct archive_cache *c)
{
	struct archive_cache *next;

	while (c) {
		next = c->next;
		free(c->name);
		free(c->data);
		free(c);
		c = next;
	}
	return NULL;
}

/*
 * -- The libarchive driver (multiple formats but very slow). --
 */

enum {
	FILTER_IGNORE,
	FILTER_ABORT,
	FILTER_NAME_ONLY,
	FILTER_READ_ALL,
};

static struct archive_cache *libarchive_read_file_entries(
		const char *fpath, int (*filter)(struct archive_entry *entry))
{
	struct archive *a = archive_read_new();
	struct archive_entry *entry;
	struct archive_cache *c, *cache = NULL;
	int r;

	assert(a);
	archive_read_support_filter_all(a);
	archive_read_support_format_all(a);
	r = archive_read_open_filename(a, fpath, 10240);
	if (r != ARCHIVE_OK) {
		ERROR("Failed parsing archive using libarchive: %s\n", fpath);
		archive_read_free(a);
		return NULL;
	}

	WARN("Loading data from archive: %s ", fpath);
	while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
		fputc('.', stderr);
		if (archive_entry_filetype(entry) != AE_IFREG)
			continue;
		if (filter)
			r = filter(entry);
		else
			r = FILTER_READ_ALL;

		if (r == FILTER_ABORT)
			break;
		if (r == FILTER_IGNORE)
			continue;

		c = archive_cache_new(cache, archive_entry_pathname(entry));
		if (!c) {
			ERROR("Internal error: out of memory.\n");
			archive_cache_free(cache);
			archive_read_free(a);
			return NULL;
		}
		cache = c;

		if (r == FILTER_NAME_ONLY)
			continue;

		assert(r == FILTER_READ_ALL);
		c->size = archive_entry_size(entry);
		c->mtime = archive_entry_mtime(entry);
		c->data = (uint8_t *)calloc(1, c->size + 1);
		if (!c->data) {
			WARN("Out of memory when loading: %s\n", c->name);
			continue;
		}
		if (archive_read_data(a, c->data, c->size) != c->size) {
			WARN("Failed reading from archive: %s\n", c->name);
			continue;
		}
		c->has_data = 1;
	}
	fputs("\r\n", stderr);  /* Flush the '.' */
	VB2_DEBUG("Finished loading from archive: %s.\n", fpath);

	archive_read_free(a);
	return cache;
}

/* Callback for archive_open on an ARCHIVE file. */
static void *archive_libarchive_open(const char *name)
{
	/*
	 * The firmware archives today can usually all load into memory
	 * so we are using a NULL filter. Change that to a specific list in
	 * future if the /build/$BOARD/firmware archive becomes too large.
	 */
	return libarchive_read_file_entries(name, NULL);
}

/* Callback for archive_close on an ARCHIVE file. */
static int archive_libarchive_close(void *handle)
{
	archive_cache_free(handle);
	return 0;
}

/* Callback for archive_has_entry on an ARCHIVE file. */
static int archive_libarchive_has_entry(void *handle, const char *fname)
{
	return archive_cache_find(handle, fname) != NULL;
}

/* Callback for archive_walk on an ARCHIVE file. */
static int archive_libarchive_walk(
		void *handle, void *arg,
		int (*callback)(const char *name, void *arg))
{
	return archive_cache_walk(handle, arg, callback);
}

/* Callback for archive_read_file on an ARCHIVE file. */
static int archive_libarchive_read_file(
		void *handle, const char *fname, uint8_t **data,
		uint32_t *size, int64_t *mtime)
{
	struct archive_cache *c = archive_cache_find(handle, fname);

	if (!c)
		return 1;

	if (!c->has_data) {
		/* TODO(hungte) Re-read. */
		ERROR("Not in the cache: %s\n", fname);
		return 1;
	}

	if (mtime)
		*mtime = c->mtime;
	if (size)
		*size = c->size;
	*data = (uint8_t *)malloc(c->size + 1);
	if (!*data) {
		ERROR("Out of memory when reading: %s\n", c->name);
		return 1;
	}
	memcpy(*data, c->data, c->size);
	(*data)[c->size] = '\0';
	return 0;
}

/* Callback for archive_write_file on an ARCHIVE file. */
static int archive_libarchive_write_file(
		void *handle, const char *fname, uint8_t *data, uint32_t size,
		int64_t mtime)
{
	ERROR("Not implemented!\n");
	return 1;
}
#endif

/*
 * -- The libzip driver (for ZIP, the official format for CrOS fw updater). --
 */

#ifdef HAVE_LIBZIP

/* Callback for archive_open on a ZIP file. */
static void *archive_zip_open(const char *name)
{
	return zip_open(name, 0, NULL);
}

/* Callback for archive_close on a ZIP file. */
static int archive_zip_close(void *handle)
{
	struct zip *zip = (struct zip *)handle;

	if (zip)
		return zip_close(zip);
	return 0;
}

/* Callback for archive_has_entry on a ZIP file. */
static int archive_zip_has_entry(void *handle, const char *fname)
{
	struct zip *zip = (struct zip *)handle;
	assert(zip);
	return zip_name_locate(zip, fname, 0) != -1;
}

/* Callback for archive_walk on a ZIP file. */
static int archive_zip_walk(
		void *handle, void *arg,
		int (*callback)(const char *name, void *arg))
{
	zip_int64_t num, i;
	struct zip *zip = (struct zip *)handle;
	assert(zip);

	num = zip_get_num_entries(zip, 0);
	if (num < 0)
		return 1;
	for (i = 0; i < num; i++) {
		const char *name = zip_get_name(zip, i, 0);
		if (*name && name[strlen(name) - 1] == '/')
			continue;
		if (callback(name, arg))
			break;
	}
	return 0;
}

/* Callback for archive_zip_read_file on a ZIP file. */
static int archive_zip_read_file(void *handle, const char *fname,
			     uint8_t **data, uint32_t *size, int64_t *mtime)
{
	struct zip *zip = (struct zip *)handle;
	struct zip_file *fp;
	struct zip_stat stat;

	assert(zip);
	*data = NULL;
	*size = 0;
	zip_stat_init(&stat);
	if (zip_stat(zip, fname, 0, &stat)) {
		ERROR("Fail to stat entry in ZIP: %s\n", fname);
		return 1;
	}
	fp = zip_fopen(zip, fname, 0);
	if (!fp) {
		ERROR("Failed to open entry in ZIP: %s\n", fname);
		return 1;
	}
	*data = (uint8_t *)malloc(stat.size + 1);
	if (*data) {
		if (zip_fread(fp, *data, stat.size) == stat.size) {
			if (mtime)
				*mtime = stat.mtime;
			*size = stat.size;
			(*data)[stat.size] = '\0';
		} else {
			ERROR("Failed to read entry in zip: %s\n", fname);
			free(*data);
			*data = NULL;
		}
	}
	zip_fclose(fp);
	return *data == NULL;
}

/* Callback for archive_zip_write_file on a ZIP file. */
static int archive_zip_write_file(void *handle, const char *fname,
				  uint8_t *data, uint32_t size, int64_t mtime)
{
	struct zip *zip = (struct zip *)handle;
	struct zip_source *src;

	VB2_DEBUG("Writing %s\n", fname);
	assert(zip);
	src = zip_source_buffer(zip, data, size, 0);
	if (!src) {
		ERROR("Internal error: cannot allocate buffer: %s\n", fname);
		return 1;
	}

	if (zip_file_add(zip, fname, src, ZIP_FL_OVERWRITE) < 0) {
		zip_source_free(src);
		ERROR("Internal error: failed to add: %s\n", fname);
		return 1;
	}
	/* zip_source_free is not needed if zip_file_add success. */
#if LIBZIP_VERSION_MAJOR >= 1
	zip_file_set_mtime(zip, zip_name_locate(zip, fname, 0), mtime, 0);
#endif
	return 0;
}
#endif

/*
 * -- The public functions for using u_archive. --
 */

struct u_archive *archive_open(const char *path)
{
	struct stat path_stat;
	struct u_archive *ar;

	if (stat(path, &path_stat) != 0) {
		ERROR("Cannot identify type of path: %s\n", path);
		return NULL;
	}

	ar = (struct u_archive *)calloc(sizeof(*ar), 1);
	if (!ar) {
		ERROR("Internal error: allocation failure.\n");
		return NULL;
	}

	if (S_ISDIR(path_stat.st_mode)) {
		VB2_DEBUG("Found directory, use fallback (fs) driver: %s\n",
			  path);
		/* Regular file system. */
		ar->open = archive_fallback_open;
		ar->close = archive_fallback_close;
		ar->walk = archive_fallback_walk;
		ar->has_entry = archive_fallback_has_entry;
		ar->read_file = archive_fallback_read_file;
		ar->write_file = archive_fallback_write_file;
	}

	/* Format detection must try ZIP (the official format) first. */
#ifdef HAVE_LIBZIP
	if (!ar->open) {
		ar->handle = archive_zip_open(path);

		if (ar->handle) {
			VB2_DEBUG("Found a ZIP file: %s\n", path);
			ar->open = archive_zip_open;
			ar->close = archive_zip_close;
			ar->walk = archive_zip_walk;
			ar->has_entry = archive_zip_has_entry;
			ar->read_file = archive_zip_read_file;
			ar->write_file = archive_zip_write_file;
		}
	}
#endif

	/* LIBARCHIVE must be the last driver. */
#ifdef HAVE_LIBARCHIVE
	if (!ar->open) {
		VB2_DEBUG("Found a file, use libarchive: %s\n", path);
		ar->open = archive_libarchive_open;
		ar->close = archive_libarchive_close;
		ar->walk = archive_libarchive_walk;
		ar->has_entry = archive_libarchive_has_entry;
		ar->read_file = archive_libarchive_read_file;
		ar->write_file = archive_libarchive_write_file;
	}
#endif

	if (!ar->open) {
		ERROR("Found a file, but no drivers were selected: %s\n", path);
		free(ar);
		return NULL;
	}

	/* Some drivers may have already opened the archive. */
	if (!ar->handle)
		ar->handle = ar->open(path);

	if (!ar->handle) {
		ERROR("Failed to open archive: %s\n", path);
		free(ar);
		return NULL;
	}
	return ar;
}

int archive_close(struct u_archive *ar)
{
	int r = ar->close(ar->handle);
	free(ar);
	return r;
}

int archive_has_entry(struct u_archive *ar, const char *name)
{
	if (!ar || *name == '/')
		return archive_fallback_has_entry(NULL, name);
	return ar->has_entry(ar->handle, name);
}

int archive_walk(struct u_archive *ar, void *arg,
		 int (*callback)(const char *path, void *arg))
{
	if (!ar)
		return archive_fallback_walk(NULL, arg, callback);
	return ar->walk(ar->handle, arg, callback);
}

int archive_read_file(struct u_archive *ar, const char *fname,
		      uint8_t **data, uint32_t *size, int64_t *mtime)
{
	if (!ar || *fname == '/')
		return archive_fallback_read_file(NULL, fname, data, size, mtime);
	return ar->read_file(ar->handle, fname, data, size, mtime);
}

int archive_write_file(struct u_archive *ar, const char *fname,
		       uint8_t *data, uint32_t size, int64_t mtime)
{
	if (!ar || *fname == '/')
		return archive_fallback_write_file(NULL, fname, data, size, mtime);
	return ar->write_file(ar->handle, fname, data, size, mtime);
}

struct _copy_arg {
	struct u_archive *from, *to;
};

/* Callback for archive_copy. */
static int archive_copy_callback(const char *path, void *_arg)
{
	const struct _copy_arg *arg = (const struct _copy_arg*)_arg;
	uint32_t size;
	uint8_t *data;
	int64_t mtime;
	int r;

	INFO("Copying: %s\n", path);
	if (archive_read_file(arg->from, path, &data, &size, &mtime)) {
		ERROR("Failed reading: %s\n", path);
		return 1;
	}
	r = archive_write_file(arg->to, path, data, size, mtime);
	VB2_DEBUG("result=%d\n", r);
	free(data);
	return r;
}

int archive_copy(struct u_archive *from, struct u_archive *to)
{
	struct _copy_arg arg = { .from = from, .to = to };
	return archive_walk(from, &arg, archive_copy_callback);
}
