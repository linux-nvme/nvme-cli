// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 *
 * Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 *
 * This program parses C header files and generates accessor
 * functions (setter/getter) for each member found within.
 *
 * Limitations:
 *   - Does not support typedef struct. For example,
 *     typedef struct {
 *         ...
 *     } my_struct_t;
 *
 *   - Does not support struct within struct. For example,
 *     struct my_struct {
 *         struct another_struct {
 *            ...
 *         } my_var;
 *         ...
 *     };
 *
 * Example usage:
 *   ./generate-accessors private.h
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <regex.h>
#include <stdbool.h>
#include <getopt.h>
#include <glob.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <libgen.h>
#include <stdio.h>
#include <ctype.h>

#define OUTPUT_FNAME_DEFAULT_C "accessors.c"
#define OUTPUT_FNAME_DEFAULT_H "accessors.h"

#define SPACES  " \t\n\r"
#define streq(a, b) (strcmp((a), (b)) == 0)

static const char *banner =
	"// SPDX-License-Identifier: LGPL-2.1-or-later\n"
	"/**\n"
	" * This file is part of libnvme.\n"
	" *\n"
	" *   ____                           _           _    ____          _\n"
	" *  / ___| ___ _ __   ___ _ __ __ _| |_ ___  __| |  / ___|___   __| | ___\n"
	" * | |  _ / _ \\ '_ \\ / _ \\ '__/ _` | __/ _ \\/ _` | | |   / _ \\ / _` |/ _ \\\n"
	" * | |_| |  __/ | | |  __/ | | (_| | ||  __/ (_| | | |__| (_) | (_| |  __/\n"
	" *  \\____|\\___|_| |_|\\___|_|  \\__,_|\\__\\___|\\__,_|  \\____\\___/ \\__,_|\\___|\n"
	" *\n"
	" * Auto-generated struct member accessors (setter/getter)\n"
	" */\n";

/**
 * @brief Remove leading whitespace characters from string
 *        in-place.
 *
 * Removes leading whitespace defined by SPACES by returning
 * a pointer within @s to the first character that is not a
 * whitespace.
 *
 * @param s: The writable string to trim. If NULL, return NULL.
 *
 * @return Pointer to the first character of s that is not a
 *         white space, or NULL if @s is NULL.
 */
static inline char *ltrim(const char *s)
{
	return s ? (char *)s + strspn(s, SPACES) : NULL;
}

/**
 * @brief Remove trailing whitespace characters from a string in-place.
 *
 * Removes trailing whitespace defined by SPACES by writing a
 * terminating NUL byte at the first trailing whitespace position.
 *
 * @param s: The writable string to trim. If NULL, return NULL.
 *
 * @return The same pointer @s, or NULL if @s is NULL.
 */
static char *rtrim(char *s)
{
	if (!s)
		return NULL;

	char *p0 = s;

	for (char *p = s; *p; p++) {
		if (!strchr(SPACES, *p))
			p0 = p + 1;
	}
	*p0 = '\0';

	return s;
}

/**
 * @brief Trim both leading and trailing whitespace from a string.
 *
 * Uses ltrim to skip leading whitespace (returns pointer into original
 * string) and rtrim to remove trailing whitespace in-place.
 *
 * @param s: The string to trim. If NULL, returns NULL.
 *
 * @return Pointer to the trimmed string (may be interior of original),
 *         or NULL if @s is NULL.
 */
static char *trim(char *s)
{
	return s ? rtrim(ltrim(s)) : NULL;
}

/**
 * @brief Strip inline C++-style comments ("// ...") from a line.
 *
 * If the substring "//" is found in @line, it is replaced by a NUL
 * terminator so the remainder is ignored.
 *
 * @param line: Line buffer to modify (in-place).
 *
 * @return Pointer to the (possibly truncated) line.
 */
static char *trim_inline_comments(char *line)
{
	char *p = strstr(line, "//");

	if (p)
		*p = '\0';
	return line;
}

/**
 * @brief Remove C-style block comments (like this comment) from
 *        a text buffer.
 *
 * Replaces all comment characters with space characters to
 * preserve offsets while removing comment content.
 *
 * @param text: The buffer to clean (modified in-place). If no
 *              match is found the text pointed to by @text is
 *              left alone.
 */
static void mask_c_comments(char *text)
{
	char *p = text;

	while ((p = strstr(p, "/*")) != NULL) {
		char *end = strstr(p + 2, "*/");

		if (!end)
			break;
		memset(p, ' ', end - p + 2);
		p = end + 2;
	}
}

/**
 * @brief Convert a string to uppercase in-place.
 *
 * Iterates each character of @s and transforms it to uppercase
 * using toupper().
 *
 * @param s: The string to convert (modified in-place). Must be
 *           writable.
 *
 * @return Pointer to the modified @s.
 */
static char *to_uppercase(char *s)
{
	if (!s)
		return s;
	for (int i = 0; s[i] != '\0'; i++)
		s[i] = toupper((unsigned char)s[i]);
	return s;
}

/**
 * @brief Sanitize a string to form a valid C identifier.
 *
 * This function modifies the given string in place so that all characters
 * conform to the rules of a valid C variable name (identifier):
 *  - The first character must be a letter (A–Z, a–z) or underscore ('_').
 *  - Subsequent characters may be letters, digits, or underscores.
 *
 * Any character that violates these rules is replaced with an underscore ('_').
 * The string is always modified in place; no new memory is allocated.
 *
 * @param s Pointer to the NUL-terminated string to sanitize.
 *           If @p s is NULL or points to an empty string, the function does nothing.
 *
 * @note This function does not check for C keywords or identifier length limits.
 *
 * @code
 * char name[] = "123bad-name!";
 * sanitize_identifier(name);
 * // Result: "_23bad_name_"
 * @endcode
 */
static const char *sanitize_identifier(char *s)
{
	if (s == NULL || *s == '\0')
		return s;

	// The first character must be a letter or underscore
	if (!isalpha((unsigned char)s[0]) && s[0] != '_')
		s[0] = '_';

	// Remaining characters: letters, digits, underscores allowed
	for (char *p = s + 1; *p; ++p) {
		if (!isalnum((unsigned char)*p) && *p != '_')
			*p = '_';
	}

	return s;
}

/**
 * @brief Duplicate a C string safely.
 *
 * Allocates memory for and returns a copy of @s including the
 * terminating NUL. Uses malloc and memcpy to copy the entire buffer.
 *
 * The POSIX strdup() has unpredictable behavior when provided
 * with a NULL pointer. This function adds a NULL check for
 * safety. Also, strdup() is a POSIX extension that may not be
 * available on all platforms. Therefore, this function uses
 * malloc() and memcpy() instead of invoking strdup().
 *
 * @param s: Source string to duplicate. If NULL, returns NULL.
 *
 * @return Newly allocated copy of @s, or NULL on allocation failure or
 *         if @s is NULL. Caller must free().
 */
static char *safe_strdup(const char *s)
{
	if (!s)
		return NULL;

	size_t len = strlen(s) + 1; /* length including NUL-terminator */
	char *new_string = (char *)malloc(len);

	if (!new_string)
		return NULL; /* Return NULL on allocation failure */

	memcpy(new_string, s, len); /* Copy the string including NUL-terminator */

	return new_string;
}

/**
 * @brief Duplicate up to @size characters of a C string safely.
 *
 * Copies at most @size characters from @s into a newly allocated,
 * NUL-terminated buffer. If @s is shorter than @size, copies only
 * up to the terminating NUL.
 *
 * The POSIX strndup() has unpredictable behavior when provided
 * with a NULL pointer. This function adds a NULL check for
 * safety. Also, strndup() is a POSIX extension that may not be
 * available on all platforms. Therefore, this function uses
 * malloc() and memcpy() instead of invoking strndup().
 *
 * @param s: Source string to duplicate. If NULL, returns NULL.
 * @param size: Maximum number of characters to consider from @s.
 *
 * @return Newly allocated NUL-terminated copy, or NULL on
 *         allocation failure or if @s is NULL. Caller must
 *         free().
 */
static char *safe_strndup(const char *s, size_t size)
{
	if (!s)
		return NULL;

	size_t len = strnlen(s, size);
	char *new_string = malloc(len + 1);

	if (!new_string)
		return NULL;

	memcpy(new_string, s, len);
	new_string[len] = '\0';

	return new_string;
}

/**
 * @brief Test whether a string contains only decimal digits.
 *
 * Returns false for NULL or empty string.
 *
 * @param s: Null-terminated string to test.
 *
 * @return true if every character in @s is a decimal digit (0-9),
 *         false otherwise.
 */
static bool str_is_all_numbers(const char *s)
{
	if (!s || *s == '\0')
		return false;

	for (; *s != '\0'; s++) {
		if (!isdigit((unsigned char)*s))
			return false;
	}

	return true;
}

/**
 * @brief Return pointer to filename component within a path.
 *
 * Finds the last '/' in @path and returns pointer to the next
 * character; if no '/' is found returns the original @path.
 *
 * @param path: Input path string (must be NUL-terminated).
 *
 * @return Pointer to filename portion (not newly allocated).
 */
static const char *get_filename(const char *path)
{
	const char *slash = strrchr(path, '/');

	return slash ? slash + 1 : path;
}

/**
 * @brief Create directories recursively (mkdir -p behavior).
 *
 * Walks the path components and creates each intermediate directory
 * with the specified @mode. If @path is ".", returns success.
 *
 * @param path: Path to create (e.g., "/tmp/a/b").
 * @param mode: Permissions bits for created directories (as for mkdir).
 *
 * @return true on success (directories created or already exist),
 *         false on error (errno is set).
 */
static bool mkdir_p(const char *path, mode_t mode)
{
	bool ok = false;
	char *tmp;
	char *p = NULL;
	size_t len;

	if (streq(path, "."))
		return true;

	if (!path || !*path) {
		errno = EINVAL;
		return false;
	}

	/* Copy path to temporary buffer */
	tmp = safe_strdup(path);
	len = strlen(tmp);
	if (tmp[len - 1] == '/')
		tmp[len - 1] = '\0';  /* remove trailing slash */

	for (p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			/* Attempt to create directory */
			if (mkdir(tmp, mode) != 0) {
				if (errno != EEXIST)
					goto mkdir_out;
			}
			*p = '/';
		}
	}

	/* Create final directory */
	if (mkdir(tmp, mode) != 0) {
		if (errno != EEXIST)
			goto mkdir_out;
	}

	ok = true;

mkdir_out:
	free(tmp);
	return ok;
}

/**
 * @brief Create directories to hold file specified by @fullpath
 *
 * Given a path and file name (@fullpath), create the
 * directories to hold the file. This is done by splitting the
 * file portion from @fullpath and creating the directory tree.
 *
 * @param fullpath:  Directories + file name.
 * @param mode:  Permissions bits for created directories (as for mkdir).
 *
 * @return true on success (directories created or already exist),
 *         false on error (errno is set).
 */
static bool mkdir_fullpath(const char *fullpath, mode_t mode)
{
	char  saved;
	bool  ok;
	char  *fname = (char *)get_filename(fullpath);

	/* Check whether it's just a file name w/o a path. */
	if (fname == fullpath)
		return true;

	saved = fname[0];
	fname[0] = '\0';  /* split file name from path */
	ok = mkdir_p(fullpath, mode);
	fname[0] = saved; /* restore full path */

	return ok;
}

/**
 * @brief Read entire file into a newly-allocated buffer.
 *
 * Opens the file at @path and reads all bytes into a buffer that is
 * NUL-terminated. Exits the program on failure to open the file.
 *
 * @param path: Path to the file to read.
 *
 * @return Pointer to a malloc()-allocated buffer containing the file
 *         contents (NUL-terminated). Caller must free(). On error the
 *         program exits with EXIT_FAILURE.
 */
static char *read_file(const char *path)
{
	long  len;
	char *buf;
	FILE *f = fopen(path, "rb");

	if (!f) {
		perror(path);
		exit(EXIT_FAILURE);
	}
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	rewind(f);
	buf = malloc(len + 1);
	len = fread(buf, 1, len, f);
	buf[len] = '\0';
	fclose(f);
	return buf;
}


/******************************************************************************/


/**
 * @brief Compute the length of a regex match represented by regmatch_t.
 *
 * Returns zero if the match is invalid (rm_so or rm_eo negative or
 * rm_eo < rm_so).
 *
 * @param m: Pointer to regmatch_t describing the match.
 *
 * @return Size in bytes of the match, or 0 if invalid.
 */
static size_t regmatch_size(const regmatch_t *m)
{
	bool invalid = m->rm_so < 0 || m->rm_eo < 0 || m->rm_eo < m->rm_so;

	return invalid ? 0 : m->rm_eo - m->rm_so;
}

/**
 * @brief Duplicate the substring matched by a regmatch_t.
 *
 * Allocates a new NUL-terminated buffer and copies the matched span
 * from @src.
 *
 * @param src: Source string used in the regexec().
 * @param m:   Pointer to regmatch_t describing the match.
 *
 * @return Newly allocated string containing the match, or NULL if the
 *         match has zero length. Caller must free().
 */
static char *regmatch_strdup(const char *src, const regmatch_t *m)
{
	size_t len = regmatch_size(m);

	return len ? safe_strndup(src + m->rm_so, len) : NULL;
}

/**
 * @brief Check whether a regex match contains a specific character.
 *
 * Iterates characters inside the matched span and returns true if
 * character @c appears within.
 *
 * @param src: Source string used for the match.
 * @param m:   Match information.
 * @param c:   Character to search for.
 *
 * @return true if @c present in match span, false otherwise.
 */
static bool regmatch_contains_char(const char *src, const regmatch_t *m, char c)
{
	size_t len = regmatch_size(m);

	if (!len)
		return false;

	const char *arr = src + m->rm_so;

	for (size_t i = 0; (arr[i] != '\0') && (i < len); i++) {
		if (arr[i] == c)
			return true;
	}
	return false;
}

/**
 * @brief Test whether the matched substring begins with a given prefix.
 *
 * Compares the first bytes of the match against @s.
 *
 * @param src: Source string used for matching.
 * @param m:   Match information.
 * @param s:   Prefix to compare.
 *
 * @return true if the matched substring starts with @s, false
 *         otherwise.
 */
static bool regmatch_startswith(const char       *src,
				const regmatch_t *m,
				const char       *s)
{
	size_t size;
	size_t len = regmatch_size(m);

	if (len == 0)
		return false;

	size = strlen(s);
	if (len < size)
		return false;

	const char *arr = src + m->rm_so;

	return !strncmp(arr, s, size);
}


/******************************************************************************/


typedef struct StringList {
	const char  **strings;  /* Pointer to an array of char pointers */
	size_t      count;      /* Current number of strings */
	size_t      capacity;   /* Allocated capacity for strings */
} StringList_t;


/**
 * @brief Initialize a StringList_t object.
 *
 * Allocates the internal array with at least @initial_capacity
 * entries (minimum STRINGLIST_INITIAL_CAPACITY). The list is
 * empty after initialization.
 *
 * @param list: Pointer to the list to initialize.
 * @param initial_capacity: Desired initial capacity (will be rounded
 *                          up to at least STRINGLIST_INITIAL_CAPACITY).
 */
#define STRINGLIST_INITIAL_CAPACITY 8
static void strlst_init(StringList_t *list, size_t initial_capacity)
{
	if (initial_capacity < STRINGLIST_INITIAL_CAPACITY)
		initial_capacity = STRINGLIST_INITIAL_CAPACITY;
	list->strings = (const char **)calloc(initial_capacity, sizeof(char *));
	list->count = 0;
	list->capacity = initial_capacity;
}

/**
 * @brief Append a string to a StringList_t.
 *
 * If list capacity is exhausted, it doubles the capacity and
 * reallocates. The input string is set either by stealing the
 * passed pointer or by duplicating it depending on @steal.
 *
 * @param list: Pointer to the string list.
 * @param string: Null-terminated string to add.
 * @param steal: If true, take ownership of @string pointer (no copy).
 */
static void strlst_add(StringList_t *list, const char *string, bool steal)
{
	if (!string)
		return; /* Do nothing is string is NULL */

	if (list->count == list->capacity) {
		/* Reallocate to double capacity */
		list->capacity *= 2;
		list->strings = (const char **)realloc(list->strings,
						       list->capacity * sizeof(char *));
		for (size_t i = list->count; i < list->capacity; i++)
			list->strings[i] = NULL;
	}

	/* Allocate memory for the new string and copy its content */
	list->strings[list->count++] = steal ? string : safe_strdup(string);
}

/**
 * @brief Remove all strings from the list and free them.
 *
 * Frees each stored string and resets count to zero but leaves the
 * allocated array in place so the list can be reused.
 *
 * @param list: Pointer to the string list to clear.
 */
static void strlst_clear(StringList_t *list)
{
	for (size_t i = 0; i < list->count; i++) {
		free((void *)list->strings[i]);
		list->strings[i] = NULL;
	}

	list->count = 0;
}

/**
 * @brief Free a StringList_t and its contents.
 *
 * Frees all stored strings and the internal array and resets the list
 * fields to indicate an empty/unallocated list.
 *
 * @param list: Pointer to the list to free.
 */
static void strlst_free(StringList_t *list)
{
	strlst_clear(list);
	free(list->strings);
	list->strings = NULL;
	list->capacity = 0;
}

/**
 * @brief Test if the string list is empty.
 *
 * @param list: Pointer to the string list.
 *
 * @return true if list contains no elements, false otherwise.
 */
#define STRLST_EMPTY(list) ((list)->count == 0)

/**
 * @brief Iterate over a StringList_t returning next element.
 *
 * @param sl:  Pointer to the string list.
 * @param s:   Pointer that gets updated with char* at current
 *             index or NULL if end reached.
 */
#define STRLST_FOREACH(sl, s) \
	for (size_t __str_next = 0; \
	({ \
		(s) = (__str_next >= (sl)->count) ? NULL : (sl)->strings[__str_next++]; \
		(s) != NULL; \
	});)

/**
 * @brief Check whether a list contains a given string.
 *
 * Compares strings using strcmp (streq macro).
 *
 * @param list: Pointer to the string list.
 * @param s: String to search for.
 *
 * @return true if @s exists in the list, false otherwise.
 */
static bool strlst_contains(const StringList_t *list, const char *s)
{
	const char *str;

	STRLST_FOREACH(list, str) {
		if (streq(s, str))
			return true;
	}
	return false;
}

/**
 * @brief Load strings from a text file into a StringList_t.
 *
 * Reads the file line-by-line. For each line, trims whitespace and
 * skips empty lines or lines starting with '#'. Remaining lines are
 * added to @list.
 *
 * @param list: Pointer to the initialized StringList_t to append to.
 * @param filename: Path to the file to read. If NULL, the
 *                  function returns immediately.
 */
static void strlst_load(StringList_t *list, const char *filename)
{
	char line[LINE_MAX];
	FILE *f;

	if (!filename)
		return;

	f = fopen(filename, "r");
	if (!f) {
		fprintf(stderr, "Warning: could not open file '%s'\n", filename);
		return;
	}

	while (fgets(line, sizeof(line), f)) {
		/* Strip whitespace and comments */
		char *p = trim(line);

		if (*p == '\0' || *p == '#')
			continue;
		strlst_add(list, p, false);
	}

	fclose(f);
}

/**
 * @brief Check whether a struct or struct member is excluded.
 *
 * The exclusion list may contain either struct names (to exclude the
 * whole struct) or entries of the form "StructName::member" to exclude
 * individual members.
 *
 * @param excl_list: Pointer to the exclusion StringList_t.
 * @param struct_name: Name of the struct being considered.
 * @param member_name: Name of the member (or NULL to check whole struct).
 *
 * @return true if the struct or member is present in the exclusion list,
 *         false otherwise.
 */
static bool is_excluded(const StringList_t *excl_list,
			const char         *struct_name,
			const char         *member_name)
{
	char key[LINE_MAX];

	/* First, check if the whole struct is excluded */
	for (size_t i = 0; i < excl_list->count; i++) {
		if (streq(excl_list->strings[i], struct_name))
			return true; /* exclude entire struct */
	}

	if (!member_name)
		return false;

	/* Second, check if StructName::member is excluded */
	snprintf(key, sizeof(key), "%s::%s", struct_name, member_name);
	for (size_t i = 0; i < excl_list->count; i++) {
		if (streq(excl_list->strings[i], key))
			return true; /* exclude member of struct */
	}

	return false;
}

/**
 * @brief Decide whether a struct name is included by the include list.
 *
 * If the include list is empty, everything is considered included.
 *
 * @param incl_list: Pointer to inclusion StringList_t.
 * @param struct_name: Name of the struct to test.
 *
 * @return true if struct is included (or include list empty), false otherwise.
 */
static bool is_included(const StringList_t *incl_list, const char *struct_name)
{
	/* Note: If include list is empty, then everything is included */
	if (STRLST_EMPTY(incl_list))
		return true;

	return strlst_contains(incl_list, struct_name);
}


/******************************************************************************/


typedef struct Args {
	bool          verbose;
	const char    *c_fname;		/* Generated output *.c file name */
	const char    *h_fname;		/* Generated output *.h file name */
	const char    *prefix;		/* Prefix added to each functions */
	const char    *excl_file;	/* Exclusion list */
	const char    *incl_file;	/* Inclusion list */
	StringList_t  hdr_files;	/* Input header file list */
} Args_t;

typedef struct {
	regex_t       re_struct;
	regex_t       re_char_array;
	regex_t       re_member;
} regex_db_t;

typedef struct Conf {
	Args_t        args;
	StringList_t  incl_list;
	StringList_t  excl_list;
	regex_db_t    re;
} Conf_t;


/******************************************************************************/
/**
 * The following structures are used to save the structs and members found
 * while parsing the header files (*.h). Here's the relationship between
 * the different objects.
 *
 * +--------------------------+
 * |        StructList_t      |
 * |--------------------------|
 * | StructInfo_t *items ---> [ array of StructInfo_t ]
 * | size_t count             |
 * | size_t capacity          |
 * +--------------------------+
 *               |
 *               v
 *     +--------------------------+
 *     |       StructInfo_t       |
 *     |--------------------------|
 *     | char *name               |
 *     | Member_t *members ---> [ array of Member_t ]
 *     | size_t count             |
 *     | size_t capacity          |
 *     +--------------------------+
 *                     |
 *                     v
 *          +--------------------------+
 *          |         Member_t         |
 *          |--------------------------|
 *          | char *type               |
 *          | char *name               |
 *          | char *array_size         |
 *          | bool is_char_array       |
 *          | bool is_const            |
 *          +--------------------------+
 */

typedef struct Member {
	char          *type;         /* Type of the struct member */
	char          *name;         /* Name of the struct member */
	char          *array_size;   /* If member is an array, what is its [size] */
	bool          is_char_array; /* Whether the member is an array */
	bool          is_const;      /* Whether the member is defined as const */
} Member_t;

typedef struct StructInfo {
	char          *name;         /* Name of the struct */
	Member_t      *members;      /* Array of struct members (each entry is one member) */
	size_t        count;         /* Number of entries in members */
	size_t        capacity;      /* Allocated capacity for members */
} StructInfo_t;

typedef struct StructList {
	StructInfo_t  *items;        /* Array of structs (each entry corresponds to one struct) */
	size_t        count;         /* Number of entries in items */
	size_t        capacity;      /* Allocated capacity for items */
} StructList_t;

/**
 * @brief Initialize Member_t to default empty values.
 *
 * Sets pointer fields to NULL and booleans to false.
 *
 * @param m: Pointer to Member_t to initialize.
 */
static void member_init(Member_t *m)
{
	m->type = NULL;
	m->name = NULL;
	m->array_size = NULL;
	m->is_char_array = false;
	m->is_const = false;
}

/**
 * @brief Free and reset Member_t fields.
 *
 * Frees any allocated strings in @m and reinitializes it.
 *
 * @param m: Pointer to Member_t to clear.
 */
static void member_clear(Member_t *m)
{
	free(m->type);
	free(m->name);
	free(m->array_size);
	member_init(m);
}


/**
 * @brief Initialize a StructInfo_t object with default capacity.
 *
 * Allocates the members array with default capacity
 * (MEMBERS_INITIAL_CAPACITY) and sets initial field values.
 *
 * @param si: Pointer to StructInfo_t to initialize.
 */
#define MEMBERS_INITIAL_CAPACITY 8
static void struct_info_init(StructInfo_t *si)
{
	si->name = NULL;
	si->count = 0;
	si->capacity = MEMBERS_INITIAL_CAPACITY;
	si->members = malloc(si->capacity * sizeof(Member_t));
	for (size_t m = 0; m < si->capacity; m++)
		member_init(&si->members[m]);
}

/**
 * @brief Clear the contents (members and name) of a StructInfo_t.
 *
 * Frees per-member allocations and the name string, but leaves the
 * struct ready for reuse (members array kept).
 *
 * @param si: Pointer to StructInfo_t to clear.
 */
static void struct_info_clear(StructInfo_t *si)
{
	for (size_t i = 0; i < si->count; ++i)
		member_clear(&si->members[i]);
	si->count = 0;
	free(si->name);
	si->name = NULL;
}

/**
 * @brief Free all resources used by a StructInfo_t.
 *
 * Frees members and the members array, resets pointers and capacity.
 *
 * @param si: Pointer to StructInfo_t to free.
 */
static void struct_info_free(StructInfo_t *si)
{
	for (size_t i = 0; i < si->capacity; ++i)
		member_clear(&si->members[i]);
	si->count = 0;
	free(si->members);
	si->members = NULL;

	free(si->name);
	si->name = NULL;

	si->capacity = 0;
}

/**
 * @brief Add a member to a StructInfo_t, growing the array if needed.
 *
 * Adds a new Member_t to @si. If capacity is insufficient the members
 * array is reallocated (doubled). The new Member_t's type and name are
 * set either by stealing the passed pointers or by duplicating them
 * depending on @steal_type/@steal_name.
 *
 * @param si: Pointer to StructInfo_t to append to.
 * @param type: String describing the member type.
 * @param name: Member name string.
 * @param steal_type: If true, take ownership of @type pointer (no copy).
 * @param steal_name: If true, take ownership of @name pointer (no copy).
 *
 * @return Pointer to the newly added Member_t.
 */
static Member_t *struct_info_member_add(StructInfo_t *si,
					char         *type,
					char         *name,
					bool         steal_type,
					bool         steal_name)
{
	Member_t *m;

	if (si->count == si->capacity) {
		/* Reallocate to double capacity */
		si->capacity *= 2;
		si->members = (Member_t *)realloc(si->members, si->capacity * sizeof(Member_t));
		for (size_t i = si->count; i < si->capacity; i++)
			member_init(&si->members[i]);
	}
	m = &si->members[si->count++];
	m->type = steal_type ? type : safe_strdup(type);
	m->name = steal_name ? name : safe_strdup(name);
	return m;
}

/**
 * @brief Test whether a StructInfo_t contains no members.
 *
 * @param si: Pointer to StructInfo_t.
 *
 * @return true if si has zero members, false otherwise.
 */
#define STRUCT_INFO_EMPTY(si) ((si)->count == 0)


/**
 * @brief Initialize a StructList_t with default capacity.
 *
 * Allocates the items array and initializes contained StructInfo_t
 * entries.
 *
 * @param sl: Pointer to StructList_t to initialize.
 */
static void struct_list_init(StructList_t *sl)
{
	sl->count = 0;
	sl->capacity = 16;
	sl->items = malloc(sl->capacity * sizeof(StructInfo_t));
	for (size_t i = 0; i < sl->capacity; i++)
		struct_info_init(&sl->items[i]);
}


/**
 * @brief Clear all StructInfo_t elements in a StructList_t.
 *
 * Calls struct_info_clear on each existing item and resets count to 0.
 *
 * @param sl: Pointer to StructList_t to clear.
 */
static void struct_list_clear(StructList_t *sl)
{
	for (size_t i = 0; i < sl->count; ++i)
		struct_info_clear(&sl->items[i]);
	sl->count = 0;
}

/**
 * @brief Free all resources used by a StructList_t.
 *
 * Frees each StructInfo_t and the items array and resets list fields.
 *
 * @param sl: Pointer to StructList_t to free.
 */
static void struct_list_free(StructList_t *sl)
{
	for (size_t i = 0; i < sl->capacity; ++i)
		struct_info_free(&sl->items[i]);
	free(sl->items);
	sl->items = NULL;
	sl->count = 0;
	sl->capacity = 0;
}

/**
 * @brief Add a new StructInfo_t entry to a StructList_t.
 *
 * If the list capacity is exhausted it doubles capacity and reallocates
 * the items array. The struct name is either stolen or duplicated
 * depending on @steal.
 *
 * @param sl: Pointer to StructList_t.
 * @param struct_name: Name of the struct to add.
 * @param steal: If true, take ownership of @struct_name pointer.
 *
 * @return Pointer to the newly added StructInfo_t.
 */
static StructInfo_t *struct_list_struct_add(StructList_t *sl,
					    char         *struct_name,
					    bool         steal)
{
	StructInfo_t *si;

	if (sl->count == sl->capacity) {
		/* Reallocate to increase capacity */
		sl->capacity *= 2; /* Double the capacity */
		sl->items = (StructInfo_t *)realloc(sl->items,
						    sl->capacity * sizeof(StructInfo_t));
		for (size_t i = sl->count; i < sl->capacity; i++)
			struct_info_init(&sl->items[i]);
	}
	si = &sl->items[sl->count++];
	si->name = steal ? struct_name : safe_strdup(struct_name);
	return si;
}

/**
 * @brief Test if a StructList_t contains no structs.
 *
 * @param sl: Pointer to StructList_t.
 *
 * @return true if no items present, false otherwise.
 */
#define STRUCT_LIST_EMPTY(sl) ((sl)->count == 0)

/**
 * @brief Parse C structs from a header text and populate StructList_t.
 *
 * Uses compiled regexes in @conf to find struct definitions in @text,
 * extracts member declarations and populates @sl with StructInfo_t
 * entries. Honors include/exclude lists in @conf.
 *
 * The function:
 *  - Clears @sl before parsing.
 *  - Iterates all regex matches for "struct ... { ... };" as defined by
 *    conf->re.re_struct.
 *  - Removes C comments and inline comments and tokenizes the struct
 *    body by newline to parse individual member declarations.
 *  - Supports char arrays and pointer-to-char members specially.
 *
 * @param sl: Pointer to StructList_t to populate (must be initialized).
 * @param text: Null-terminated text containing header content.
 * @param conf: Pointer to configuration containing regexes and lists.
 */
static void struct_list_parse(StructList_t *sl, const char *text, Conf_t *conf)
{
	regmatch_t regmatch_struct[4];
	const char *cursor;
	int rc;

	struct_list_clear(sl);

	for (cursor = text,
	     rc = regexec(&conf->re.re_struct, cursor, 4, regmatch_struct, 0);
	     rc == 0;
	     cursor += regmatch_struct[0].rm_eo,
	     rc = regexec(&conf->re.re_struct, cursor, 4, regmatch_struct, 0)) {
		struct StructInfo  *si;
		char  *struct_name;
		char  *body;
		char  *line;

		struct_name = regmatch_strdup(cursor, &regmatch_struct[1]);

		if (is_excluded(&conf->excl_list, struct_name, NULL) ||
		    !is_included(&conf->incl_list, struct_name)) {
			free(struct_name);
			continue;
		}

		si = struct_list_struct_add(sl, struct_name, true);

		body = regmatch_strdup(cursor, &regmatch_struct[2]);
		mask_c_comments(body);

		/* Split struct body into lines */
		for (line = strtok(body, "\n"); line != NULL; line = strtok(NULL, "\n")) {
			regmatch_t  regmatch_member[5];
			char  *trimmed_line;

			trimmed_line = trim(trim_inline_comments(line));

			if (trimmed_line[0] == '\0' ||        /* empty line */
			    !strchr(trimmed_line, ';') ||     /* skip lines without semicolon */
			    strstr(trimmed_line, "static") || /* skip static members */
			    strstr(trimmed_line, "struct"))   /* skip struct members */
				continue;

			/* Look for char arrays. E.g. char buffer[10] */
			if (regexec(&conf->re.re_char_array, trimmed_line, 5,
				    regmatch_member, 0) == 0) {
				char *name;
				Member_t *m;

				name = regmatch_strdup(trimmed_line, &regmatch_member[2]);
				if (is_excluded(&conf->excl_list, struct_name, name)) {
					free(name);
					continue;
				}
				m = struct_info_member_add(si, "const char *", name, false, true);

				m->is_char_array = true;
				m->is_const = regmatch_startswith(trimmed_line,
								  &regmatch_member[1], "const");
				m->array_size = regmatch_strdup(trimmed_line, &regmatch_member[3]);

				continue;
			}

			/* All other members */
			if (regexec(&conf->re.re_member, trimmed_line, 5,
				    regmatch_member, 0) == 0) {
				Member_t *m;
				bool is_ptr;
				char *type;
				char *name;

				name = regmatch_strdup(trimmed_line, &regmatch_member[4]);
				if (is_excluded(&conf->excl_list, struct_name, name)) {
					free(name);
					continue;
				}

				is_ptr = regmatch_contains_char(trimmed_line,
								&regmatch_member[3], '*');
				if (is_ptr) {
					bool is_char =
						regmatch_startswith(trimmed_line,
								    &regmatch_member[2], "char");

					/* Skip if we have a pointer, but it's not a "char *" */
					if (!is_char) {
						free(name);
						continue;
					}

					/* type is used as the getter return type */
					type = safe_strdup("const char *");
				} else {
					type = regmatch_strdup(trimmed_line, &regmatch_member[2]);
				}

				m = struct_info_member_add(si, type, name, true, true);
				m->is_const = regmatch_startswith(trimmed_line,
								  &regmatch_member[1], "const");
			}
		}
		free(body);

		if (conf->args.verbose && !STRUCT_INFO_EMPTY(si))
			printf("Found struct: %s (%zu members)\n", si->name, si->count);
	}
}

/**
 * @brief Iterate over a StructList_t returning next StructInfo_t*.
 *
 * @param sl: Pointer to the struct list.
 * @param si: Pointer that gets updated with StructInfo_t* at
 *            current index or NULL if end reached.
 */
#define STRUCT_LIST_FOREACH(sl, si) \
	for (size_t __si_next = 0; \
	({ \
		(si) = (__si_next >= (sl)->count) ? NULL : &(sl)->items[__si_next++]; \
		(si) != NULL; \
	});)

/******************************************************************************/


/**
 * @brief Generate header (.h) declarations for accessors of one struct.
 *
 * Writes function prototypes for setters and getters for every member
 * of @si to the provided output FILE (@generated_hdr).
 *
 * @param generated_hdr: FILE* to write header declarations to.
 * @param si: Pointer to StructInfo_t describing the struct and members.
 * @param conf: Pointer to Conf_t containing args and generation options.
 */
static void generate_hdr(FILE  *generated_hdr, StructInfo_t  *si, Conf_t *conf)
{
	for (size_t m = 0; m < si->count; m++) {
		Member_t  *members = &si->members[m];

		/* Setter method */
		if (!members->is_const) { /* No setter on const members */
			if (members->is_char_array || streq(members->type, "const char *"))
				fprintf(generated_hdr,
					"void %s%s_%s_set(struct %s *p, const char *%s);\n",
					conf->args.prefix, si->name,
					members->name, si->name, members->name);
			else
				fprintf(generated_hdr,
					"void %s%s_%s_set(struct %s *p, %s %s);\n",
					conf->args.prefix, si->name,
					members->name, si->name, members->type, members->name);
		}

		/* Getter method */
		fprintf(generated_hdr, "%s %s%s_%s_get(struct %s *p);\n\n",
			members->type, conf->args.prefix, si->name, members->name, si->name);
	}
}

/**
 * @brief Generate source (.c) implementations for accessors of one struct.
 *
 * Writes setter and getter function implementations for each member in
 * @si to the provided output FILE (@generated_src). Handles special
 * cases:
 *  - dynamic "const char *" members are strdup'd and freed on set.
 *  - fixed-size char arrays use strncpy and ensure NUL termination.
 *  - other members are assigned directly.
 *
 * @param generated_src: FILE* to write implementations to.
 * @param si: Pointer to the struct description.
 * @param conf: Pointer to Conf_t controlling generation options.
 */
static void generate_src(FILE  *generated_src, StructInfo_t  *si, Conf_t  *conf)
{
	for (size_t m = 0; m < si->count; m++) {
		Member_t  *member = &si->members[m];

		/* Setter method */
		if (!member->is_const) {
			if (!member->is_char_array && streq(member->type, "const char *")) {
				/* dynamic string */
				fprintf(generated_src,
					"void %s%s_%s_set(struct %s *p, const char *%s) {\n"
					"    free(p->%s);\n"
					"    p->%s = %s ? strdup(%s) : NULL;\n"
					"}\n\n",
					conf->args.prefix, si->name, member->name,
					si->name, member->name,
					member->name,
					member->name, member->name, member->name);
			} else if (member->is_char_array) {
				/* fixed-size array */
				if (str_is_all_numbers(member->array_size)) {
					unsigned long sz = strtoul(member->array_size, NULL, 10);

					fprintf(generated_src,
						"void %s%s_%s_set(struct %s *p, const char *%s) {\n"
						"    strncpy(p->%s, %s, %lu);\n"
						"    p->%s[%lu] = '\\0';\n"
						"}\n\n",
						conf->args.prefix, si->name, member->name,
						si->name, member->name,
						member->name, member->name, sz,
						member->name, sz - 1);
				} else {
					fprintf(generated_src,
						"void %s%s_%s_set(struct %s *p, const char *%s) {\n"
						"    strncpy(p->%s, %s, %s);\n"
						"    p->%s[%s - 1] = '\\0';\n"
						"}\n\n",
						conf->args.prefix, si->name, member->name,
						si->name, member->name,
						member->name, member->name, member->array_size,
						member->name, member->array_size);
				}
			} else { /* numeric or struct */
				fprintf(generated_src,
					"void %s%s_%s_set(struct %s *p, %s %s) {\n"
					"    p->%s = %s;\n"
					"}\n\n",
					conf->args.prefix, si->name, member->name, si->name,
					member->type, member->name,
					member->name, member->name);

			}
		}

		/* Getter method */
		fprintf(generated_src, "%s %s%s_%s_get(struct %s *p) {\n"
			"    return p->%s;\n"
			"}\n\n",
			member->type, conf->args.prefix, si->name, member->name, si->name,
			member->name);
	}
}


/******************************************************************************/


/**
 * @brief Print usage information for this program.
 *
 * @param prog: Program name (argv[0]) used in the usage message.
 */
static void print_usage(const char *prog)
{
	printf("Usage: %s [options] <header_file>\n"
	       "Options:\n"
	       "  -c, --c-out         Name of the generated *.c file. Default: %s\n"
	       "  -h, --h-out         Name of the generated *.h file. Default: %s\n"
	       "  -e, --excl <file>   Exclusion list. Which member of a struct to exclude (struct::member per line). Default: do not exclude anything\n"
	       "  -i, --incl <file>   Inclusion list. Which struct to include (struct name per line). Default: include every struct found\n"
	       "  -p, --prefix <str>  Prefix for generated function names\n"
	       "  -v, --verbose       Verbose output\n"
	       "  -H, --help          Show this message\n",
	       prog, OUTPUT_FNAME_DEFAULT_C, OUTPUT_FNAME_DEFAULT_H);
}

/**
 * @brief Parse command line arguments and populate an Args_t.
 *
 * Uses getopt_long to process supported options and expands file
 * wildcards using glob(). Populates args->hdr_files with matched
 * header filenames.
 *
 * @param args: Pointer to Args_t to populate (must be writable).
 * @param argc: Argument count from main().
 * @param argv: Argument vector from main().
 *
 * @note This function exits the process on fatal errors (missing files).
 */
static void args_init(Args_t *args, int argc, char *argv[])
{
	int  opt;
	int  option_index = 0;

	args->verbose = false;
	args->c_fname = OUTPUT_FNAME_DEFAULT_C;
	args->h_fname = OUTPUT_FNAME_DEFAULT_H;
	args->prefix = "";
	args->excl_file = NULL;
	args->incl_file = NULL;
	strlst_init(&args->hdr_files, 16);

	static struct option long_options[] = {
		{ "c-out",   required_argument, 0, 'c' },
		{ "h-out",   required_argument, 0, 'h' },
		{ "excl",    required_argument, 0, 'e' },
		{ "incl",    required_argument, 0, 'i' },
		{ "prefix",  required_argument, 0, 'p' },
		{ "verbose", no_argument,       0, 'v' },
		{ "help",    no_argument,       0, 'H' },
		{ 0, 0, 0, 0 }
	};

	while ((opt =
		  getopt_long(argc, argv, "o:c:h:e:i:p:vH", long_options, &option_index)) != -1) {
		switch (opt) {
		case 'c':
			args->c_fname = optarg;
			break;
		case 'h':
			args->h_fname = optarg;
			break;
		case 'e':
			args->excl_file = optarg;
			break;
		case 'i':
			args->incl_file = optarg;
			break;
		case 'p':
			args->prefix = optarg;
			break;
		case 'v':
			args->verbose = true;
			break;
		case 'H':
			print_usage(argv[0]);
			exit(EXIT_SUCCESS);
		default:
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	/* Remaining arguments after options are file names or wildcards */
	if (optind >= argc) {
		fprintf(stderr, "Please specify header file(s) to parse\n");
		exit(EXIT_FAILURE);
	}

	for (int i = optind; i < argc; ++i) {
		glob_t  glob_result = { 0 };
		int  ret = glob(argv[i], GLOB_TILDE|GLOB_NOCHECK, NULL, &glob_result);

		if (ret == 0) {
			for (size_t j = 0; j < glob_result.gl_pathc; ++j)
				strlst_add(&args->hdr_files,
					   realpath(glob_result.gl_pathv[j], NULL), true);
		} else {
			fprintf(stderr, "Warning: No match for %s\n", argv[i]);
		}
		globfree(&glob_result);
	}
}

/**
 * @brief Free resources held by Args_t.
 *
 * Frees the hdr_files list contents and resets fields as necessary.
 *
 * @param args: Pointer to Args_t to free.
 */
static void args_free(Args_t *args)
{
	strlst_free(&args->hdr_files);
}

/**
 * @brief Initialize Conf_t including regex compilation and loading lists.
 *
 * Parses command-line args via args_init, initializes inclusion and
 * exclusion lists and compiles the regular expressions used to parse
 * structs and members.
 *
 * @param conf: Pointer to Conf_t to initialize.
 * @param argc: Argument count from main().
 * @param argv: Argument vector from main().
 */
#define STRUCT_RE   "struct[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*\\{([^}]*)\\}[[:space:]]*;"
#define CHAR_ARRAY_RE "^(const[[:space:]]+)?char[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*\\[[[:space:]]*([A-Za-z0-9_]+)[[:space:]]*\\][[:space:]]*;"
#define MEMBER_RE "^(const[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)([*[:space:]]+)([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*;"
static void conf_init(Conf_t *conf, int argc, char *argv[])
{
	args_init(&conf->args, argc, argv);

	strlst_init(&conf->incl_list, 16);
	strlst_load(&conf->incl_list, conf->args.incl_file);

	strlst_init(&conf->excl_list, 16);
	strlst_load(&conf->excl_list, conf->args.excl_file);

	regcomp(&conf->re.re_struct, STRUCT_RE, REG_EXTENDED);
	regcomp(&conf->re.re_member, MEMBER_RE, REG_EXTENDED);
	regcomp(&conf->re.re_char_array, CHAR_ARRAY_RE, REG_EXTENDED);
}

/**
 * @brief Free resources allocated in Conf_t.
 *
 * Frees include/exclude lists, releases compiled regexes and frees
 * argument-held resources via args_free.
 *
 * @param conf: Pointer to Conf_t to free.
 */
static void conf_free(Conf_t *conf)
{
	strlst_free(&conf->incl_list);
	strlst_free(&conf->excl_list);

	regfree(&conf->re.re_char_array);
	regfree(&conf->re.re_member);
	regfree(&conf->re.re_struct);

	args_free(&conf->args);
}


/******************************************************************************/


/**
 * @brief Main program entry point.
 *
 * Parses CLI, reads header files, discovers structs and members, and
 * generates accessor header/source files.
 *
 * @param argc: Argument count.
 * @param argv: Argument vector.
 *
 * @return EXIT_SUCCESS on success (exits the program), or exits with
 *         failure codes on errors encountered.
 */
int main(int argc, char *argv[])
{
	StructList_t  sl;
	StringList_t  files_to_include;
	StringList_t  forward_declares;
	const char    *struct_to_declare;
	const char    *include_fname;
	const char    *in_hdr;
	char          *guard;
	FILE          *generated_hdr = NULL;
	FILE          *generated_src = NULL;
	FILE          *tmp_hdr_code = NULL;
	FILE          *tmp_src_code = NULL;
	Conf_t        conf;
	int           dont_care;
	int           c;

	(void)dont_care;

	conf_init(&conf, argc, argv);

	struct_list_init(&sl);
	strlst_init(&files_to_include, 0);
	strlst_init(&forward_declares, 0);

	/* Creates temporary files to hold the generated code. */
	tmp_hdr_code = tmpfile();
	tmp_src_code = tmpfile();

	STRLST_FOREACH(&conf.args.hdr_files, in_hdr) {
		StructInfo_t *si;
		const char   *in_hdr_fname = get_filename(in_hdr);

		if (conf.args.verbose)
			printf("\nProcessing %s\n", in_hdr);

		char *text = read_file(in_hdr);

		struct_list_parse(&sl, text, &conf);
		free(text);

		if (STRUCT_LIST_EMPTY(&sl)) {
			if (conf.args.verbose) {
				if (STRLST_EMPTY(&conf.incl_list))
					printf("No structs found in %s.\n",
					       in_hdr);
				else
					printf("Structs in %s are not in the include list.\n",
					       in_hdr);
			}
			continue;
		}

		strlst_add(&files_to_include, in_hdr_fname, false);

		STRUCT_LIST_FOREACH(&sl, si) {
			if (STRUCT_INFO_EMPTY(si))
				continue;

			strlst_add(&forward_declares, si->name, false);

			/* Generate code for the header file (*.h) */
			fprintf(tmp_hdr_code,
				"\n"
				"/****************************************************************************\n"
				" * Accessors for: struct %s\n"
				" */\n", si->name);
			generate_hdr(tmp_hdr_code, si, &conf);

			/* Generate code for the source file (*.c) */
			fprintf(tmp_src_code,
				"\n"
				"/****************************************************************************\n"
				" * Accessors for: struct %s\n"
				" */\n", si->name);
			generate_src(tmp_src_code, si, &conf);
		}
	}

	struct_list_free(&sl);

	/* We've collected all the data we needed. Now let's generate some files. */

	/***********************************************************************
	 * First, output the generated header file.
	 */

	/* Add a guard in the generated header file that is made of
	 * the UPPERCASE file name's stem. In other words, if the file
	 * name is "accessors.h" then the guard should be "_ACCESSORS_H_"
	 */
	dont_care = asprintf(&guard, "_%s_", get_filename(conf.args.h_fname));
	sanitize_identifier(to_uppercase(guard));

	mkdir_fullpath(conf.args.h_fname, 0755); /* create output file's directory if needed */

	generated_hdr = fopen(conf.args.h_fname, "w");
	fprintf(generated_hdr,
		"%s\n"
		"#ifndef %s\n"
		"#define %s\n"
		"\n"
		"#include <stdlib.h>\n"
		"#include <string.h>\n"
		"#include <stdbool.h>\n"
		"#include <stdint.h>\n"
		"#include <linux/types.h> /* __u32, __u64, etc. */\n"
		"\n", banner, guard, guard);

	fprintf(generated_hdr, "/* Forward declarations. These are internal (opaque) structs. */\n");
	STRLST_FOREACH(&forward_declares, struct_to_declare)
		fprintf(generated_hdr, "struct %s;\n", struct_to_declare);
	strlst_free(&forward_declares);

	/* Copy temporary file to output */
	rewind(tmp_hdr_code);
	while ((c = fgetc(tmp_hdr_code)) != EOF)
		fputc(c, generated_hdr);
	fclose(tmp_hdr_code);

	fprintf(generated_hdr, "#endif /* %s */\n", guard);
	fclose(generated_hdr);
	free(guard);


	/***********************************************************************
	 * Second, output the generated source file.
	 */

	mkdir_fullpath(conf.args.c_fname, 0755); /* create output file's directory if needed */
	generated_src = fopen(conf.args.c_fname, "w");
	fprintf(generated_src,
		"%s\n"
		"#include <stdlib.h>\n"
		"#include <string.h>\n"
		"#include \"%s\"\n"
		"\n", banner, get_filename(conf.args.h_fname));

	STRLST_FOREACH(&files_to_include, include_fname)
		fprintf(generated_src, "#include \"%s\"\n", include_fname);
	strlst_free(&files_to_include);

	/* Copy temporary file to output */
	rewind(tmp_src_code);
	while ((c = fgetc(tmp_src_code)) != EOF)
		fputc(c, generated_src);
	fclose(tmp_src_code);

	fclose(generated_src);

	if (conf.args.verbose)
		printf("\nGenerated %s and %s\n", conf.args.h_fname, conf.args.c_fname);

	conf_free(&conf);

	exit(EXIT_SUCCESS);
}

