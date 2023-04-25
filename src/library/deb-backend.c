#include <dpkg/db-ctrl.h>
#include <dpkg/db-fsys.h>
#include <dpkg/pkg-array.h>
#include <dpkg/program.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <uthash.h>

#include "conf.h"
#include "fapolicyd-backend.h"
#include "file.h"
#include "llist.h"
#include "message.h"

static const char kDebBackend[] = "debdb";
const int kMaxKeyLength = 4096;
const int kMd5HexSize = 32;

static int deb_init_backend(void);
static int deb_load_list(const conf_t *);
static int deb_destroy_backend(void);

backend deb_backend = {
    kDebBackend,
    deb_init_backend,
    deb_load_list,
    deb_destroy_backend,
    /* list initialization */
    {0, 0, NULL},
};

struct _hash_record {
  const char *key;
  UT_hash_handle hh;
};

/*
 * Given a path to a file with an expected MD5 digest, add
 * the file to the trust database if it matches.
 *
 * Dpkg does not provide sha256 sums or file sizes to verify against.
 * The only source for verification is MD5. The logic implemented is:
 * 1) Calculate the MD5 sum and compare to the dpkg database. If it does
 *    not match, abort.
 * 2) Calculate the SHA256 and file size on the local files.
 * 3) Add to database.
 *
 * Security considerations:
 * An attacker would need to craft a file with a MD5 hash collision.
 * While MD5 is considered broken, this is still some effort.
 * This function would compute a sha256 and file size on the attackers
 * crafted file so they do not secure this backend.
 */
static int add_file_to_backend(const char *path,
                               struct _hash_record **hashtable,
                               const char *expected_md5) {
  struct stat path_stat;
  stat(path, &path_stat);

  // If its not a regular file, skip.
  if (!S_ISREG(path_stat.st_mode)) {
    msg(LOG_DEBUG, "\nNot regular file %s", path);
    return 1;
  }

  // Open the file and calculate sha256 and size.
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    msg(LOG_WARNING, "\nCould not open %s", path);
    return 1;
  }
  size_t file_size = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);
  char *sha_digest = get_hash_from_fd2(fd, file_size, 1);

  if (sha_digest == NULL) {
    msg(LOG_ERR, "\nSha digest returned NULL");
    return 1;
  }

  lseek(fd, 0, SEEK_SET);
  char *md5_digest = get_hash_from_fd2(fd, file_size, 0);

  if (md5_digest == NULL) {
    free(sha_digest);
    msg(LOG_ERR, "\nMD5 digest returned NULL");
    return 1;
  }

  close(fd);

  if (strcmp(md5_digest, expected_md5) != 0) {
    msg(LOG_WARNING, "\nSkipping %s as hash mismatched. Should be %s, got %s",
        path, expected_md5, md5_digest);
    free(sha_digest);
    free(md5_digest);
    return 1;
  }
  free(md5_digest);

  char *data;
  if (asprintf(&data, DATA_FORMAT, SRC_DEB, file_size, sha_digest) == -1) {
    data = NULL;
  }
  free(sha_digest);

  if (data) {
    // Getting rid of the duplicates.
    struct _hash_record *rcd = NULL;
    char key[kMaxKeyLength];
    snprintf(key, kMaxKeyLength - 1, "%s %s", path, data);

    HASH_FIND_STR(*hashtable, key, rcd);

    if (!rcd) {
      rcd = (struct _hash_record *)malloc(sizeof(struct _hash_record));
      rcd->key = strdup(key);
      HASH_ADD_KEYPTR(hh, *hashtable, rcd->key, strlen(rcd->key), rcd);
      list_append(&deb_backend.list, strdup(path), data);
    } else {
      free((void *)data);
    }
    return 0;
  }
  return 1;
}

// ================================================================
// These functions are copied from dpkg source v1.21.1
// For some reason they segfault when i call :/

parse_filehash_buffer(struct varbuf *buf, struct pkginfo *pkg,
                      struct pkgbin *pkgbin) {
  char *thisline, *nextline;
  const char *pkgname = pkg_name(pkg, pnaw_nonambig);
  const char *buf_end = buf->buf + buf->used;

  for (thisline = buf->buf; thisline < buf_end; thisline = nextline) {
    struct fsys_namenode *namenode;
    char *endline, *hash_end, *filename;

    endline = memchr(thisline, '\n', buf_end - thisline);
    if (endline == NULL) {
      msg(LOG_ERR,
          "control file '%s' for package '%s' is "
          "missing final newline\n",
          HASHFILE, pkgname);
      return 1;
    }

    /* The md5sum hash has a constant length. */
    hash_end = thisline + kMd5HexSize;

    filename = hash_end + 2;
    if (filename + 1 > endline) {
      msg(LOG_ERR,
          "control file '%s' for package '%s' is "
          "missing value\n",
          HASHFILE, pkgname);
      return 1;
    }

    if (hash_end[0] != ' ' || hash_end[1] != ' ') {
      msg(LOG_ERR,
          "control file '%s' for package '%s' is "
          "missing value separator\n",
          HASHFILE, pkgname);
      return 1;
    }
    hash_end[0] = '\0';

    /* Where to start next time around. */
    nextline = endline + 1;
    /* Strip trailing ‘/’. */
    if (endline > thisline && endline[-1] == '/') endline--;
    *endline = '\0';

    if (endline == thisline) {
      msg(LOG_ERR,
          "control file '%s' for package '%s' "
          "contains empty filename\n",
          HASHFILE, pkgname);
      return 1;
    }

    /* Add the file to the list. */
    namenode = fsys_hash_find_node(filename, 0);
    namenode->newhash = nfstrsave(thisline);
  }
}

void parse_filehash2(struct pkginfo *pkg, struct pkgbin *pkgbin) {
  const char *hashfile;
  struct varbuf buf = VARBUF_INIT;
  struct dpkg_error err = DPKG_ERROR_INIT;

  hashfile = pkg_infodb_get_file(pkg, pkgbin, HASHFILE);

  if (file_slurp(hashfile, &buf, &err) < 0 && err.syserrno != ENOENT)
    msg(LOG_ERR, "loading control file '%s' for package '%s'", HASHFILE,
        pkg_name(pkg, pnaw_nonambig));

  if (buf.used > 0) parse_filehash_buffer(&buf, pkg, pkgbin);

  varbuf_destroy(&buf);
}

// End of functions copied from dpkg.
// =======================================================================

static int deb_load_list(const conf_t *conf) {
  const char *control_file = "md5sums";

  list_empty(&deb_backend.list);
  struct _hash_record *hashtable = NULL;
  struct _hash_record **hashtable_ptr = &hashtable;

  struct pkg_array array;
  pkg_array_init_from_hash(&array);

  msg(LOG_INFO, "Computing hashes for %d packages.", array.n_pkgs);

  for (int i = 0; i < array.n_pkgs; i++) {
    struct pkginfo *package = array.pkgs[i];
    if (package->status != PKG_STAT_INSTALLED) {
      continue;
    }
    printf("\x1b[2K\rPackage %d / %d : %s", i + 1, array.n_pkgs,
           package->set->name);
    if (pkg_infodb_has_file(package, &package->installed, control_file))
      pkg_infodb_get_file(package, &package->installed, control_file);
    ensure_packagefiles_available(package);

    // Should not need this copy of code ...
    parse_filehash2(package, &package->installed);

    // This is causing segfault in linked lib :/
    // parse_filehash(package, &package->installed);
    // ensure_diversions();

    struct fsys_namenode_list *file = package->files;
    if (!file) {
      // Package does not have any files.
      continue;
    }
    // Loop over all files in the package, adding them to debdb.
    while (file) {
      struct fsys_namenode *namenode = file->namenode;
      // Get the hash and path of the file.
      const char *hash =
          (namenode->newhash == NULL) ? namenode->oldhash : namenode->newhash;
      const char *path = (namenode->divert && !namenode->divert->camefrom)
                             ? namenode->divert->useinstead->name
                             : namenode->name;
      if (hash != NULL) {
        add_file_to_backend(path, hashtable_ptr, hash);
      }
      file = file->next;
    }
  }

  struct _hash_record *item, *tmp;
  HASH_ITER(hh, hashtable, item, tmp) {
    HASH_DEL(hashtable, item);
    free((void *)item->key);
    free((void *)item);
  }

  pkg_array_destroy(&array);
  return 0;
}

static int deb_init_backend() {
  dpkg_program_init(kDebBackend);
  list_init(&deb_backend.list);

  msg(LOG_INFO, "Loading debdb backend");

  enum modstatdb_rw status = msdbrw_readonly;
  status = modstatdb_open(msdbrw_readonly);
  if (status != msdbrw_readonly) {
    msg(LOG_ERR, "Could not open database for reading. Status %d", status);
    return 1;
  }

  return 0;
}

static int deb_destroy_backend() {
  dpkg_program_done();
  list_empty(&deb_backend.list);
  modstatdb_shutdown();
  return 0;
}
