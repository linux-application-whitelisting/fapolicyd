#ifndef AVL_HEADER
#define AVL_HEADER

#include "gcc-attributes.h"

/* Maximum AVL tree height. */
#ifndef AVL_MAX_HEIGHT
#define AVL_MAX_HEIGHT 92
#endif

/* Data structures */

/* One element of the AVL tree */
typedef struct avl {
    struct avl *avl_link[2];  /* Subtrees. */
    signed char avl_balance;  /* Balance factor. */
} avl;

/* An AVL tree */
typedef struct avl_tree {
    avl *root;
    int (*compar)(void *a, void *b);
} avl_tree;


/* Public methods */

/* Insert element a into the AVL tree t
 * returns the added element a, or a pointer the
 * element that is equal to a (as returned by t->compar())
 * a is linked directly to the tree, so it has to
 * be properly allocated by the caller.
 */
avl *avl_insert(avl_tree *t, avl *a) NEVERNULL WARNUNUSED;

/* Remove an element a from the AVL tree t
 * returns a pointer to the removed element
 * or NULL if an element equal to a is not found
 * (equal as returned by t->compar())
 */
avl *avl_remove(avl_tree *t, avl *a) WARNUNUSED;

/* Find the element into the tree that equal to a
 * (equal as returned by t->compar())
 * returns NULL is no element is equal to a
 */
avl *avl_search(avl_tree *t, avl *a);

/* Initialize the avl_tree_lock
 */
void avl_init(avl_tree *t, int (*compar)(void *a, void *b));

/* Walk the tree and call callback at each node
 */
int avl_traverse(avl_tree *t, int (*callback)(void *entry, void *data),
		 void *data);

/* Walk the tree down to the first node and return it
 */
avl *avl_first(avl_tree *t);

/* Given two trees, see if any in needle are contained in haystack
 */
int avl_intersection(avl_tree *needle, avl_tree *haystack);

#endif /* avl.h */
