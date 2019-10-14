#ifndef AVL_HEADER
#define AVL_HEADER

/* Maximum AVL tree height. */
#ifndef AVL_MAX_HEIGHT
#define AVL_MAX_HEIGHT 92
#endif

/* Data structures */

/* One element of the AVL tree */
typedef struct avl {
    struct avl *avl_link[2];  /* Subtrees. */
    signed char avl_balance;       /* Balance factor. */
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
avl *avl_insert(avl_tree *t, avl *a);

/* Remove an element a from the AVL tree t
 * returns a pointer to the removed element
 * or NULL if an element equal to a is not found
 * (equal as returned by t->compar())
 */
avl *avl_remove(avl_tree *t, avl *a);

/* Find the element into the tree that equal to a
 * (equal as returned by t->compar())
 * returns NULL is no element is equal to a
 */
avl *avl_search(avl_tree *t, avl *a);

/* Initialize the avl_tree_lock
 */
void avl_init(avl_tree *t, int (*compar)(void *a, void *b));


int avl_traverse(avl_tree *t, int (*callback)(void *entry, void *data), void *data);

#endif /* avl.h */
