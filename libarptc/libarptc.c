/* Library which manipulates firewall rules.  Version 0.1. */

/* Architecture of firewall rules is as follows:
 *
 * Chains go INPUT, FORWARD, OUTPUT then user chains.
 * Each user chain starts with an ERROR node.
 * Every chain ends with an unconditional jump: a RETURN for user chains,
 * and a POLICY for built-ins.
 */

/* (C)1999 Paul ``Rusty'' Russell - Placed under the GNU GPL (See
   COPYING for details). */

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#ifdef DEBUG_CONNTRACK
#define inline
#endif


#include "libarptc/libarptc.h"

#define IP_VERSION	4
#define IP_OFFSET	0x1FFF

#define STRUCT_ENTRY_TARGET	struct arpt_entry_target
#define STRUCT_ENTRY		struct arpt_entry
#define STRUCT_ENTRY_MATCH	struct arpt_entry_match
#define STRUCT_GETINFO		struct arpt_getinfo
#define STRUCT_GET_ENTRIES	struct arpt_get_entries
#define STRUCT_COUNTERS		struct arpt_counters
#define STRUCT_COUNTERS_INFO	struct arpt_counters_info
#define STRUCT_STANDARD_TARGET	struct arpt_standard_target
#define STRUCT_REPLACE		struct arpt_replace

#define STRUCT_TC_HANDLE	struct arptc_handle
#define TC_HANDLE_T		arptc_handle_t

#define ENTRY_ITERATE		ARPT_ENTRY_ITERATE
#define TABLE_MAXNAMELEN	ARPT_TABLE_MAXNAMELEN
#define FUNCTION_MAXNAMELEN	ARPT_FUNCTION_MAXNAMELEN

#define GET_TARGET		arpt_get_target

#define ERROR_TARGET		ARPT_ERROR_TARGET

#define ARPT_CHAINLABEL		arpt_chainlabel

#define TC_DUMP_ENTRIES		dump_entries
#define TC_IS_CHAIN		arptc_is_chain
#define TC_FIRST_CHAIN		arptc_first_chain
#define TC_NEXT_CHAIN		arptc_next_chain
#define TC_FIRST_RULE		arptc_first_rule
#define TC_NEXT_RULE		arptc_next_rule
#define TC_GET_TARGET		arptc_get_target
#define TC_BUILTIN		arptc_builtin
#define TC_GET_POLICY		arptc_get_policy
#define TC_INSERT_ENTRY		arptc_insert_entry
#define TC_REPLACE_ENTRY	arptc_replace_entry
#define TC_APPEND_ENTRY		arptc_append_entry
#define TC_DELETE_ENTRY		arptc_delete_entry
#define TC_DELETE_NUM_ENTRY	arptc_delete_num_entry
#define TC_CHECK_PACKET		arptc_check_packet
#define TC_FLUSH_ENTRIES	arptc_flush_entries
#define TC_ZERO_ENTRIES		arptc_zero_entries
#define TC_READ_COUNTER		arptc_read_counter
#define TC_ZERO_COUNTER		arptc_zero_counter
#define TC_SET_COUNTER		arptc_set_counter
#define TC_CREATE_CHAIN		arptc_create_chain
#define TC_GET_REFERENCES	arptc_get_references
#define TC_DELETE_CHAIN		arptc_delete_chain
#define TC_RENAME_CHAIN		arptc_rename_chain
#define TC_SET_POLICY		arptc_set_policy
#define TC_GET_RAW_SOCKET	arptc_get_raw_socket
#define TC_INIT			arptc_init
#define TC_COMMIT		arptc_commit
#define TC_STRERROR		arptc_strerror

#define TC_AF			AF_INET
#define TC_IPPROTO		IPPROTO_IP

#define SO_SET_REPLACE		ARPT_SO_SET_REPLACE
#define SO_SET_ADD_COUNTERS	ARPT_SO_SET_ADD_COUNTERS
#define SO_GET_INFO		ARPT_SO_GET_INFO
#define SO_GET_ENTRIES		ARPT_SO_GET_ENTRIES
#define SO_GET_VERSION		ARPT_SO_GET_VERSION

#define STANDARD_TARGET		ARPT_STANDARD_TARGET
#define LABEL_RETURN		ARPTC_LABEL_RETURN
#define LABEL_ACCEPT		ARPTC_LABEL_ACCEPT
#define LABEL_DROP		ARPTC_LABEL_DROP
#define LABEL_QUEUE		ARPTC_LABEL_QUEUE

#define ALIGN			ARPT_ALIGN
#define RETURN			ARPT_RETURN

//#include "libarptc_incl.c"

/* Library which manipulates firewall rules.  Version $Revision: 1.7 $ */

/* Architecture of firewall rules is as follows:
 *
 * Chains go INPUT, FORWARD, OUTPUT then user chains.
 * Each user chain starts with an ERROR node.
 * Every chain ends with an unconditional jump: a RETURN for user chains,
 * and a POLICY for built-ins.
 */

/* (C)1999 Paul ``Rusty'' Russell - Placed under the GNU GPL (See
   COPYING for details). */

#ifndef __OPTIMIZE__
STRUCT_ENTRY_TARGET *
GET_TARGET(STRUCT_ENTRY *e)
{
	return (void *)e + e->target_offset;
}
#endif

static int sockfd = -1;
static void *arptc_fn = NULL;

static const char *hooknames[] =
{
	[NF_ARP_IN]		"INPUT",
	[NF_ARP_OUT]		"OUTPUT",
	[NF_ARP_FORWARD]	"FORWARD",
};

struct counter_map
{
	enum {
		COUNTER_MAP_NOMAP,
		COUNTER_MAP_NORMAL_MAP,
		COUNTER_MAP_ZEROED,
		COUNTER_MAP_SET
	} maptype;
	unsigned int mappos;
};

/* Convenience structures */
struct arpt_error_target
{
	STRUCT_ENTRY_TARGET t;
	char error[TABLE_MAXNAMELEN];
};

struct chain_cache
{
	char name[TABLE_MAXNAMELEN];
	/* This is the first rule in chain. */
	STRUCT_ENTRY *start;
	/* Last rule in chain */
	STRUCT_ENTRY *end;
};

STRUCT_TC_HANDLE
{
	/* Have changes been made? */
	int changed;
	/* Size in here reflects original state. */
	STRUCT_GETINFO info;

	struct counter_map *counter_map;
	/* Array of hook names */
	const char **hooknames;

	/* Cached position of chain heads (NULL = no cache). */
	unsigned int cache_num_chains;
	unsigned int cache_num_builtins;
	struct chain_cache *cache_chain_heads;

	/* Chain iterator: current chain cache entry. */
	struct chain_cache *cache_chain_iteration;

	/* Rule iterator: terminal rule */
	STRUCT_ENTRY *cache_rule_end;

	/* Number in here reflects current state. */
	unsigned int new_number;
	STRUCT_GET_ENTRIES entries;
};

static void
set_changed(TC_HANDLE_T h)
{
	if (h->cache_chain_heads) {
		free(h->cache_chain_heads);
		h->cache_chain_heads = NULL;
		h->cache_num_chains = 0;
		h->cache_chain_iteration = NULL;
		h->cache_rule_end = NULL;
	}
	h->changed = 1;
}

#ifdef ARPTC_DEBUG
static void do_check(TC_HANDLE_T h, unsigned int line);
#define CHECK(h) do { if (!getenv("ARPTC_NO_CHECK")) do_check((h), __LINE__); } while(0)
#else
#define CHECK(h)
#endif

static inline int
get_number(const STRUCT_ENTRY *i,
	   const STRUCT_ENTRY *seek,
	   unsigned int *pos)
{
	if (i == seek)
		return 1;
	(*pos)++;
	return 0;
}

static unsigned int
entry2index(const TC_HANDLE_T h, const STRUCT_ENTRY *seek)
{
	unsigned int pos = 0;

	if (ENTRY_ITERATE(h->entries.entrytable, h->entries.size,
			  get_number, seek, &pos) == 0) {
		fprintf(stderr, "ERROR: offset %zu not an entry!\n",
			(char *)seek - (char *)h->entries.entrytable);
		abort();
	}
	return pos;
}

static inline int
get_entry_n(STRUCT_ENTRY *i,
	    unsigned int number,
	    unsigned int *pos,
	    STRUCT_ENTRY **pe)
{
	if (*pos == number) {
		*pe = i;
		return 1;
	}
	(*pos)++;
	return 0;
}

static STRUCT_ENTRY *
index2entry(TC_HANDLE_T h, unsigned int index)
{
	unsigned int pos = 0;
	STRUCT_ENTRY *ret = NULL;

	ENTRY_ITERATE(h->entries.entrytable, h->entries.size,
		      get_entry_n, index, &pos, &ret);

	return ret;
}

static inline STRUCT_ENTRY *
get_entry(TC_HANDLE_T h, unsigned int offset)
{
	return (STRUCT_ENTRY *)((char *)h->entries.entrytable + offset);
}

static inline unsigned long
entry2offset(const TC_HANDLE_T h, const STRUCT_ENTRY *e)
{
	return (char *)e - (char *)h->entries.entrytable;
}

static unsigned long
index2offset(TC_HANDLE_T h, unsigned int index)
{
	return entry2offset(h, index2entry(h, index));
}

static const char *
get_errorlabel(TC_HANDLE_T h, unsigned int offset)
{
	STRUCT_ENTRY *e;

	e = get_entry(h, offset);
	if (strcmp(GET_TARGET(e)->u.user.name, ERROR_TARGET) != 0) {
		fprintf(stderr, "ERROR: offset %u not an error node!\n",
			offset);
		abort();
	}

	return (const char *)GET_TARGET(e)->data;
}

/* Allocate handle of given size */
static TC_HANDLE_T
alloc_handle(const char *tablename, unsigned int size, unsigned int num_rules)
{
	size_t len;
	TC_HANDLE_T h;

	len = sizeof(STRUCT_TC_HANDLE)
		+ size
		+ num_rules * sizeof(struct counter_map);

	if ((h = malloc(len)) == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	h->changed = 0;
	h->cache_num_chains = 0;
	h->cache_chain_heads = NULL;
	h->counter_map = (void *)h
		+ sizeof(STRUCT_TC_HANDLE)
		+ size;
	strcpy(h->info.name, tablename);
	strcpy(h->entries.name, tablename);

	return h;
}

TC_HANDLE_T
TC_INIT(const char *tablename)
{
	TC_HANDLE_T h;
	STRUCT_GETINFO info;
	unsigned int i;
	socklen_t s, tmp;

	arptc_fn = TC_INIT;

	if (sockfd != -1)
		close(sockfd);

	sockfd = socket(TC_AF, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0)
		return NULL;

	s = sizeof(info);
	if (RUNTIME_NF_ARP_NUMHOOKS == 2)
		s -= 2 * sizeof(unsigned int);

	if (strlen(tablename) >= TABLE_MAXNAMELEN) {
		errno = EINVAL;
		return NULL;
	}
	strcpy(info.name, tablename);
	if (getsockopt(sockfd, TC_IPPROTO, SO_GET_INFO, &info, &s) < 0)
		return NULL;

	if (RUNTIME_NF_ARP_NUMHOOKS == 2) {
		memmove(&(info.hook_entry[3]), &(info.hook_entry[2]),
		5 * sizeof(unsigned int));
		memmove(&(info.underflow[3]), &(info.underflow[2]),
		2 * sizeof(unsigned int));
	}

	if ((h = alloc_handle(info.name, info.size, info.num_entries))
	    == NULL)
		return NULL;

/* Too hard --RR */
#if 0
	sprintf(pathname, "%s/%s", ARPT_LIB_DIR, info.name);
	dynlib = dlopen(pathname, RTLD_NOW);
	if (!dynlib) {
		errno = ENOENT;
		return NULL;
	}
	h->hooknames = dlsym(dynlib, "hooknames");
	if (!h->hooknames) {
		errno = ENOENT;
		return NULL;
	}
#else
	h->hooknames = hooknames;
#endif

	/* Initialize current state */
	h->info = info;
	h->new_number = h->info.num_entries;
	for (i = 0; i < h->info.num_entries; i++)
		h->counter_map[i]
			= ((struct counter_map){COUNTER_MAP_NORMAL_MAP, i});

	h->entries.size = h->info.size;

	tmp = sizeof(STRUCT_GET_ENTRIES) + h->info.size;

	if (getsockopt(sockfd, TC_IPPROTO, SO_GET_ENTRIES, &h->entries,
		       &tmp) < 0) {
		free(h);
		return NULL;
	}

	CHECK(h);
	return h;
}

/*
static inline int
print_match(const STRUCT_ENTRY_MATCH *m)
{
	printf("Match name: `%s'\n", m->u.user.name);
	return 0;
}
*/

static int dump_entry(STRUCT_ENTRY *e, const TC_HANDLE_T handle);

void
TC_DUMP_ENTRIES(const TC_HANDLE_T handle)
{
	CHECK(handle);

	printf("libarptc v%s.  %u entries, %u bytes.\n",
	       ARPTABLES_VERSION,
	       handle->new_number, handle->entries.size);
	printf("Table `%s'\n", handle->info.name);
	printf("Hooks: in/out = %u/%u\n",
	       handle->info.hook_entry[NF_ARP_IN],
	       handle->info.hook_entry[NF_ARP_OUT]);
	printf("Underflows: in/out = %u/%u\n",
	       handle->info.underflow[NF_ARP_IN],
	       handle->info.underflow[NF_ARP_OUT]);

	ENTRY_ITERATE(handle->entries.entrytable, handle->entries.size,
		      dump_entry, handle);
}

/* Returns 0 if not hook entry, else hooknumber + 1 */
static inline unsigned int
is_hook_entry(STRUCT_ENTRY *e, TC_HANDLE_T h)
{
	unsigned int i;

	for (i = 0; i < RUNTIME_NF_ARP_NUMHOOKS; i++) {
		if ((h->info.valid_hooks & (1 << i))
		    && get_entry(h, h->info.hook_entry[i]) == e)
			return i+1;
	}
	return 0;
}

static inline int
add_chain(STRUCT_ENTRY *e, TC_HANDLE_T h, STRUCT_ENTRY **prev)
{
	unsigned int builtin;

	/* Last entry.  End it. */
	if (entry2offset(h, e) + e->next_offset == h->entries.size) {
		/* This is the ERROR node at end of the table */
		h->cache_chain_heads[h->cache_num_chains-1].end = *prev;
		return 0;
	}

	/* We know this is the start of a new chain if it's an ERROR
	   target, or a hook entry point */
	if (strcmp(GET_TARGET(e)->u.user.name, ERROR_TARGET) == 0) {
		/* prev was last entry in previous chain */
		h->cache_chain_heads[h->cache_num_chains-1].end
			= *prev;

		strcpy(h->cache_chain_heads[h->cache_num_chains].name,
		       (const char *)GET_TARGET(e)->data);
		h->cache_chain_heads[h->cache_num_chains].start
			= (void *)e + e->next_offset;
		h->cache_num_chains++;
	} else if ((builtin = is_hook_entry(e, h)) != 0) {
		if (h->cache_num_chains > 0)
			/* prev was last entry in previous chain */
			h->cache_chain_heads[h->cache_num_chains-1].end
				= *prev;

		strcpy(h->cache_chain_heads[h->cache_num_chains].name,
		       h->hooknames[builtin-1]);
		h->cache_chain_heads[h->cache_num_chains].start
			= (void *)e;
		h->cache_num_chains++;
	}

	*prev = e;
	return 0;
}

static int alphasort(const void *a, const void *b)
{
	return strcmp(((struct chain_cache *)a)->name,
		      ((struct chain_cache *)b)->name);
}

static int populate_cache(TC_HANDLE_T h)
{
	unsigned int i;
	STRUCT_ENTRY *prev;

	/* # chains < # rules / 2 + num builtins - 1 */
	h->cache_chain_heads = malloc((h->new_number / 2 + 4)
				      * sizeof(struct chain_cache));
	if (!h->cache_chain_heads) {
		errno = ENOMEM;
		return 0;
	}

	h->cache_num_chains = 0;
	h->cache_num_builtins = 0;

	/* Count builtins */
	for (i = 0; i < RUNTIME_NF_ARP_NUMHOOKS; i++) {
		if (h->info.valid_hooks & (1 << i))
			h->cache_num_builtins++;
	}

	prev = NULL;
	ENTRY_ITERATE(h->entries.entrytable, h->entries.size,
		      add_chain, h, &prev);

	qsort(h->cache_chain_heads + h->cache_num_builtins,
	      h->cache_num_chains - h->cache_num_builtins,
	      sizeof(struct chain_cache), alphasort);

	return 1;
}

/* Returns cache ptr if found, otherwise NULL. */
static struct chain_cache *
find_label(const char *name, TC_HANDLE_T handle)
{
	unsigned int i;

	if (handle->cache_chain_heads == NULL
	    && !populate_cache(handle))
		return NULL;

	/* FIXME: Linear search through builtins, then binary --RR */
	for (i = 0; i < handle->cache_num_chains; i++) {
		if (strcmp(handle->cache_chain_heads[i].name, name) == 0)
			return &handle->cache_chain_heads[i];
	}

	return NULL;
}

/* Does this chain exist? */
int TC_IS_CHAIN(const char *chain, const TC_HANDLE_T handle)
{
	return find_label(chain, handle) != NULL;
}

/* Returns the position of the final (ie. unconditional) element. */
static unsigned int
get_chain_end(const TC_HANDLE_T handle, unsigned int start)
{
	unsigned int last_off, off;
	STRUCT_ENTRY *e;

	last_off = start;
	e = get_entry(handle, start);

	/* Terminate when we meet a error label or a hook entry. */
	for (off = start + e->next_offset;
	     off < handle->entries.size;
	     last_off = off, off += e->next_offset) {
		STRUCT_ENTRY_TARGET *t;
		unsigned int i;

		e = get_entry(handle, off);

		/* We hit an entry point. */
		for (i = 0; i < RUNTIME_NF_ARP_NUMHOOKS; i++) {
			if ((handle->info.valid_hooks & (1 << i))
			    && off == handle->info.hook_entry[i])
				return last_off;
		}

		/* We hit a user chain label */
		t = GET_TARGET(e);
		if (strcmp(t->u.user.name, ERROR_TARGET) == 0)
			return last_off;
	}
	/* SHOULD NEVER HAPPEN */
	fprintf(stderr, "ERROR: Off end (%u) of chain from %u!\n",
		handle->entries.size, off);
	abort();
}

/* Iterator functions to run through the chains. */
const char *
TC_FIRST_CHAIN(TC_HANDLE_T *handle)
{
	if ((*handle)->cache_chain_heads == NULL
	    && !populate_cache(*handle))
		return NULL;

	(*handle)->cache_chain_iteration
		= &(*handle)->cache_chain_heads[0];

	return (*handle)->cache_chain_iteration->name;
}

/* Iterator functions to run through the chains.  Returns NULL at end. */
const char *
TC_NEXT_CHAIN(TC_HANDLE_T *handle)
{
	(*handle)->cache_chain_iteration++;

	if ((*handle)->cache_chain_iteration - (*handle)->cache_chain_heads
	    == (*handle)->cache_num_chains)
		return NULL;

	return (*handle)->cache_chain_iteration->name;
}

/* Get first rule in the given chain: NULL for empty chain. */
const STRUCT_ENTRY *
TC_FIRST_RULE(const char *chain, TC_HANDLE_T *handle)
{
	struct chain_cache *c;

	c = find_label(chain, *handle);
	if (!c) {
		errno = ENOENT;
		return NULL;
	}

	/* Empty chain: single return/policy rule */
	if (c->start == c->end)
		return NULL;

	(*handle)->cache_rule_end = c->end;
	return c->start;
}

/* Returns NULL when rules run out. */
const STRUCT_ENTRY *
TC_NEXT_RULE(const STRUCT_ENTRY *prev, TC_HANDLE_T *handle)
{
	if ((void *)prev + prev->next_offset
	    == (void *)(*handle)->cache_rule_end)
		return NULL;

	return (void *)prev + prev->next_offset;
}

#if 0
/* How many rules in this chain? */
unsigned int
TC_NUM_RULES(const char *chain, TC_HANDLE_T *handle)
{
	unsigned int off = 0;
	STRUCT_ENTRY *start, *end;

	CHECK(*handle);
	if (!find_label(&off, chain, *handle)) {
		errno = ENOENT;
		return (unsigned int)-1;
	}

	start = get_entry(*handle, off);
	end = get_entry(*handle, get_chain_end(*handle, off));

	return entry2index(*handle, end) - entry2index(*handle, start);
}

/* Get n'th rule in this chain. */
const STRUCT_ENTRY *TC_GET_RULE(const char *chain,
				unsigned int n,
				TC_HANDLE_T *handle)
{
	unsigned int pos = 0, chainindex;

	CHECK(*handle);
	if (!find_label(&pos, chain, *handle)) {
		errno = ENOENT;
		return NULL;
	}

	chainindex = entry2index(*handle, get_entry(*handle, pos));

	return index2entry(*handle, chainindex + n);
}
#endif

static const char *
target_name(TC_HANDLE_T handle, const STRUCT_ENTRY *ce)
{
	int spos;
	const unsigned char *data;
	unsigned int labelidx;
	STRUCT_ENTRY *jumpto;

	/* To avoid const warnings */
	STRUCT_ENTRY *e = (STRUCT_ENTRY *)ce;

	if (strcmp(GET_TARGET(e)->u.user.name, STANDARD_TARGET) != 0)
		return GET_TARGET(e)->u.user.name;

	/* Standard target: evaluate */
	data = GET_TARGET(e)->data;
	spos = *(const int *)data;
	if (spos < 0) {
		if (spos == RETURN)
			return LABEL_RETURN;
		else if (spos == -NF_ACCEPT-1)
			return LABEL_ACCEPT;
		else if (spos == -NF_DROP-1)
			return LABEL_DROP;
		else if (spos == -NF_QUEUE-1)
			return LABEL_QUEUE;

		fprintf(stderr, "ERROR: off %lu/%u not a valid target (%i)\n",
			entry2offset(handle, e), handle->entries.size,
			spos);
		abort();
	}

	jumpto = get_entry(handle, spos);

	/* Fall through rule */
	if (jumpto == (void *)e + e->next_offset)
		return "";

	/* Must point to head of a chain: ie. after error rule */
	labelidx = entry2index(handle, jumpto) - 1;
	return get_errorlabel(handle, index2offset(handle, labelidx));
}

/* Returns a pointer to the target name of this position. */
const char *TC_GET_TARGET(const STRUCT_ENTRY *e,
			  TC_HANDLE_T *handle)
{
	return target_name(*handle, e);
}

/* Is this a built-in chain?  Actually returns hook + 1. */
int
TC_BUILTIN(const char *chain, const TC_HANDLE_T handle)
{
	unsigned int i;

	for (i = 0; i < RUNTIME_NF_ARP_NUMHOOKS; i++) {
		if ((handle->info.valid_hooks & (1 << i))
		    && handle->hooknames[i]
		    && strcmp(handle->hooknames[i], chain) == 0)
			return i+1;
	}
	return 0;
}

/* Get the policy of a given built-in chain */
const char *
TC_GET_POLICY(const char *chain,
	      STRUCT_COUNTERS *counters,
	      TC_HANDLE_T *handle)
{
	unsigned int start;
	STRUCT_ENTRY *e;
	int hook;

	hook = TC_BUILTIN(chain, *handle);
	if (hook != 0)
		start = (*handle)->info.hook_entry[hook-1];
	else
		return NULL;

	e = get_entry(*handle, get_chain_end(*handle, start));
	*counters = e->counters;

	return target_name(*handle, e);
}

static int
correct_verdict(STRUCT_ENTRY *e,
		char *base,
		unsigned int offset, int delta_offset)
{
	STRUCT_STANDARD_TARGET *t = (void *)GET_TARGET(e);
	unsigned int curr = (char *)e - base;

	/* Trap: insert of fall-through rule.  Don't change fall-through
	   verdict to jump-over-next-rule. */
	if (strcmp(t->target.u.user.name, STANDARD_TARGET) == 0
	    && t->verdict > (int)offset
	    && !(curr == offset &&
		 t->verdict == curr + e->next_offset)) {
		t->verdict += delta_offset;
	}

	return 0;
}

/* Adjusts standard verdict jump positions after an insertion/deletion. */
static int
set_verdict(unsigned int offset, int delta_offset, TC_HANDLE_T *handle)
{
	ENTRY_ITERATE((*handle)->entries.entrytable,
		      (*handle)->entries.size,
		      correct_verdict, (char *)(*handle)->entries.entrytable,
		      offset, delta_offset);

	set_changed(*handle);
	return 1;
}

/* If prepend is set, then we are prepending to a chain: if the
 * insertion position is an entry point, keep the entry point. */
static int
insert_rules(unsigned int num_rules, unsigned int rules_size,
	     const STRUCT_ENTRY *insert,
	     unsigned int offset, unsigned int num_rules_offset,
	     int prepend,
	     TC_HANDLE_T *handle)
{
	TC_HANDLE_T newh;
	STRUCT_GETINFO newinfo;
	unsigned int i;

	if (offset >= (*handle)->entries.size) {
		errno = EINVAL;
		return 0;
	}

	newinfo = (*handle)->info;

	/* Fix up entry points. */
	for (i = 0; i < RUNTIME_NF_ARP_NUMHOOKS; i++) {
		/* Entry points to START of chain, so keep same if
                   inserting on at that point. */
		if ((*handle)->info.hook_entry[i] > offset)
			newinfo.hook_entry[i] += rules_size;

		/* Underflow always points to END of chain (policy),
		   so if something is inserted at same point, it
		   should be advanced. */
		if ((*handle)->info.underflow[i] >= offset)
			newinfo.underflow[i] += rules_size;
	}

	newh = alloc_handle((*handle)->info.name,
			    (*handle)->entries.size + rules_size,
			    (*handle)->new_number + num_rules);
	if (!newh)
		return 0;
	newh->info = newinfo;

	/* Copy pre... */
	memcpy(newh->entries.entrytable, (*handle)->entries.entrytable,offset);
	/* ... Insert new ... */
	memcpy((char *)newh->entries.entrytable + offset, insert, rules_size);
	/* ... copy post */
	memcpy((char *)newh->entries.entrytable + offset + rules_size,
	       (char *)(*handle)->entries.entrytable + offset,
	       (*handle)->entries.size - offset);

	/* Move counter map. */
	/* Copy pre... */
	memcpy(newh->counter_map, (*handle)->counter_map,
	       sizeof(struct counter_map) * num_rules_offset);
	/* ... copy post */
	memcpy(newh->counter_map + num_rules_offset + num_rules,
	       (*handle)->counter_map + num_rules_offset,
	       sizeof(struct counter_map) * ((*handle)->new_number
					     - num_rules_offset));
	/* Set intermediates to no counter copy */
	for (i = 0; i < num_rules; i++)
		newh->counter_map[num_rules_offset+i]
			= ((struct counter_map){ COUNTER_MAP_SET, 0 });

	newh->new_number = (*handle)->new_number + num_rules;
	newh->entries.size = (*handle)->entries.size + rules_size;
	newh->hooknames = (*handle)->hooknames;

	if ((*handle)->cache_chain_heads)
		free((*handle)->cache_chain_heads);
	free(*handle);
	*handle = newh;

	return set_verdict(offset, rules_size, handle);
}

static int
delete_rules(unsigned int num_rules, unsigned int rules_size,
	     unsigned int offset, unsigned int num_rules_offset,
	     TC_HANDLE_T *handle)
{
	unsigned int i;

	if (offset + rules_size > (*handle)->entries.size) {
		errno = EINVAL;
		return 0;
	}

	/* Fix up entry points. */
	for (i = 0; i < RUNTIME_NF_ARP_NUMHOOKS; i++) {
		/* In practice, we never delete up to a hook entry,
		   since the built-in chains are always first,
		   so these two are never equal */
		if ((*handle)->info.hook_entry[i] >= offset + rules_size)
			(*handle)->info.hook_entry[i] -= rules_size;
		else if ((*handle)->info.hook_entry[i] > offset) {
			fprintf(stderr, "ERROR: Deleting entry %u %u %u\n",
				i, (*handle)->info.hook_entry[i], offset);
			abort();
		}

		/* Underflow points to policy (terminal) rule in
                   built-in, so sequality is valid here (when deleting
                   the last rule). */
		if ((*handle)->info.underflow[i] >= offset + rules_size)
			(*handle)->info.underflow[i] -= rules_size;
		else if ((*handle)->info.underflow[i] > offset) {
			fprintf(stderr, "ERROR: Deleting uflow %u %u %u\n",
				i, (*handle)->info.underflow[i], offset);
			abort();
		}
	}

	/* Move the rules down. */
	memmove((char *)(*handle)->entries.entrytable + offset,
		(char *)(*handle)->entries.entrytable + offset + rules_size,
		(*handle)->entries.size - (offset + rules_size));

	/* Move the counter map down. */
	memmove(&(*handle)->counter_map[num_rules_offset],
		&(*handle)->counter_map[num_rules_offset + num_rules],
		sizeof(struct counter_map)
		* ((*handle)->new_number - (num_rules + num_rules_offset)));

	/* Fix numbers */
	(*handle)->new_number -= num_rules;
	(*handle)->entries.size -= rules_size;

	return set_verdict(offset, -(int)rules_size, handle);
}

static int
standard_map(STRUCT_ENTRY *e, int verdict)
{
	STRUCT_STANDARD_TARGET *t;

	t = (STRUCT_STANDARD_TARGET *)GET_TARGET(e);

	if (t->target.u.target_size
	    != ALIGN(sizeof(STRUCT_STANDARD_TARGET))) {
		errno = EINVAL;
		return 0;
	}
	/* memset for memcmp convenience on delete/replace */
	memset(t->target.u.user.name, 0, FUNCTION_MAXNAMELEN);
	strcpy(t->target.u.user.name, STANDARD_TARGET);
	t->verdict = verdict;

	return 1;
}

static int
map_target(const TC_HANDLE_T handle,
	   STRUCT_ENTRY *e,
	   unsigned int offset,
	   STRUCT_ENTRY_TARGET *old)
{
	STRUCT_ENTRY_TARGET *t = GET_TARGET(e);

	/* Save old target (except data, which we don't change, except for
	   standard case, where we don't care). */
	*old = *t;

	/* Maybe it's empty (=> fall through) */
	if (strcmp(t->u.user.name, "") == 0)
		return standard_map(e, offset + e->next_offset);
	/* Maybe it's a standard target name... */
	else if (strcmp(t->u.user.name, LABEL_ACCEPT) == 0)
		return standard_map(e, -NF_ACCEPT - 1);
	else if (strcmp(t->u.user.name, LABEL_DROP) == 0)
		return standard_map(e, -NF_DROP - 1);
	else if (strcmp(t->u.user.name, LABEL_QUEUE) == 0)
		return standard_map(e, -NF_QUEUE - 1);
	else if (strcmp(t->u.user.name, LABEL_RETURN) == 0)
		return standard_map(e, RETURN);
	else if (TC_BUILTIN(t->u.user.name, handle)) {
		/* Can't jump to builtins. */
		errno = EINVAL;
		return 0;
	} else {
		/* Maybe it's an existing chain name. */
		struct chain_cache *c;

		c = find_label(t->u.user.name, handle);
		if (c)
			return standard_map(e, entry2offset(handle, c->start));
	}

	/* Must be a module?  If not, kernel will reject... */
	/* memset to all 0 for your memcmp convenience. */
	memset(t->u.user.name + strlen(t->u.user.name),
	       0,
	       FUNCTION_MAXNAMELEN - strlen(t->u.user.name));
	return 1;
}

static void
unmap_target(STRUCT_ENTRY *e, STRUCT_ENTRY_TARGET *old)
{
	STRUCT_ENTRY_TARGET *t = GET_TARGET(e);

	/* Save old target (except data, which we don't change, except for
	   standard case, where we don't care). */
	*t = *old;
}

/* Insert the entry `fw' in chain `chain' into position `rulenum'. */
int
TC_INSERT_ENTRY(const ARPT_CHAINLABEL chain,
		const STRUCT_ENTRY *e,
		unsigned int rulenum,
		TC_HANDLE_T *handle)
{
	unsigned int chainindex, offset;
	STRUCT_ENTRY_TARGET old;
	struct chain_cache *c;
	STRUCT_ENTRY *tmp;
	int ret;

	arptc_fn = TC_INSERT_ENTRY;
	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	chainindex = entry2index(*handle, c->start);

	tmp = index2entry(*handle, chainindex + rulenum);
	if (!tmp || tmp > c->end) {
		errno = E2BIG;
		return 0;
	}
	offset = index2offset(*handle, chainindex + rulenum);

	/* Mapping target actually alters entry, but that's
           transparent to the caller. */
	if (!map_target(*handle, (STRUCT_ENTRY *)e, offset, &old))
		return 0;

	ret = insert_rules(1, e->next_offset, e, offset,
			   chainindex + rulenum, rulenum == 0, handle);
	unmap_target((STRUCT_ENTRY *)e, &old);
	return ret;
}

/* Atomically replace rule `rulenum' in `chain' with `fw'. */
int
TC_REPLACE_ENTRY(const ARPT_CHAINLABEL chain,
		 const STRUCT_ENTRY *e,
		 unsigned int rulenum,
		 TC_HANDLE_T *handle)
{
	unsigned int chainindex, offset;
	STRUCT_ENTRY_TARGET old;
	struct chain_cache *c;
	STRUCT_ENTRY *tmp;
	int ret;

	arptc_fn = TC_REPLACE_ENTRY;

	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	chainindex = entry2index(*handle, c->start);

	tmp = index2entry(*handle, chainindex + rulenum);
	if (!tmp || tmp >= c->end) {
		errno = E2BIG;
		return 0;
	}

	offset = index2offset(*handle, chainindex + rulenum);
	/* Replace = delete and insert. */
	if (!delete_rules(1, get_entry(*handle, offset)->next_offset,
			  offset, chainindex + rulenum, handle))
		return 0;

	if (!map_target(*handle, (STRUCT_ENTRY *)e, offset, &old))
		return 0;

	ret = insert_rules(1, e->next_offset, e, offset,
			   chainindex + rulenum, 1, handle);
	unmap_target((STRUCT_ENTRY *)e, &old);
	return ret;
}

/* Append entry `fw' to chain `chain'.  Equivalent to insert with
   rulenum = length of chain. */
int
TC_APPEND_ENTRY(const ARPT_CHAINLABEL chain,
		const STRUCT_ENTRY *e,
		TC_HANDLE_T *handle)
{
	struct chain_cache *c;
	STRUCT_ENTRY_TARGET old;
	int ret;

	arptc_fn = TC_APPEND_ENTRY;
	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	if (!map_target(*handle, (STRUCT_ENTRY *)e,
			entry2offset(*handle, c->end), &old))
		return 0;

	ret = insert_rules(1, e->next_offset, e,
			   entry2offset(*handle, c->end),
			   entry2index(*handle, c->end),
			   0, handle);
	unmap_target((STRUCT_ENTRY *)e, &old);
	return ret;
}

/*
static inline int
match_different(const STRUCT_ENTRY_MATCH *a,
		const unsigned char *a_elems,
		const unsigned char *b_elems,
		unsigned char **maskptr)
{
	const STRUCT_ENTRY_MATCH *b;
	unsigned int i;
*/
	/* Offset of b is the same as a. */
/*
	b = (void *)b_elems + ((unsigned char *)a - a_elems);

	if (a->u.match_size != b->u.match_size)
		return 1;

	if (strcmp(a->u.user.name, b->u.user.name) != 0)
		return 1;

	*maskptr += ALIGN(sizeof(*a));

	for (i = 0; i < a->u.match_size - ALIGN(sizeof(*a)); i++)
		if (((a->data[i] ^ b->data[i]) & (*maskptr)[i]) != 0)
			return 1;
	*maskptr += i;
	return 0;
}
*/

static inline int
target_different(const unsigned char *a_targdata,
		 const unsigned char *b_targdata,
		 unsigned int tdatasize,
		 const unsigned char *mask)
{
	unsigned int i;
	for (i = 0; i < tdatasize; i++)
		if (((a_targdata[i] ^ b_targdata[i]) & mask[i]) != 0)
			return 1;

	return 0;
}

static int
is_same(const STRUCT_ENTRY *a,
	const STRUCT_ENTRY *b,
	unsigned char *matchmask);

/* Delete the first rule in `chain' which matches `fw'. */
int
TC_DELETE_ENTRY(const ARPT_CHAINLABEL chain,
		const STRUCT_ENTRY *origfw,
		unsigned char *matchmask,
		TC_HANDLE_T *handle)
{
	unsigned int offset;
	struct chain_cache *c;
	STRUCT_ENTRY *e, *fw;

	arptc_fn = TC_DELETE_ENTRY;
	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	fw = malloc(origfw->next_offset);
	if (fw == NULL) {
		errno = ENOMEM;
		return 0;
	}

	for (offset = entry2offset(*handle, c->start);
	     offset < entry2offset(*handle, c->end);
	     offset += e->next_offset) {
		STRUCT_ENTRY_TARGET discard;

		memcpy(fw, origfw, origfw->next_offset);

		/* FIXME: handle this in is_same --RR */
		if (!map_target(*handle, fw, offset, &discard)) {
			free(fw);
			return 0;
		}
		e = get_entry(*handle, offset);

#if 0
		printf("Deleting:\n");
		dump_entry(newe);
#endif
		if (is_same(e, fw, matchmask)) {
			int ret;
			ret = delete_rules(1, e->next_offset,
					   offset, entry2index(*handle, e),
					   handle);
			free(fw);
			return ret;
		}
	}

	free(fw);
	errno = ENOENT;
	return 0;
}

/* Delete the rule in position `rulenum' in `chain'. */
int
TC_DELETE_NUM_ENTRY(const ARPT_CHAINLABEL chain,
		    unsigned int rulenum,
		    TC_HANDLE_T *handle)
{
	unsigned int index;
	int ret;
	STRUCT_ENTRY *e;
	struct chain_cache *c;

	arptc_fn = TC_DELETE_NUM_ENTRY;
	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	index = entry2index(*handle, c->start) + rulenum;

	if (index >= entry2index(*handle, c->end)) {
		errno = E2BIG;
		return 0;
	}

	e = index2entry(*handle, index);
	if (e == NULL) {
		errno = EINVAL;
		return 0;
	}

	ret = delete_rules(1, e->next_offset, entry2offset(*handle, e),
			   index, handle);
	return ret;
}

/* Check the packet `fw' on chain `chain'.  Returns the verdict, or
   NULL and sets errno. */
const char *
TC_CHECK_PACKET(const ARPT_CHAINLABEL chain,
		STRUCT_ENTRY *entry,
		TC_HANDLE_T *handle)
{
	errno = ENOSYS;
	return NULL;
}

/* Flushes the entries in the given chain (ie. empties chain). */
int
TC_FLUSH_ENTRIES(const ARPT_CHAINLABEL chain, TC_HANDLE_T *handle)
{
	unsigned int startindex, endindex;
	struct chain_cache *c;
	int ret;

	arptc_fn = TC_FLUSH_ENTRIES;
	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}
	startindex = entry2index(*handle, c->start);
	endindex = entry2index(*handle, c->end);

	ret = delete_rules(endindex - startindex,
			   (char *)c->end - (char *)c->start,
			   entry2offset(*handle, c->start), startindex,
			   handle);
	return ret;
}

/* Zeroes the counters in a chain. */
int
TC_ZERO_ENTRIES(const ARPT_CHAINLABEL chain, TC_HANDLE_T *handle)
{
	unsigned int i, end;
	struct chain_cache *c;

	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	i = entry2index(*handle, c->start);
	end = entry2index(*handle, c->end);

	for (; i <= end; i++) {
		if ((*handle)->counter_map[i].maptype ==COUNTER_MAP_NORMAL_MAP)
			(*handle)->counter_map[i].maptype = COUNTER_MAP_ZEROED;
	}
	set_changed(*handle);

	return 1;
}

STRUCT_COUNTERS *
TC_READ_COUNTER(const ARPT_CHAINLABEL chain,
		unsigned int rulenum,
		TC_HANDLE_T *handle)
{
	STRUCT_ENTRY *e;
	struct chain_cache *c;
	unsigned int chainindex, end;

	arptc_fn = TC_READ_COUNTER;
	CHECK(*handle);

	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return NULL;
	}

	chainindex = entry2index(*handle, c->start);
	end = entry2index(*handle, c->end);

	if (chainindex + rulenum > end) {
		errno = E2BIG;
		return NULL;
	}

	e = index2entry(*handle, chainindex + rulenum);

	return &e->counters;
}

int
TC_ZERO_COUNTER(const ARPT_CHAINLABEL chain,
		unsigned int rulenum,
		TC_HANDLE_T *handle)
{
	struct chain_cache *c;
	unsigned int chainindex, end;

	arptc_fn = TC_ZERO_COUNTER;
	CHECK(*handle);

	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	chainindex = entry2index(*handle, c->start);
	end = entry2index(*handle, c->end);

	if (chainindex + rulenum > end) {
		errno = E2BIG;
		return 0;
	}

	if ((*handle)->counter_map[chainindex + rulenum].maptype
			== COUNTER_MAP_NORMAL_MAP) {
		(*handle)->counter_map[chainindex + rulenum].maptype
			 = COUNTER_MAP_ZEROED;
	}

	set_changed(*handle);

	return 1;
}

int
TC_SET_COUNTER(const ARPT_CHAINLABEL chain,
	       unsigned int rulenum,
	       STRUCT_COUNTERS *counters,
	       TC_HANDLE_T *handle)
{
	STRUCT_ENTRY *e;
	struct chain_cache *c;
	unsigned int chainindex, end;

	arptc_fn = TC_SET_COUNTER;
	CHECK(*handle);

	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	chainindex = entry2index(*handle, c->start);
	end = entry2index(*handle, c->end);

	if (chainindex + rulenum > end) {
		errno = E2BIG;
		return 0;
	}

	e = index2entry(*handle, chainindex + rulenum);

	(*handle)->counter_map[chainindex + rulenum].maptype
		= COUNTER_MAP_SET;

	memcpy(&e->counters, counters, sizeof(STRUCT_COUNTERS));

	set_changed(*handle);

	return 1;
}

/* Creates a new chain. */
/* To create a chain, create two rules: error node and unconditional
 * return. */
int
TC_CREATE_CHAIN(const ARPT_CHAINLABEL chain, TC_HANDLE_T *handle)
{
	int ret;
	struct {
		STRUCT_ENTRY head;
		struct arpt_error_target name;
		STRUCT_ENTRY ret;
		STRUCT_STANDARD_TARGET target;
	} newc;

	arptc_fn = TC_CREATE_CHAIN;

	/* find_label doesn't cover built-in targets: DROP, ACCEPT,
           QUEUE, RETURN. */
	if (find_label(chain, *handle)
	    || strcmp(chain, LABEL_DROP) == 0
	    || strcmp(chain, LABEL_ACCEPT) == 0
	    || strcmp(chain, LABEL_QUEUE) == 0
	    || strcmp(chain, LABEL_RETURN) == 0) {
		errno = EEXIST;
		return 0;
	}

	if (strlen(chain)+1 > sizeof(ARPT_CHAINLABEL)) {
		errno = EINVAL;
		return 0;
	}

	memset(&newc, 0, sizeof(newc));
	newc.head.target_offset = sizeof(STRUCT_ENTRY);
	newc.head.next_offset
		= sizeof(STRUCT_ENTRY)
		+ ALIGN(sizeof(struct arpt_error_target));
	strcpy(newc.name.t.u.user.name, ERROR_TARGET);
	newc.name.t.u.target_size = ALIGN(sizeof(struct arpt_error_target));
	strcpy(newc.name.error, chain);

	newc.ret.target_offset = sizeof(STRUCT_ENTRY);
	newc.ret.next_offset
		= sizeof(STRUCT_ENTRY)
		+ ALIGN(sizeof(STRUCT_STANDARD_TARGET));
	strcpy(newc.target.target.u.user.name, STANDARD_TARGET);
	newc.target.target.u.target_size
		= ALIGN(sizeof(STRUCT_STANDARD_TARGET));
	newc.target.verdict = RETURN;

	/* Add just before terminal entry */
	ret = insert_rules(2, sizeof(newc), &newc.head,
			   index2offset(*handle, (*handle)->new_number - 1),
			   (*handle)->new_number - 1,
			   0, handle);
	return ret;
}

static int
count_ref(STRUCT_ENTRY *e, unsigned int offset, unsigned int *ref)
{
	STRUCT_STANDARD_TARGET *t;

	if (strcmp(GET_TARGET(e)->u.user.name, STANDARD_TARGET) == 0) {
		t = (STRUCT_STANDARD_TARGET *)GET_TARGET(e);

		if (t->verdict == offset)
			(*ref)++;
	}

	return 0;
}

/* Get the number of references to this chain. */
int
TC_GET_REFERENCES(unsigned int *ref, const ARPT_CHAINLABEL chain,
		  TC_HANDLE_T *handle)
{
	struct chain_cache *c;

	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	*ref = 0;
	ENTRY_ITERATE((*handle)->entries.entrytable,
		      (*handle)->entries.size,
		      count_ref, entry2offset(*handle, c->start), ref);
	return 1;
}

/* Deletes a chain. */
int
TC_DELETE_CHAIN(const ARPT_CHAINLABEL chain, TC_HANDLE_T *handle)
{
	unsigned int labelidx, labeloff;
	unsigned int references;
	struct chain_cache *c;
	int ret;

	if (!TC_GET_REFERENCES(&references, chain, handle))
		return 0;

	arptc_fn = TC_DELETE_CHAIN;

	if (TC_BUILTIN(chain, *handle)) {
		errno = EINVAL;
		return 0;
	}

	if (references > 0) {
		errno = EMLINK;
		return 0;
	}

	if (!(c = find_label(chain, *handle))) {
		errno = ENOENT;
		return 0;
	}

	if ((void *)c->start != c->end) {
		errno = ENOTEMPTY;
		return 0;
	}

	/* Need label index: preceeds chain start */
	labelidx = entry2index(*handle, c->start) - 1;
	labeloff = index2offset(*handle, labelidx);

	ret = delete_rules(2,
			   get_entry(*handle, labeloff)->next_offset
			   + c->start->next_offset,
			   labeloff, labelidx, handle);
	return ret;
}

/* Renames a chain. */
int TC_RENAME_CHAIN(const ARPT_CHAINLABEL oldname,
		    const ARPT_CHAINLABEL newname,
		    TC_HANDLE_T *handle)
{
	unsigned int labeloff, labelidx;
	struct chain_cache *c;
	struct arpt_error_target *t;

	arptc_fn = TC_RENAME_CHAIN;

	/* find_label doesn't cover built-in targets: DROP, ACCEPT,
           QUEUE, RETURN. */
	if (find_label(newname, *handle)
	    || strcmp(newname, LABEL_DROP) == 0
	    || strcmp(newname, LABEL_ACCEPT) == 0
	    || strcmp(newname, LABEL_QUEUE) == 0
	    || strcmp(newname, LABEL_RETURN) == 0) {
		errno = EEXIST;
		return 0;
	}

	if (!(c = find_label(oldname, *handle))
	    || TC_BUILTIN(oldname, *handle)) {
		errno = ENOENT;
		return 0;
	}

	if (strlen(newname)+1 > sizeof(ARPT_CHAINLABEL)) {
		errno = EINVAL;
		return 0;
	}

	/* Need label index: preceeds chain start */
	labelidx = entry2index(*handle, c->start) - 1;
	labeloff = index2offset(*handle, labelidx);

	t = (struct arpt_error_target *)
		GET_TARGET(get_entry(*handle, labeloff));

	memset(t->error, 0, sizeof(t->error));
	strcpy(t->error, newname);
	set_changed(*handle);

	return 1;
}

/* Sets the policy on a built-in chain. */
int
TC_SET_POLICY(const ARPT_CHAINLABEL chain,
	      const ARPT_CHAINLABEL policy,
	      STRUCT_COUNTERS *counters,
	      TC_HANDLE_T *handle)
{
	unsigned int hook;
	unsigned int policyoff, ctrindex;
	STRUCT_ENTRY *e;
	STRUCT_STANDARD_TARGET *t;

	arptc_fn = TC_SET_POLICY;
	/* Figure out which chain. */
	hook = TC_BUILTIN(chain, *handle);
	if (hook == 0) {
		errno = ENOENT;
		return 0;
	} else
		hook--;

	policyoff = get_chain_end(*handle, (*handle)->info.hook_entry[hook]);
	if (policyoff != (*handle)->info.underflow[hook]) {
		printf("ERROR: Policy for `%s' offset %u != underflow %u\n",
		       chain, policyoff, (*handle)->info.underflow[hook]);
		return 0;
	}

	e = get_entry(*handle, policyoff);
	t = (STRUCT_STANDARD_TARGET *)GET_TARGET(e);

	if (strcmp(policy, LABEL_ACCEPT) == 0)
		t->verdict = -NF_ACCEPT - 1;
	else if (strcmp(policy, LABEL_DROP) == 0)
		t->verdict = -NF_DROP - 1;
	else {
		errno = EINVAL;
		return 0;
	}

	ctrindex = entry2index(*handle, e);

	if (counters) {
		/* set byte and packet counters */
		memcpy(&e->counters, counters, sizeof(STRUCT_COUNTERS));

		(*handle)->counter_map[ctrindex].maptype
			= COUNTER_MAP_SET;

	} else {
		(*handle)->counter_map[ctrindex]
			= ((struct counter_map){ COUNTER_MAP_NOMAP, 0 });
	}

	set_changed(*handle);

	return 1;
}

/* Without this, on gcc 2.7.2.3, we get:
   libarptc.c: In function `TC_COMMIT':
   libarptc.c:833: fixed or forbidden register was spilled.
   This may be due to a compiler bug or to impossible asm
   statements or clauses.
*/
static void
subtract_counters(STRUCT_COUNTERS *answer,
		  const STRUCT_COUNTERS *a,
		  const STRUCT_COUNTERS *b)
{
	answer->pcnt = a->pcnt - b->pcnt;
	answer->bcnt = a->bcnt - b->bcnt;
}

int
TC_COMMIT(TC_HANDLE_T *handle)
{
	/* Replace, then map back the counters. */
	STRUCT_REPLACE *repl;
	STRUCT_COUNTERS_INFO *newcounters;
	unsigned int i;
	size_t counterlen
		= sizeof(STRUCT_COUNTERS_INFO)
		+ sizeof(STRUCT_COUNTERS) * (*handle)->new_number;
	int sizeof_repl = sizeof(*repl);

	CHECK(*handle);
#if 0
	TC_DUMP_ENTRIES(*handle);
#endif

	/* Don't commit if nothing changed. */
	if (!(*handle)->changed)
		goto finished;

	/* allocate a bit more than needed for ease */
	repl = malloc(2 * sizeof(*repl) + (*handle)->entries.size);
	if (!repl) {
		errno = ENOMEM;
		return 0;
	}

	/* These are the old counters we will get from kernel */
	repl->counters = malloc(sizeof(STRUCT_COUNTERS)
				* (*handle)->info.num_entries);
	if (!repl->counters) {
		free(repl);
		errno = ENOMEM;
		return 0;
	}

	/* These are the counters we're going to put back, later. */
	newcounters = malloc(counterlen);
	if (!newcounters) {
		free(repl->counters);
		free(repl);
		errno = ENOMEM;
		return 0;
	}

	strcpy(repl->name, (*handle)->info.name);
	repl->num_entries = (*handle)->new_number;
	repl->size = (*handle)->entries.size;
	memcpy(repl->hook_entry, (*handle)->info.hook_entry,
	       sizeof(repl->hook_entry));
	memcpy(repl->underflow, (*handle)->info.underflow,
	       sizeof(repl->underflow));
	repl->num_counters = (*handle)->info.num_entries;
	repl->valid_hooks = (*handle)->info.valid_hooks;
	memcpy(repl->entries, (*handle)->entries.entrytable,
	       (*handle)->entries.size);

	if (RUNTIME_NF_ARP_NUMHOOKS == 2) {
		memmove(&(repl->underflow[2]), &(repl->underflow[3]),
		((*handle)->entries.size) + sizeof(struct arpt_replace));
		memmove(&(repl->hook_entry[2]), &(repl->hook_entry[3]),
		((*handle)->entries.size) + sizeof(struct arpt_replace));
		sizeof_repl -= 2 * sizeof(unsigned int);
	}

	if (setsockopt(sockfd, TC_IPPROTO, SO_SET_REPLACE, repl,
		       sizeof_repl + (*handle)->entries.size) < 0) {
		free(repl->counters);
		free(repl);
		free(newcounters);
		return 0;
	}

	if (RUNTIME_NF_ARP_NUMHOOKS == 2) {
		memmove(&(repl->hook_entry[3]), &(repl->hook_entry[2]),
		((*handle)->entries.size) + sizeof(struct arpt_replace));
		memmove(&(repl->underflow[3]), &(repl->underflow[2]),
		((*handle)->entries.size) + sizeof(struct arpt_replace));
	}

	/* Put counters back. */
	strcpy(newcounters->name, (*handle)->info.name);
	newcounters->num_counters = (*handle)->new_number;
	for (i = 0; i < (*handle)->new_number; i++) {
		unsigned int mappos = (*handle)->counter_map[i].mappos;
		switch ((*handle)->counter_map[i].maptype) {
		case COUNTER_MAP_NOMAP:
			newcounters->counters[i]
				= ((STRUCT_COUNTERS){ 0, 0 });
			break;

		case COUNTER_MAP_NORMAL_MAP:
			/* Original read: X.
			 * Atomic read on replacement: X + Y.
			 * Currently in kernel: Z.
			 * Want in kernel: X + Y + Z.
			 * => Add in X + Y
			 * => Add in replacement read.
			 */
			newcounters->counters[i] = repl->counters[mappos];
			break;

		case COUNTER_MAP_ZEROED:
			/* Original read: X.
			 * Atomic read on replacement: X + Y.
			 * Currently in kernel: Z.
			 * Want in kernel: Y + Z.
			 * => Add in Y.
			 * => Add in (replacement read - original read).
			 */
			subtract_counters(&newcounters->counters[i],
					  &repl->counters[mappos],
					  &index2entry(*handle, i)->counters);
			break;

		case COUNTER_MAP_SET:
			/* Want to set counter (iptables-restore) */

			memcpy(&newcounters->counters[i],
			       &index2entry(*handle, i)->counters,
			       sizeof(STRUCT_COUNTERS));

			break;
		}
	}

#ifdef KERNEL_64_USERSPACE_32
	{
		/* Kernel will think that pointer should be 64-bits, and get
		   padding.  So we accomodate here (assumption: alignment of
		   `counters' is on 64-bit boundary). */
		u_int64_t *kernptr = (u_int64_t *)&newcounters->counters;
		if ((unsigned long)&newcounters->counters % 8 != 0) {
			fprintf(stderr,
				"counters alignment incorrect! Mail rusty!\n");
			abort();
		}
		*kernptr = newcounters->counters;
	}
#endif /* KERNEL_64_USERSPACE_32 */

	if (setsockopt(sockfd, TC_IPPROTO, SO_SET_ADD_COUNTERS,
		       newcounters, counterlen) < 0) {
		free(repl->counters);
		free(repl);
		free(newcounters);
		return 0;
	}

	free(repl->counters);
	free(repl);
	free(newcounters);

 finished:
	if ((*handle)->cache_chain_heads)
		free((*handle)->cache_chain_heads);
	free(*handle);
	*handle = NULL;
	return 1;
}

/* Get raw socket. */
int
TC_GET_RAW_SOCKET()
{
	return sockfd;
}

/* Translates errno numbers into more human-readable form than strerror. */
const char *
TC_STRERROR(int err)
{
	unsigned int i;
	struct table_struct {
		void *fn;
		int err;
		const char *message;
	} table [] =
	  { { TC_INIT, EPERM, "Permission denied (you must be root)" },
	    { TC_INIT, EINVAL, "Module is wrong version" },
	    { TC_INIT, ENOENT,
		    "Table does not exist (do you need to insmod?)" },
	    { TC_DELETE_CHAIN, ENOTEMPTY, "Chain is not empty" },
	    { TC_DELETE_CHAIN, EINVAL, "Can't delete built-in chain" },
	    { TC_DELETE_CHAIN, EMLINK,
	      "Can't delete chain with references left" },
	    { TC_CREATE_CHAIN, EEXIST, "Chain already exists" },
	    { TC_INSERT_ENTRY, E2BIG, "Index of insertion too big" },
	    { TC_REPLACE_ENTRY, E2BIG, "Index of replacement too big" },
	    { TC_DELETE_NUM_ENTRY, E2BIG, "Index of deletion too big" },
	    { TC_READ_COUNTER, E2BIG, "Index of counter too big" },
	    { TC_ZERO_COUNTER, E2BIG, "Index of counter too big" },
	    { TC_INSERT_ENTRY, ELOOP, "Loop found in table" },
	    { TC_INSERT_ENTRY, EINVAL, "Target problem" },
	    /* EINVAL for CHECK probably means bad interface. */
	    { TC_CHECK_PACKET, EINVAL,
	      "Bad arguments (does that interface exist?)" },
	    { TC_CHECK_PACKET, ENOSYS,
	      "Checking will most likely never get implemented" },
	    /* ENOENT for DELETE probably means no matching rule */
	    { TC_DELETE_ENTRY, ENOENT,
	      "Bad rule (does a matching rule exist in that chain?)" },
	    { TC_SET_POLICY, ENOENT,
	      "Bad built-in chain name" },
	    { TC_SET_POLICY, EINVAL,
	      "Bad policy name" },

	    { NULL, 0, "Incompatible with this kernel" },
	    { NULL, ENOPROTOOPT, "arptables who? (do you need to insmod?)" },
	    { NULL, ENOSYS, "Will be implemented real soon.  I promise ;)" },
	    { NULL, ENOMEM, "Memory allocation problem" },
	    { NULL, ENOENT, "No chain/target/match by that name" },
	  };

	for (i = 0; i < sizeof(table)/sizeof(struct table_struct); i++) {
		if ((!table[i].fn || table[i].fn == arptc_fn)
		    && table[i].err == err)
			return table[i].message;
	}

	return strerror(err);
}


#define IP_PARTS_NATIVE(n)			\
(unsigned int)((n)>>24)&0xFF,			\
(unsigned int)((n)>>16)&0xFF,			\
(unsigned int)((n)>>8)&0xFF,			\
(unsigned int)((n)&0xFF)

#define IP_PARTS(n) IP_PARTS_NATIVE(ntohl(n))

int
dump_entry(STRUCT_ENTRY *e, const TC_HANDLE_T handle)
{
	size_t i;
	STRUCT_ENTRY_TARGET *t;

	printf("Entry %u (%lu):\n", entry2index(handle, e),
	       entry2offset(handle, e));
	printf("SRC IP: %u.%u.%u.%u/%u.%u.%u.%u\n",
	       IP_PARTS(e->arp.src.s_addr),IP_PARTS(e->arp.smsk.s_addr));
	printf("DST IP: %u.%u.%u.%u/%u.%u.%u.%u\n",
	       IP_PARTS(e->arp.tgt.s_addr),IP_PARTS(e->arp.tmsk.s_addr));
	printf("Interface: `%s'/", e->arp.iniface);
	for (i = 0; i < IFNAMSIZ; i++)
		printf("%c", e->arp.iniface_mask[i] ? 'X' : '.');
	printf("to `%s'/", e->arp.outiface);
	for (i = 0; i < IFNAMSIZ; i++)
		printf("%c", e->arp.outiface_mask[i] ? 'X' : '.');
	printf("Flags: %02X\n", e->arp.flags);
	printf("Invflags: %02X\n", e->arp.invflags);
	printf("Counters: %"PRIu64" packets, %"PRIu64" bytes\n",
	       e->counters.pcnt, e->counters.bcnt);
/*
	printf("Cache: %08X ", e->nfcache);
	if (e->nfcache & NFC_ALTERED) printf("ALTERED ");
	if (e->nfcache & NFC_UNKNOWN) printf("UNKNOWN ");
	if (e->nfcache & NFC_IP_SRC) printf("IP_SRC ");
	if (e->nfcache & NFC_IP_DST) printf("IP_DST ");
	if (e->nfcache & NFC_IP_IF_IN) printf("IP_IF_IN ");
	if (e->nfcache & NFC_IP_IF_OUT) printf("IP_IF_OUT ");
	if (e->nfcache & NFC_IP_TOS) printf("IP_TOS ");
	if (e->nfcache & NFC_IP_PROTO) printf("IP_PROTO ");
	if (e->nfcache & NFC_IP_OPTIONS) printf("IP_OPTIONS ");
	if (e->nfcache & NFC_IP_TCPFLAGS) printf("IP_TCPFLAGS ");
	if (e->nfcache & NFC_IP_SRC_PT) printf("IP_SRC_PT ");
	if (e->nfcache & NFC_IP_DST_PT) printf("IP_DST_PT ");
	if (e->nfcache & NFC_IP_PROTO_UNKNOWN) printf("IP_PROTO_UNKNOWN ");
*/
	printf("\n");

/*
	ARPT_MATCH_ITERATE(e, print_match);
*/

	t = GET_TARGET(e);
	printf("Target name: `%s' [%u]\n", t->u.user.name, t->u.target_size);
	if (strcmp(t->u.user.name, STANDARD_TARGET) == 0) {
		const unsigned char *data = t->data;
		const int pos = *(const int *)data;
		if (pos < 0)
			printf("verdict=%s\n",
			       pos == -NF_ACCEPT-1 ? "NF_ACCEPT"
			       : pos == -NF_DROP-1 ? "NF_DROP"
			       : pos == -NF_QUEUE-1 ? "NF_QUEUE"
			       : pos == RETURN ? "RETURN"
			       : "UNKNOWN");
		else
			printf("verdict=%u\n", pos);
	} else if (strcmp(t->u.user.name, ARPT_ERROR_TARGET) == 0)
		printf("error=`%s'\n", t->data);

	printf("\n");
	return 0;
}

static int
is_same(const STRUCT_ENTRY *a, const STRUCT_ENTRY *b, unsigned char *matchmask)
{
	unsigned int i;
	STRUCT_ENTRY_TARGET *ta, *tb;
	unsigned char *mptr;

	/* Always compare head structures: ignore mask here. */
	if (a->arp.src.s_addr != b->arp.src.s_addr
	    || a->arp.tgt.s_addr != b->arp.tgt.s_addr
	    || a->arp.smsk.s_addr != b->arp.smsk.s_addr
	    || a->arp.tmsk.s_addr != b->arp.tmsk.s_addr
	    || a->arp.arhln != b->arp.arhln
	    || a->arp.arhln_mask != b->arp.arhln_mask
	    || a->arp.arpop != b->arp.arpop
	    || a->arp.arpop_mask != b->arp.arpop_mask
	    || a->arp.arhrd != b->arp.arhrd
	    || a->arp.arhrd_mask != b->arp.arhrd_mask
	    || a->arp.arpro != b->arp.arpro
	    || a->arp.arpro_mask != b->arp.arpro_mask
	    || a->arp.flags != b->arp.flags
	    || a->arp.invflags != b->arp.invflags)
		return 0;

	for (i = 0; i < ARPT_DEV_ADDR_LEN_MAX; i++) {
		if (a->arp.src_devaddr.addr[i] != b->arp.src_devaddr.addr[i] ||
		    a->arp.src_devaddr.mask[i] != b->arp.src_devaddr.mask[i])
			return 0;
		if (a->arp.tgt_devaddr.addr[i] != b->arp.tgt_devaddr.addr[i] ||
		    a->arp.tgt_devaddr.mask[i] != b->arp.tgt_devaddr.mask[i])
			return 0;
	}

	for (i = 0; i < IFNAMSIZ; i++) {
		if (a->arp.iniface_mask[i] != b->arp.iniface_mask[i])
			return 0;
		if ((a->arp.iniface[i] & a->arp.iniface_mask[i])
		    != (b->arp.iniface[i] & b->arp.iniface_mask[i]))
			return 0;
		if (a->arp.outiface_mask[i] != b->arp.outiface_mask[i])
			return 0;
		if ((a->arp.outiface[i] & a->arp.outiface_mask[i])
		    != (b->arp.outiface[i] & b->arp.outiface_mask[i]))
			return 0;
	}

	if (/* a->nfcache != b->nfcache
	    || */a->target_offset != b->target_offset
	    || a->next_offset != b->next_offset)
		return 0;

	mptr = matchmask + sizeof(STRUCT_ENTRY);
/*
	if (ARPT_MATCH_ITERATE(a, match_different, a->elems, b->elems, &mptr))
		return 0;
*/

	ta = GET_TARGET((STRUCT_ENTRY *)a);
	tb = GET_TARGET((STRUCT_ENTRY *)b);
	if (ta->u.target_size != tb->u.target_size)
		return 0;
	if (strcmp(ta->u.user.name, tb->u.user.name) != 0)
		return 0;

	mptr += sizeof(*ta);
	if (target_different(ta->data, tb->data,
			     ta->u.target_size - sizeof(*ta), mptr))
		return 0;

   	return 1;
}

/***************************** DEBUGGING ********************************/
static inline int
unconditional(const struct arpt_arp *arp)
{
	unsigned int i;

	for (i = 0; i < sizeof(*arp)/sizeof(u_int32_t); i++)
		if (((u_int32_t *)arp)[i])
			return 0;

	return 1;
}

/*
static inline int
check_match(const STRUCT_ENTRY_MATCH *m, unsigned int *off)
{
	assert(m->u.match_size >= sizeof(STRUCT_ENTRY_MATCH));
	assert(ALIGN(m->u.match_size) == m->u.match_size);

	(*off) += m->u.match_size;
	return 0;
}
*/

static inline int
check_entry(const STRUCT_ENTRY *e, unsigned int *i, unsigned int *off,
	    unsigned int user_offset, int *was_return,
	    TC_HANDLE_T h)
{
	unsigned int toff;
	STRUCT_STANDARD_TARGET *t;

	assert(e->target_offset >= sizeof(STRUCT_ENTRY));
	assert(e->next_offset >= e->target_offset
	       + sizeof(STRUCT_ENTRY_TARGET));
	toff = sizeof(STRUCT_ENTRY);
/*
	ARPT_MATCH_ITERATE(e, check_match, &toff);
*/

	assert(toff == e->target_offset);

	t = (STRUCT_STANDARD_TARGET *)
		GET_TARGET((STRUCT_ENTRY *)e);
	/* next_offset will have to be multiple of entry alignment. */
	assert(e->next_offset == ALIGN(e->next_offset));
	assert(e->target_offset == ALIGN(e->target_offset));
	assert(t->target.u.target_size == ALIGN(t->target.u.target_size));
	assert(!TC_IS_CHAIN(t->target.u.user.name, h));

	if (strcmp(t->target.u.user.name, STANDARD_TARGET) == 0) {
		assert(t->target.u.target_size
		       == ALIGN(sizeof(STRUCT_STANDARD_TARGET)));

		assert(t->verdict == -NF_DROP-1
		       || t->verdict == -NF_ACCEPT-1
		       || t->verdict == RETURN
		       || t->verdict < (int)h->entries.size);

		if (t->verdict >= 0) {
			STRUCT_ENTRY *te = get_entry(h, t->verdict);
			int idx;

			idx = entry2index(h, te);
			assert(strcmp(GET_TARGET(te)->u.user.name,
				      ARPT_ERROR_TARGET)
			       != 0);
			assert(te != e);

			/* Prior node must be error node, or this node. */
			assert(t->verdict == entry2offset(h, e)+e->next_offset
			       || strcmp(GET_TARGET(index2entry(h, idx-1))
					 ->u.user.name, ARPT_ERROR_TARGET)
			       == 0);
		}

		if (t->verdict == RETURN
		    && unconditional(&e->arp)
		    && e->target_offset == sizeof(*e))
			*was_return = 1;
		else
			*was_return = 0;
	} else if (strcmp(t->target.u.user.name, ARPT_ERROR_TARGET) == 0) {
		assert(t->target.u.target_size
		       == ALIGN(sizeof(struct arpt_error_target)));

		/* If this is in user area, previous must have been return */
		if (*off > user_offset)
			assert(*was_return);

		*was_return = 0;
	}
	else *was_return = 0;

	if (*off == user_offset)
		assert(strcmp(t->target.u.user.name, ARPT_ERROR_TARGET) == 0);

	(*off) += e->next_offset;
	(*i)++;
	return 0;
}

#ifdef ARPTC_DEBUG
/* Do every conceivable sanity check on the handle */
static void
do_check(TC_HANDLE_T h, unsigned int line)
{
	unsigned int i, n;
	unsigned int user_offset; /* Offset of first user chain */
	int was_return;

	assert(h->changed == 0 || h->changed == 1);
	if (strcmp(h->info.name, "filter") == 0) {
		assert(h->info.valid_hooks
		       == (1 << NF_IP_LOCAL_IN
			   | 1 << NF_IP_FORWARD
			   | 1 << NF_IP_LOCAL_OUT));

		/* Hooks should be first three */
		assert(h->info.hook_entry[NF_IP_LOCAL_IN] == 0);

		n = get_chain_end(h, 0);
		n += get_entry(h, n)->next_offset;
		assert(h->info.hook_entry[NF_IP_FORWARD] == n);

		n = get_chain_end(h, n);
		n += get_entry(h, n)->next_offset;
		assert(h->info.hook_entry[NF_IP_LOCAL_OUT] == n);

		user_offset = h->info.hook_entry[NF_IP_LOCAL_OUT];
	} else if (strcmp(h->info.name, "nat") == 0) {
		assert((h->info.valid_hooks
		        == (1 << NF_IP_PRE_ROUTING
			    | 1 << NF_IP_POST_ROUTING
			    | 1 << NF_IP_LOCAL_OUT)) ||
		       (h->info.valid_hooks
			== (1 << NF_IP_PRE_ROUTING
			    | 1 << NF_IP_LOCAL_IN
			    | 1 << NF_IP_POST_ROUTING
			    | 1 << NF_IP_LOCAL_OUT)));

		assert(h->info.hook_entry[NF_IP_PRE_ROUTING] == 0);

		n = get_chain_end(h, 0);

		n += get_entry(h, n)->next_offset;
		assert(h->info.hook_entry[NF_IP_POST_ROUTING] == n);
		n = get_chain_end(h, n);

		n += get_entry(h, n)->next_offset;
		assert(h->info.hook_entry[NF_IP_LOCAL_OUT] == n);
		user_offset = h->info.hook_entry[NF_IP_LOCAL_OUT];

		if (h->info.valid_hooks & (1 << NF_IP_LOCAL_IN)) {
			n = get_chain_end(h, n);
			n += get_entry(h, n)->next_offset;
			assert(h->info.hook_entry[NF_IP_LOCAL_IN] == n);
			user_offset = h->info.hook_entry[NF_IP_LOCAL_IN];
		}

	} else if (strcmp(h->info.name, "mangle") == 0) {
		/* This code is getting ugly because linux < 2.4.18-pre6 had
		 * two mangle hooks, linux >= 2.4.18-pre6 has five mangle hooks
		 * */
		assert((h->info.valid_hooks
			== (1 << NF_IP_PRE_ROUTING
			    | 1 << NF_IP_LOCAL_OUT)) || 
		       (h->info.valid_hooks
			== (1 << NF_IP_PRE_ROUTING
			    | 1 << NF_IP_LOCAL_IN
			    | 1 << NF_IP_FORWARD
			    | 1 << NF_IP_LOCAL_OUT
			    | 1 << NF_IP_POST_ROUTING)));

		/* Hooks should be first five */
		assert(h->info.hook_entry[NF_IP_PRE_ROUTING] == 0);

		n = get_chain_end(h, 0);

		if (h->info.valid_hooks & (1 << NF_IP_LOCAL_IN)) {
			n += get_entry(h, n)->next_offset;
			assert(h->info.hook_entry[NF_IP_LOCAL_IN] == n);
			n = get_chain_end(h, n);
		}

		if (h->info.valid_hooks & (1 << NF_IP_FORWARD)) {
			n += get_entry(h, n)->next_offset;
			assert(h->info.hook_entry[NF_IP_FORWARD] == n);
			n = get_chain_end(h, n);
		}

		n += get_entry(h, n)->next_offset;
		assert(h->info.hook_entry[NF_IP_LOCAL_OUT] == n);
		user_offset = h->info.hook_entry[NF_IP_LOCAL_OUT];

		if (h->info.valid_hooks & (1 << NF_IP_POST_ROUTING)) {
			n = get_chain_end(h, n);
			n += get_entry(h, n)->next_offset;
			assert(h->info.hook_entry[NF_IP_POST_ROUTING] == n);
			user_offset = h->info.hook_entry[NF_IP_POST_ROUTING];
		}

#ifdef NF_IP_DROPPING
	} else if (strcmp(h->info.name, "drop") == 0) {
		assert(h->info.valid_hooks == (1 << NF_IP_DROPPING));

		/* Hook should be first */
		assert(h->info.hook_entry[NF_IP_DROPPING] == 0);
		user_offset = 0;
#endif
	} else {
		fprintf(stderr, "Unknown table `%s'\n", h->info.name);
		abort();
	}

	/* User chain == end of last builtin + policy entry */
	user_offset = get_chain_end(h, user_offset);
	user_offset += get_entry(h, user_offset)->next_offset;

	/* Overflows should be end of entry chains, and unconditional
           policy nodes. */
	for (i = 0; i < RUNTIME_NF_ARP_NUMHOOKS; i++) {
		STRUCT_ENTRY *e;
		STRUCT_STANDARD_TARGET *t;

		if (!(h->info.valid_hooks & (1 << i)))
			continue;
		assert(h->info.underflow[i]
		       == get_chain_end(h, h->info.hook_entry[i]));

		e = get_entry(h, get_chain_end(h, h->info.hook_entry[i]));
		assert(unconditional(&e->ip));
		assert(e->target_offset == sizeof(*e));
		t = (STRUCT_STANDARD_TARGET *)GET_TARGET(e);
		assert(t->target.u.target_size == ALIGN(sizeof(*t)));
		assert(e->next_offset == sizeof(*e) + ALIGN(sizeof(*t)));

		assert(strcmp(t->target.u.user.name, STANDARD_TARGET)==0);
		assert(t->verdict == -NF_DROP-1 || t->verdict == -NF_ACCEPT-1);

		/* Hooks and underflows must be valid entries */
		entry2index(h, get_entry(h, h->info.hook_entry[i]));
		entry2index(h, get_entry(h, h->info.underflow[i]));
	}

	assert(h->info.size
	       >= h->info.num_entries * (sizeof(STRUCT_ENTRY)
					 +sizeof(STRUCT_STANDARD_TARGET)));

	assert(h->entries.size
	       >= (h->new_number
		   * (sizeof(STRUCT_ENTRY)
		      + sizeof(STRUCT_STANDARD_TARGET))));
	assert(strcmp(h->info.name, h->entries.name) == 0);

	i = 0; n = 0;
	was_return = 0;
	/* Check all the entries. */
	ENTRY_ITERATE(h->entries.entrytable, h->entries.size,
		      check_entry, &i, &n, user_offset, &was_return, h);

	assert(i == h->new_number);
	assert(n == h->entries.size);

	/* Final entry must be error node */
	assert(strcmp(GET_TARGET(index2entry(h, h->new_number-1))
		      ->u.user.name,
		      ERROR_TARGET) == 0);
}
#endif /*ARPTC_DEBUG*/
