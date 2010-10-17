/* Copyright (C) 2010 G.P. Halkes
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 3, as
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>
#include <map>
#include "ucm2cct.h"

typedef struct full_state_t full_state_t;

typedef struct {
	full_state_t *next_state;
	action_t action;
} full_entry_t;

struct full_state_t {
	full_state_t *prev, *next; // Doubly linked list
	full_state_t *linked_from;
	full_entry_t entries[256];
	int flags;
	int count;
	int cost;
};

typedef struct {
	const State *state;
	full_state_t *full_state;
} state_pair_t;

static int calculate_state_cost(full_state_t *state);

static map<pair<full_state_t *, full_state_t *>, int> costs;

static full_state_t *allocate_new_state(full_state_t **head, full_state_t **tail, const vector<State *> &states, int idx) {
	bool calculate_cost = true;
	full_state_t *current;
	size_t i;
	int j;

	if ((current = (full_state_t *) calloc(1, sizeof(full_state_t))) == NULL)
		OOM();

	/* Set pointers correctly for systems which use non-zero NULL ptr. */
	for (i = 0; i < 256; i++)
		current->entries[i].next_state = NULL;
	current->next = NULL;
	current->count = 1;

	if (*head == NULL) {
		*head = *tail = current;
		current->prev = NULL;
	} else {
		(*tail)->next = current;
		current->prev = (*tail);
		*tail = current;
	}

	for (i = 0; i < states[idx]->entries.size(); i++) {
		for (j = states[idx]->entries[i].low; j <= states[idx]->entries[i].high; j++) {
			switch (states[idx]->entries[i].action) {
				case ACTION_VALID:
					current->entries[j].action = ACTION_VALID;
					current->entries[j].next_state = allocate_new_state(head, tail, states, states[idx]->entries[i].next_state);
					current->entries[j].next_state->linked_from = current;
					calculate_cost = false;
					break;
				case ACTION_FINAL:
				case ACTION_FINAL_PAIR:
				case ACTION_UNASSIGNED:
					current->entries[j].action = ACTION_UNASSIGNED;
					/* This is a bit of a hack: we store the pointers to the original states
					   rather than the actual state-tree state. Because we never follow
					   this pointer, this doesn't cause problems. However, this does mean we
					   have to do some extra stuff later on. */
					current->entries[j].next_state = (full_state_t *) states[states[idx]->entries[i].next_state];
					break;
				case ACTION_SHIFT:
				case ACTION_ILLEGAL:
					// See note on previous entry.
					current->entries[j].next_state = (full_state_t *) states[states[idx]->entries[i].next_state];
					current->entries[j].action = states[idx]->entries[i].action;
					break;
				default:
					PANIC();
			}
		}
	}

	current->cost = calculate_cost;

	return current;
}

static void mark_entry(full_state_t *start, unsigned char *bytes, int length, bool pair) {
	switch (start->entries[*bytes].action) {
		case ACTION_VALID:
			if (length == 1)
				PANIC();
			mark_entry(start->entries[*bytes].next_state, bytes + 1, length - 1, pair);
			return;
		case ACTION_UNASSIGNED:
		case ACTION_FINAL:
			start->entries[*bytes].action = pair ? ACTION_FINAL_PAIR : ACTION_FINAL;
			return;
		case ACTION_FINAL_PAIR:
			return;
		default:
			PANIC();
	}
}

static int count_states(full_state_t *ptr) {
	int states = 0;
	for (; ptr != NULL; ptr = ptr->next)
		states++;
	return states;
}

static bool can_merge(full_state_t *a, full_state_t *b) {
	int i;

	if ((a->flags & State::INITIAL) || (b->flags & State::INITIAL))
		return false;

	for (i = 0; i < 256; i++) {
		switch (a->entries[i].action) {
			case ACTION_SHIFT:
				if (a->entries[i].next_state != b->entries[i].next_state)
					return false;
			case ACTION_ILLEGAL:
				if (a->entries[i].action != b->entries[i].action)
					return false;
				if (a->entries[i].next_state != b->entries[i].next_state)
					return false;
				break;
			case ACTION_FINAL_PAIR:
			case ACTION_FINAL:
			case ACTION_UNASSIGNED:
				switch (b->entries[i].action) {
					case ACTION_FINAL_PAIR:
					case ACTION_FINAL:
					case ACTION_UNASSIGNED:
						if (a->entries[i].next_state != b->entries[i].next_state)
							return false;
						break;
					default:
						return false;
				}
				break;
			case ACTION_VALID:
				return false;
			default:
				PANIC();
		}
	}
	return true;
}

static int calculate_state_cost(full_state_t *state) {
	action_t last_action = (action_t) -1;
	int i, cost;

	cost = 256; //FIXME: chose: either calculate in memory costs, or on disk cost, but not something inbetween!!!

	for (i = 0; i < 256; i++) {
		if (last_action != state->entries[i].action)
			cost += 4;
		switch (state->entries[i].action) {
			case ACTION_ILLEGAL:
			case ACTION_SHIFT:
			case ACTION_UNASSIGNED:
				break;
			case ACTION_FINAL_PAIR:
				cost += state->count * 6;
				break;
			case ACTION_FINAL:
				cost += state->count * 3;
				break;
			default:
				PANIC();
		}
		last_action = state->entries[i].action;
	}
	return cost;
}

static int calculate_merge_cost(full_state_t *a, full_state_t *b) {
	full_state_t tmp_state;
	int i;

	memcpy(&tmp_state, a, sizeof(full_state_t));
	tmp_state.count += b->count;

	for (i = 0; i < 256; i++) {
		switch (a->entries[i].action) {
			case ACTION_ILLEGAL:
			case ACTION_SHIFT:
			case ACTION_FINAL_PAIR:
				break;
			case ACTION_FINAL:
				if (b->entries[i].action == ACTION_FINAL_PAIR)
					tmp_state.entries[i].action = ACTION_FINAL_PAIR;
				break;
			case ACTION_UNASSIGNED:
				tmp_state.entries[i].action = b->entries[i].action;
				break;
			default:
				PANIC();
		}
	}
	return calculate_state_cost(&tmp_state) - (a->cost + b->cost);
}

static int find_best_merge(full_state_t *merge[2]) {
/*	full_state_t *ptr;
	int merge_cost, best_merge_cost = INT_MAX;

	for (; head != NULL; head = head->next) {
		for (ptr = head->next; ptr != NULL; ptr = ptr->next) {
			if (!can_merge(head, ptr))
				continue;

			merge_cost = calculate_merge_cost(head, ptr);
			if (merge_cost < best_merge_cost) {
				best_merge_cost = merge_cost;
				merge[0] = head;
				merge[1] = ptr;
			}
		}
	}
	return best_merge_cost;*/

	int best_merge_cost = INT_MAX;
	for (map<pair<full_state_t *, full_state_t *>, int>::iterator iter = costs.begin();
			iter != costs.end(); iter++)
	{
		if (iter->second < best_merge_cost) {
			merge[0] = iter->first.first;
			merge[1] = iter->first.second;
			best_merge_cost = iter->second;
		}
	}
	return best_merge_cost;
}

static void merge_states(full_state_t **tail, full_state_t *left, full_state_t *right) {
	full_state_t *ptr;
	int i;

	if (right->next == NULL) {
		*tail = right->prev;
		(*tail)->next = NULL;
	} else {
		right->prev->next = right->next;
		right->next->prev = right->prev;
	}
	right->next = right->prev = NULL;

	for (i = 0; i < 256; i++) {
		switch (left->entries[i].action) {
			case ACTION_ILLEGAL:
			case ACTION_SHIFT:
				break;
			case ACTION_FINAL_PAIR:
			case ACTION_FINAL:
				if (right->entries[i].action == ACTION_FINAL_PAIR)
					left->entries[i].action = ACTION_FINAL_PAIR;
				break;
			case ACTION_UNASSIGNED:
				if (right->entries[i].action == ACTION_FINAL)
					left->entries[i].action = ACTION_FINAL;
				if (right->entries[i].action == ACTION_FINAL_PAIR)
					left->entries[i].action = ACTION_FINAL_PAIR;
				break;
			case ACTION_VALID:
				break;
			default:
				PANIC();
		}
	}

	if (right->count == 1) {
		for (i = 0; i < 256; i++)
			if (right->linked_from->entries[i].next_state == right)
				right->linked_from->entries[i].next_state = left;
	} else {
		for (ptr = *tail; ptr != NULL; ptr = ptr->prev) {
			for (i = 0; i < 256; i++)
				if (ptr->entries[i].next_state == right)
					ptr->entries[i].next_state = left;
		}
	}

	left->count += right->count;

	if (left->cost > 0)
		left->cost = calculate_state_cost(left);

	free(right);
}

static void merge_duplicate_states(full_state_t *head, full_state_t **tail) {
	full_state_t *ptr;

	for (; head != NULL; head = head->next) {
		for (ptr = head->next; ptr != NULL; ptr = ptr->next) {
			if (memcmp(head->entries, ptr->entries, sizeof(full_entry_t) * 256) != 0)
				continue;

			ptr = ptr->prev;
			merge_states(tail, head, ptr->next);
		}
	}
}

static void fill_map(full_state_t *head) {
	full_state_t *ptr;

	costs.clear();
	for (; head != NULL; head = head->next) {
		for (ptr = head->next; ptr != NULL; ptr = ptr->next) {
			if (!can_merge(head, ptr))
				continue;

			costs.insert(pair<pair<full_state_t *, full_state_t*>, int>(pair<full_state_t *, full_state_t *>(head, ptr), calculate_merge_cost(head, ptr)));
		}
	}
}

void minimize_state_machine(StateMachineInfo *info, int flags) {
	const vector<State *> &states = info->get_state_machine();
	vector<State *> new_states;
	full_state_t *head = NULL, *tail = NULL, *ptr;
	state_pair_t initial_states[16];
	full_state_t *serialized_states[256];
	size_t i, j, nr_serialized_states = 0, last, nr_initial_states;
	int nr_states;

	uint8_t bytes[31];
	size_t length;
	bool is_pair;
	int state;


	if (option_verbose)
		fprintf(stderr, "Minimizing state machine\n");

	/*
		- take state machine description from ucm and convert to full_XXX_t
		   representation. [for from utf-8, use a standard state machine]
		- mark all unused entries as such based on the information in the ucm file
		- perform clustering algorithm until at most 256 states remain, then
		   continuing until further state reductions increase memory usage
		- discard the original state machine and replace with new minimized version
		   [for from utf-8 there is no original state machine]
	*/

	for (i = 0; i < 16; i++) {
		initial_states[i].state = NULL;
		initial_states[i].full_state = NULL;
	}

	// Create state table tree
	nr_serialized_states = 0;
	for (i = 0; i < states.size(); i++) {
		if (states[i]->flags & State::INITIAL) {
			initial_states[nr_serialized_states].state = states[i];
			initial_states[nr_serialized_states].full_state = allocate_new_state(&head, &tail, states, i);
			initial_states[nr_serialized_states].full_state->flags = State::INITIAL;
			serialized_states[nr_serialized_states] = initial_states[nr_serialized_states].full_state;
			nr_serialized_states++;
		}
	}
	nr_initial_states = nr_serialized_states;

	// Mark all used entries
	while (info->get_next_byteseq(bytes, length, is_pair)) {
		state = (flags & Ucm::MULTIBYTE_START_STATE_1) && length > 1 ? 1 : 0;
		mark_entry(initial_states[state].full_state, bytes, length, is_pair);
	}

	// Merge duplicate states using a fast algorithm
	merge_duplicate_states(head, &tail);
	nr_states = count_states(head);

	fprintf(stderr, "calculating costs\n");

	// Calculate cached costs for all states for which it makes sense
	for (ptr = head; ptr != NULL; ptr = ptr->next)
		if (ptr->cost)
			ptr->cost = calculate_state_cost(ptr);
	fprintf(stderr, "filling map\n");
	fill_map(head);

	while (1) {
		if (option_verbose)
			fprintf(stderr, "\rStates remaining: %d ", nr_states);
		full_state_t *merge[2];
		int cost = find_best_merge(merge);
		if (nr_states <= 256 && cost > 0)
			break;

		for (ptr = head; ptr != merge[1]; ptr = ptr->next)
			costs.erase(pair<full_state_t *, full_state_t *>(ptr, merge[1]));

		for (ptr = ptr->next; ptr != NULL; ptr = ptr->next)
			costs.erase(pair<full_state_t *, full_state_t *>(merge[1], ptr));

		merge_states(&tail, merge[0], merge[1]);

		for (ptr = head; ptr != merge[0]; ptr = ptr->next) {
			if (costs.erase(pair<full_state_t *, full_state_t *>(ptr, merge[0])))
				costs.insert(pair<pair<full_state_t *, full_state_t*>, int>(pair<full_state_t *, full_state_t *>(ptr, merge[0]), calculate_merge_cost(ptr, merge[0])));
		}

		for (ptr = ptr->next; ptr != NULL; ptr = ptr->next) {
			if (costs.erase(pair<full_state_t *, full_state_t *>(merge[0], ptr)))
				costs.insert(pair<pair<full_state_t *, full_state_t*>, int>(pair<full_state_t *, full_state_t *>(merge[0], ptr), calculate_merge_cost(merge[0], ptr)));
		}

		nr_states = count_states(head);
	}
	merge_duplicate_states(head, &tail);
	fputc('\n', stderr);

	// Put all states in an array
	for (ptr = head; ptr != NULL; ptr = ptr->next) {
		if (ptr->flags & State::INITIAL)
			continue;

		serialized_states[nr_serialized_states++] = ptr;
	}

	// Convert pointers to full_state_t to indices
	for (ptr = head; ptr != NULL; ptr = ptr->next) {
		for (i = 0; i < 256; i++) {
			if (ptr->entries[i].action == ACTION_VALID) {
				for (j = 0; j < nr_serialized_states; j++) {
					if (ptr->entries[i].next_state == serialized_states[j]) {
						ptr->entries[i].next_state = (full_state_t *) (intptr_t) j;
						break;
					}
				}
			} else {
				for (j = 0; j < nr_initial_states; j++) {
					if (ptr->entries[i].next_state == (full_state_t *) initial_states[j].state) {
						ptr->entries[i].next_state = (full_state_t *) (intptr_t) j;
						break;
					}
				}
			}
		}
	}

	for (i = 0; i < nr_serialized_states; i++) {
		new_states.push_back(new State());
		if (serialized_states[i]->flags & State::INITIAL)
			new_states.back()->flags |= State::INITIAL;

		last = 0;
		for (j = 1; j < 256; j++) {
			if (serialized_states[i]->entries[j].action == serialized_states[i]->entries[j - 1].action &&
					serialized_states[i]->entries[j].next_state == serialized_states[i]->entries[j - 1].next_state)
				continue;

			new_states.back()->new_entry(Entry(last, j - 1, (int) (intptr_t) serialized_states[i]->entries[last].next_state,
				serialized_states[i]->entries[last].action, 0, 0, 0));
			last = j;
		}
		new_states.back()->new_entry(Entry(last, j - 1, (int) (intptr_t) serialized_states[i]->entries[last].next_state,
			serialized_states[i]->entries[last].action, 0, 0, 0));
	}

	info->replace_state_machine(new_states);

	/* Free allocated memory */
	for (ptr = head; ptr != NULL; ptr = head) {
		head = head->next;
		free(ptr);
	}
}

