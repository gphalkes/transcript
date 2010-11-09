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
#include <list>
#include "ucm2cct.h"

struct full_state_t;

struct full_entry_t {
	full_state_t *next_state;
	action_t action;
};

struct full_state_t {
	full_state_t *prev, *next; // Doubly linked list
	full_state_t *linked_from;
	full_entry_t entries[256];
	int flags;
	int count;
	int cost;
};

struct state_pair_t {
	const State *state;
	full_state_t *full_state;
};

struct merge_cost_t {
	full_state_t *left, *right;
	int cost;
};

static int calculate_state_cost(full_state_t *state, Ucm::StateMachineInfo *info);

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

static void mark_entry(full_state_t *start, unsigned char *bytes, int length, bool pair, bool has_flags) {
	switch (start->entries[*bytes].action) {
		case ACTION_VALID:
			if (length == 1)
				PANIC();
			mark_entry(start->entries[*bytes].next_state, bytes + 1, length - 1, pair, has_flags);
			return;
		case ACTION_FINAL_NOFLAGS:
		case ACTION_UNASSIGNED:
			if (has_flags)
				start->entries[*bytes].action = pair ? ACTION_FINAL_PAIR : ACTION_FINAL;
			else
				start->entries[*bytes].action = pair ? ACTION_FINAL_PAIR_NOFLAGS : ACTION_FINAL_NOFLAGS;
			break;
		case ACTION_FINAL:
			if (pair)
				start->entries[*bytes].action = ACTION_FINAL_PAIR;
			return;
		/* Already marked as pair. Marking will not change this. */
		case ACTION_FINAL_PAIR:
			return;
		case ACTION_FINAL_PAIR_NOFLAGS:
			if (has_flags)
				start->entries[*bytes].action = ACTION_FINAL_PAIR;
			break;
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
			case ACTION_FINAL_PAIR_NOFLAGS:
			case ACTION_FINAL_NOFLAGS:
			case ACTION_FINAL_PAIR:
			case ACTION_FINAL:
			case ACTION_UNASSIGNED:
				switch (b->entries[i].action) {
					case ACTION_FINAL_PAIR_NOFLAGS:
					case ACTION_FINAL_NOFLAGS:
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

static int calculate_state_cost(full_state_t *state, Ucm::StateMachineInfo *info) {
	action_t last_action = (action_t) -1;
	int i;
	double cost;

	cost = 256; //FIXME: chose: either calculate in memory costs, or on disk cost, but not something inbetween!!!

	for (i = 0; i < 256; i++) {
		if (last_action != state->entries[i].action)
			cost += 4;
		switch (state->entries[i].action) {
			case ACTION_ILLEGAL:
			case ACTION_SHIFT:
			case ACTION_UNASSIGNED:
				break;
			case ACTION_FINAL_PAIR_NOFLAGS:
			case ACTION_FINAL_PAIR:
				cost += (double) state->count * 2.0 * info->get_single_cost();
				break;
			case ACTION_FINAL_NOFLAGS:
			case ACTION_FINAL:
				cost += (double) state->count * info->get_single_cost();
				break;
			default:
				PANIC();
		}
		last_action = state->entries[i].action;
	}
	return cost + 0.9;
}

static int calculate_merge_cost(full_state_t *a, full_state_t *b, Ucm::StateMachineInfo *info) {
	full_state_t tmp_state;
	int i;

	memcpy(&tmp_state, a, sizeof(full_state_t));
	tmp_state.count += b->count;

	for (i = 0; i < 256; i++) {
		switch (a->entries[i].action) {
			case ACTION_ILLEGAL:
			case ACTION_SHIFT:
			case ACTION_FINAL_PAIR_NOFLAGS:
				if (b->entries[i].action == ACTION_FINAL || b->entries[i].action == ACTION_FINAL_PAIR ||
						(b->entries[i].action == ACTION_UNASSIGNED && info->unassigned_needs_flags()))
					tmp_state.entries[i].action = ACTION_FINAL_PAIR;
				break;
			case ACTION_FINAL_PAIR:
				break;
			case ACTION_FINAL_NOFLAGS:
				if (b->entries[i].action == ACTION_FINAL_PAIR)
					tmp_state.entries[i].action = ACTION_FINAL_PAIR;
				else if (b->entries[i].action == ACTION_FINAL_PAIR_NOFLAGS)
					tmp_state.entries[i].action = ACTION_FINAL_PAIR_NOFLAGS;
				else if (b->entries[i].action == ACTION_UNASSIGNED && info->unassigned_needs_flags())
					tmp_state.entries[i].action = ACTION_FINAL;
				break;
			case ACTION_FINAL:
				if (b->entries[i].action == ACTION_FINAL_PAIR || b->entries[i].action == ACTION_FINAL_PAIR_NOFLAGS)
					tmp_state.entries[i].action = ACTION_FINAL_PAIR;
				break;
			case ACTION_UNASSIGNED:
				if (info->unassigned_needs_flags()) {
					if (b->entries[i].action == ACTION_FINAL_NOFLAGS)
						tmp_state.entries[i].action = ACTION_FINAL;
					else if (b->entries[i].action == ACTION_FINAL_PAIR_NOFLAGS)
						tmp_state.entries[i].action = ACTION_FINAL_PAIR;
					else
						tmp_state.entries[i].action = b->entries[i].action;
				} else {
					tmp_state.entries[i].action = b->entries[i].action;
				}
				break;
			default:
				PANIC();
		}
	}
	return calculate_state_cost(&tmp_state, info) - (a->cost + b->cost);
}

static void merge_states(full_state_t **tail, full_state_t *left, full_state_t *right, Ucm::StateMachineInfo *info) {
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
			case ACTION_FINAL_PAIR_NOFLAGS:
				if (right->entries[i].action == ACTION_FINAL || right->entries[i].action == ACTION_FINAL_PAIR ||
						(right->entries[i].action == ACTION_UNASSIGNED && info->unassigned_needs_flags()))
					left->entries[i].action = ACTION_FINAL_PAIR;
				break;
			case ACTION_FINAL_PAIR:
				break;
			case ACTION_FINAL_NOFLAGS:
				if (right->entries[i].action == ACTION_FINAL_PAIR)
					left->entries[i].action = ACTION_FINAL_PAIR;
				else if (right->entries[i].action == ACTION_FINAL_PAIR_NOFLAGS)
					left->entries[i].action = ACTION_FINAL_PAIR_NOFLAGS;
				else if (right->entries[i].action == ACTION_UNASSIGNED && info->unassigned_needs_flags())
					left->entries[i].action = ACTION_FINAL;
				break;
			case ACTION_FINAL:
				if (right->entries[i].action == ACTION_FINAL_PAIR || right->entries[i].action == ACTION_FINAL_PAIR_NOFLAGS)
					left->entries[i].action = ACTION_FINAL_PAIR;
				break;
			case ACTION_UNASSIGNED:
				if (info->unassigned_needs_flags()) {
					if (right->entries[i].action == ACTION_FINAL_NOFLAGS)
						left->entries[i].action = ACTION_FINAL;
					else if (right->entries[i].action == ACTION_FINAL_PAIR_NOFLAGS)
						left->entries[i].action = ACTION_FINAL_PAIR;
					else
						left->entries[i].action = right->entries[i].action;
				} else {
					left->entries[i].action = right->entries[i].action;
				}
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
		left->cost = calculate_state_cost(left, info);

	free(right);
}

static void merge_duplicate_states(full_state_t *head, full_state_t **tail, Ucm::StateMachineInfo *info) {
	full_state_t *ptr;
	bool change;

	do {
		change = false;
		for (; head != NULL; head = head->next) {
			for (ptr = head->next; ptr != NULL; ptr = ptr->next) {
				if (memcmp(head->entries, ptr->entries, sizeof(full_entry_t) * 256) != 0)
					continue;

				ptr = ptr->prev;
				merge_states(tail, head, ptr->next, info);
				change = true;
			}
		}
	} while (change);
}

static void minimize_states(full_state_t *head, full_state_t **tail, Ucm::StateMachineInfo *info) {
	merge_cost_t previous = { NULL, NULL, 0 }, best = { NULL, NULL, INT_MAX };
	list<merge_cost_t> costs;
	full_state_t *ptr, *subptr;
	int nr_states;

	// Merge duplicate states using a fast algorithm
	merge_duplicate_states(head, tail, info);
	nr_states = count_states(head);

	// Calculate cached costs for all states for which it makes sense
	for (ptr = head; ptr != NULL; ptr = ptr->next)
		if (ptr->cost)
			ptr->cost = calculate_state_cost(ptr, info);

	// Fill cost list
	for (ptr = head; ptr != NULL; ptr = ptr->next) {
		for (subptr = ptr->next; subptr != NULL; subptr = subptr->next) {
			if (!can_merge(ptr, subptr))
				continue;

			merge_cost_t tmp = { ptr, subptr, calculate_merge_cost(ptr, subptr, info) };
			costs.push_back(tmp);
		}
	}

	while (1) {
		if (option_verbose)
			fprintf(stderr, "\rStates remaining: %d   ", nr_states);

		/* Find the best option for merging, simultaneously removing/replacing cost information
		   relating to the previous merge. */
		for (list<merge_cost_t>::iterator iter = costs.begin(); iter != costs.end(); ) {
			if (iter->left == previous.right || iter->right == previous.right) {
				iter = costs.erase(iter);
				continue;
			} else  if (iter->left == previous.left || iter->right == previous.left) {
				iter->cost = calculate_merge_cost(iter->left, iter->right, info);
			}

			if (iter->cost < best.cost)
				best = *iter;

			iter++;
		}

		if (nr_states <= 256 && best.cost > 0)
			break;

		merge_states(tail, best.left, best.right, info);
		previous = best;
		best.cost = INT_MAX;

		nr_states = count_states(head);
	}
	if (option_verbose)
		fputc('\n', stderr);

	// Do a quick scan for duplicate states (should not do anything)
	merge_duplicate_states(head, tail, info);
}

void minimize_state_machine(Ucm::StateMachineInfo *info, int flags) {
	const vector<State *> &states = info->get_state_machine();
	vector<State *> new_states;
	full_state_t *head = NULL, *tail = NULL, *ptr;
	state_pair_t initial_states[16];
	full_state_t *serialized_states[256];
	size_t i, j, nr_serialized_states = 0, last, nr_initial_states;

	uint8_t bytes[31];
	size_t length;
	bool is_pair, has_flags;
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
	while (info->get_next_byteseq(bytes, length, is_pair, has_flags)) {
		state = (flags & Ucm::MULTIBYTE_START_STATE_1) && length > 1 ? 1 : 0;
		mark_entry(initial_states[state].full_state, bytes, length, is_pair, has_flags);
	}

	minimize_states(head, &tail, info);

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

	// Create new state machine in vector<State *> form
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
				serialized_states[i]->entries[last].action, 0, 0));
			last = j;
		}
		new_states.back()->new_entry(Entry(last, j - 1, (int) (intptr_t) serialized_states[i]->entries[last].next_state,
			serialized_states[i]->entries[last].action, 0, 0));
	}

	info->replace_state_machine(new_states);

	/* Free allocated memory */
	for (ptr = head; ptr != NULL; ptr = head) {
		head = head->next;
		free(ptr);
	}
}

