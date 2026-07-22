from __future__ import annotations

import ahocorasick


def build_automaton(terms: list[str]) -> ahocorasick.Automaton:
    """Builds an Aho-Corasick automaton for exact multi-pattern matching.

    Each term is registered with its index so a match yields (idx, term).
    make_automaton() is only called when terms were actually added — calling
    it on an empty trie raises. Returns the automaton either way; an empty
    one simply yields no matches from iter().
    """
    automaton = ahocorasick.Automaton()

    for idx, term in enumerate(terms):
        automaton.add_word(term, (idx, term))

    if len(automaton) > 0:
        automaton.make_automaton()

    return automaton
